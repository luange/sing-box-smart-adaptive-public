package adaptive

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

// A48SourceRuntimeV1 is also valid for the reF1nd A50 provider contract. All
// upstream provider/group arrays and callback handles terminate here.
type A48SourceRuntimeV1 struct {
	access            sync.Mutex
	hasher            *IdentityHasher
	manager           adapter.OutboundManager
	providerManager   adapter.ProviderManager
	config            SourceRuntimeConfig
	providerTags      []string
	providers         map[string]adapter.Provider
	handles           map[string]*list.Element[adapter.ProviderUpdateCallback]
	pollCancel        context.CancelFunc
	pollDone          chan struct{}
	started           bool
	closed            bool
	lastPublication   *SourcePublication
	providerRevisions map[string]uint64
	dirtyProviders    map[string]struct{}
	forceFullRefresh  bool
}

func NewA48SourceRuntimeV1(ctx context.Context, hasher *IdentityHasher, config SourceRuntimeConfig) (SourceRuntime, error) {
	manager := service.FromContext[adapter.OutboundManager](ctx)
	if manager == nil || hasher == nil {
		return nil, errors.New("adaptive source runtime dependencies are missing")
	}
	providerManager := service.FromContext[adapter.ProviderManager](ctx)
	if providerManager == nil && (len(config.ProviderTags) > 0 || config.UseAll) {
		return nil, errors.New("adaptive source runtime provider manager is missing")
	}
	config.StaticTags = append([]string(nil), config.StaticTags...)
	config.ProviderTags = append([]string(nil), config.ProviderTags...)
	return &A48SourceRuntimeV1{
		hasher:            hasher,
		manager:           manager,
		providerManager:   providerManager,
		config:            config,
		providers:         make(map[string]adapter.Provider),
		handles:           make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		providerRevisions: make(map[string]uint64),
		dirtyProviders:    make(map[string]struct{}),
	}, nil
}

func (r *A48SourceRuntimeV1) Start(onUpdate func() error) error {
	if r == nil || onUpdate == nil {
		return errors.New("adaptive source runtime callback is missing")
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.closed {
		return errors.New("adaptive source runtime is closed")
	}
	if r.started {
		return nil
	}
	providerTags := append([]string(nil), r.config.ProviderTags...)
	providers := make(map[string]adapter.Provider)
	if r.config.UseAll {
		providerTags = providerTags[:0]
		for _, provider := range r.providerManager.Providers() {
			providerTags = append(providerTags, provider.Tag())
			providers[provider.Tag()] = provider
		}
	} else {
		for index, tag := range providerTags {
			provider, loaded := r.providerManager.Get(tag)
			if !loaded {
				return errors.New("adaptive outbound provider not found at index " + strconv.Itoa(index))
			}
			providers[tag] = provider
		}
	}
	callback := func(tag string) error {
		r.access.Lock()
		r.dirtyProviders[tag] = struct{}{}
		r.access.Unlock()
		return onUpdate()
	}
	handles := make(map[string]*list.Element[adapter.ProviderUpdateCallback], len(providers))
	for tag, provider := range providers {
		handles[tag] = provider.RegisterCallback(callback)
	}
	r.providerTags = providerTags
	r.providers = providers
	r.handles = handles
	for tag, provider := range providers {
		if incremental, loaded := provider.(adapter.ProviderOutboundDelta); loaded {
			r.providerRevisions[tag] = incremental.OutboundDeltaRevision()
		}
	}
	r.started = true
	if r.config.UseAll {
		interval := r.config.ProviderPollInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		pollContext, cancel := context.WithCancel(context.Background())
		r.pollCancel = cancel
		r.pollDone = make(chan struct{})
		done := r.pollDone
		go r.pollProviders(pollContext, onUpdate, interval, done)
	}
	return nil
}

func (r *A48SourceRuntimeV1) pollProviders(ctx context.Context, onUpdate func() error, interval time.Duration, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.reconcileAllProviders(onUpdate); err != nil {
				continue
			}
		}
	}
}

func (r *A48SourceRuntimeV1) reconcileAllProviders(onUpdate func() error) error {
	r.access.Lock()
	if r.closed || !r.started || r.providerManager == nil {
		r.access.Unlock()
		return nil
	}
	desired := make(map[string]adapter.Provider)
	for _, provider := range r.providerManager.Providers() {
		if provider != nil && provider.Tag() != "" {
			desired[provider.Tag()] = provider
		}
	}
	callback := func(tag string) error {
		r.access.Lock()
		r.dirtyProviders[tag] = struct{}{}
		r.access.Unlock()
		return onUpdate()
	}
	changed := false
	for tag, handle := range r.handles {
		provider, present := desired[tag]
		if !present || provider != r.providers[tag] {
			if old := r.providers[tag]; old != nil && handle != nil {
				old.UnregisterCallback(handle)
			}
			delete(r.handles, tag)
			delete(r.providers, tag)
			delete(r.providerRevisions, tag)
			changed = true
		}
	}
	for tag, provider := range desired {
		if _, loaded := r.providers[tag]; loaded {
			continue
		}
		r.providers[tag] = provider
		r.handles[tag] = provider.RegisterCallback(callback)
		if incremental, loaded := provider.(adapter.ProviderOutboundDelta); loaded {
			r.providerRevisions[tag] = incremental.OutboundDeltaRevision()
		}
		changed = true
	}
	r.providerTags = r.providerTags[:0]
	for tag := range r.providers {
		r.providerTags = append(r.providerTags, tag)
	}
	sort.Strings(r.providerTags)
	r.access.Unlock()
	if changed {
		r.access.Lock()
		r.forceFullRefresh = true
		r.access.Unlock()
		return onUpdate()
	}
	return nil
}

func (r *A48SourceRuntimeV1) Close() error {
	if r == nil {
		return nil
	}
	r.access.Lock()
	if r.closed {
		r.access.Unlock()
		return nil
	}
	r.closed = true
	providers, handles := r.providers, r.handles
	pollCancel, pollDone := r.pollCancel, r.pollDone
	r.pollCancel, r.pollDone = nil, nil
	r.providers = nil
	r.handles = nil
	r.access.Unlock()
	if pollCancel != nil {
		pollCancel()
	}
	if pollDone != nil {
		<-pollDone
	}
	for tag, handle := range handles {
		if provider := providers[tag]; provider != nil && handle != nil {
			provider.UnregisterCallback(handle)
		}
	}
	return nil
}

func (r *A48SourceRuntimeV1) Snapshot(ctx context.Context, generation uint64) (SourcePublication, error) {
	if r == nil {
		return SourcePublication{}, errors.New("adaptive source runtime is missing")
	}
	r.access.Lock()
	if !r.started || r.closed {
		r.access.Unlock()
		return SourcePublication{}, errors.New("adaptive source runtime is not active")
	}
	providerTags := append([]string(nil), r.providerTags...)
	providers := make(map[string]adapter.Provider, len(r.providers))
	for tag, provider := range r.providers {
		providers[tag] = provider
	}
	config, manager, hasher := r.config, r.manager, r.hasher
	r.access.Unlock()
	publication, err := SnapshotA48RuntimeV1(ctx, generation, hasher, manager, config.StaticTags, providers, providerTags, config.Include, config.Exclude, config.ManualExclude)
	if err != nil {
		return SourcePublication{}, err
	}
	r.access.Lock()
	cloned := cloneSourcePublication(publication)
	r.lastPublication = &cloned
	for tag, provider := range providers {
		if incremental, loaded := provider.(adapter.ProviderOutboundDelta); loaded {
			r.providerRevisions[tag] = incremental.OutboundDeltaRevision()
		}
	}
	clear(r.dirtyProviders)
	r.forceFullRefresh = false
	r.access.Unlock()
	return publication, nil
}

func (r *A48SourceRuntimeV1) Delta(ctx context.Context, generation uint64) (SourceDeltaPublication, error) {
	if r == nil {
		return SourceDeltaPublication{}, errors.New("adaptive source runtime is missing")
	}
	r.access.Lock()
	if !r.started || r.closed || r.lastPublication == nil {
		r.access.Unlock()
		return SourceDeltaPublication{}, errors.New("adaptive source delta baseline is missing")
	}
	if r.forceFullRefresh || r.lastPublication.DuplicatesSuppressed != 0 || len(r.dirtyProviders) == 0 {
		r.access.Unlock()
		return SourceDeltaPublication{}, errors.New("adaptive provider delta requires full snapshot fallback")
	}
	previous := cloneSourcePublication(*r.lastPublication)
	dirtyProviders := make([]string, 0, len(r.dirtyProviders))
	for tag := range r.dirtyProviders {
		dirtyProviders = append(dirtyProviders, tag)
	}
	providers := make(map[string]adapter.Provider, len(r.providers))
	for tag, provider := range r.providers {
		providers[tag] = provider
	}
	revisions := make(map[string]uint64, len(r.providerRevisions))
	for tag, revision := range r.providerRevisions {
		revisions[tag] = revision
	}
	config, manager, hasher := r.config, r.manager, r.hasher
	r.access.Unlock()
	delta := SourceDeltaPublication{SourceDelta: SourceDelta{Generation: generation}, Bindings: make(map[NodeID]ExecutionPort), InputLeafCount: previous.InputLeafCount, DuplicatesSuppressed: 0}
	removed := make(map[NodeID]struct{})
	currentByID := make(map[NodeID]CanonicalNode, len(previous.Nodes))
	for _, node := range previous.Nodes {
		currentByID[node.NodeID] = node
	}
	updatedRevisions := make(map[string]uint64, len(dirtyProviders))
	for _, providerTag := range dirtyProviders {
		provider := providers[providerTag]
		incremental, incrementalOK := provider.(adapter.ProviderOutboundDelta)
		optionLookup, optionsOK := provider.(adapter.ProviderOutboundOptionLookup)
		if provider == nil || !incrementalOK || !optionsOK {
			return SourceDeltaPublication{}, errors.New("adaptive provider has no safe delta contract")
		}
		providerDelta, ok := incremental.OutboundDelta(revisions[providerTag])
		if !ok {
			return SourceDeltaPublication{}, errors.New("adaptive provider delta cursor expired")
		}
		updatedRevisions[providerTag] = providerDelta.Revision
		for _, tag := range append(append([]string(nil), providerDelta.Removes...), providerDelta.Upserts...) {
			for _, node := range previous.Nodes {
				if node.Metadata != nil && node.Metadata["source"] == providerTag && node.SourceKey == tag {
					if _, loaded := removed[node.NodeID]; !loaded {
						removed[node.NodeID] = struct{}{}
						delta.Removes = append(delta.Removes, node.NodeID)
						delta.InputLeafCount--
						delete(currentByID, node.NodeID)
					}
				}
			}
		}
		for _, tag := range providerDelta.Upserts {
			if config.Exclude != nil && config.Exclude.MatchString(tag) || config.Include != nil && !config.Include.MatchString(tag) || config.ManualExclude.Match(tag) {
				continue
			}
			candidate, loaded := provider.Outbound(tag)
			outboundOptions, optionLoaded := optionLookup.OutboundOption(tag)
			if !loaded {
				return SourceDeltaPublication{}, errors.New("adaptive provider delta object is incomplete")
			}
			if _, isGroup := candidate.(adapter.OutboundGroup); isGroup {
				return SourceDeltaPublication{}, errors.New("adaptive provider group delta requires full snapshot")
			}
			var optionPointer *option.Outbound
			if optionLoaded {
				copyOptions := outboundOptions
				optionPointer = &copyOptions
			}
			publication, buildErr := NewA48SourceAdapterV1(generation, hasher, []A48SourceRoot{{Outbound: candidate, Options: optionPointer, Source: providerTag}}, manager.Outbound).Snapshot(ctx)
			if buildErr != nil || len(publication.Nodes) != 1 {
				return SourceDeltaPublication{}, errors.New("adaptive provider delta canonicalization failed")
			}
			node := publication.Nodes[0]
			if existing, collision := currentByID[node.NodeID]; collision && existing.SourceKey != tag {
				return SourceDeltaPublication{}, errors.New("adaptive provider delta identity collision requires full snapshot")
			}
			currentByID[node.NodeID] = node
			delta.Upserts = append(delta.Upserts, node)
			delta.Bindings[node.NodeID] = publication.Bindings[node.NodeID]
			delta.InputLeafCount++
		}
	}
	current, err := ApplySourceDelta(previous, delta)
	if err != nil {
		return SourceDeltaPublication{}, err
	}
	r.access.Lock()
	cloned := cloneSourcePublication(current)
	r.lastPublication = &cloned
	for tag, revision := range updatedRevisions {
		r.providerRevisions[tag] = revision
		if provider := r.providers[tag]; provider != nil {
			if incremental, loaded := provider.(adapter.ProviderOutboundDelta); loaded && incremental.OutboundDeltaRevision() == revision {
				delete(r.dirtyProviders, tag)
			}
		}
	}
	r.access.Unlock()
	return delta, nil
}

func cloneSourcePublication(source SourcePublication) SourcePublication {
	cloned := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: source.Generation, InputLeafCount: source.InputLeafCount, DuplicatesSuppressed: source.DuplicatesSuppressed, Nodes: make([]CanonicalNode, len(source.Nodes))}, Bindings: make(map[NodeID]ExecutionPort, len(source.Bindings))}
	for index, node := range source.Nodes {
		cloned.Nodes[index] = cloneCanonicalNode(node)
	}
	for id, binding := range source.Bindings {
		cloned.Bindings[id] = binding
	}
	return cloned
}

func SnapshotA48RuntimeV1(ctx context.Context, generation uint64, hasher *IdentityHasher, manager adapter.OutboundManager, staticTags []string, providers map[string]adapter.Provider, providerTags []string, include, exclude *regexp.Regexp, manualExclude ...*nodefilter.Matcher) (SourcePublication, error) {
	var manual *nodefilter.Matcher
	if len(manualExclude) > 0 {
		manual = manualExclude[0]
	}
	var roots []A48SourceRoot
	for _, tag := range staticTags {
		candidate, loaded := manager.Outbound(tag)
		if !loaded {
			return SourcePublication{}, errors.New("adaptive static outbound not found: " + tag)
		}
		roots = append(roots, A48SourceRoot{Outbound: candidate, Source: "static"})
	}
	for _, providerTag := range providerTags {
		provider := providers[providerTag]
		if provider == nil {
			continue
		}
		var optionsByTag map[string]option.Outbound
		if optionProvider, loaded := provider.(adapter.ProviderOutboundOptions); loaded {
			optionsByTag = optionProvider.OutboundOptions()
		}
		for _, candidate := range provider.Outbounds() {
			if exclude != nil && exclude.MatchString(candidate.Tag()) {
				continue
			}
			if manual.Match(candidate.Tag()) {
				continue
			}
			if include != nil && !include.MatchString(candidate.Tag()) {
				continue
			}
			var optionPointer *option.Outbound
			if outboundOptions, loaded := optionsByTag[candidate.Tag()]; loaded {
				copyOptions := outboundOptions
				optionPointer = &copyOptions
			}
			roots = append(roots, A48SourceRoot{Outbound: candidate, Options: optionPointer, Source: providerTag})
		}
	}
	adapterV1 := NewA48SourceAdapterV1(generation, hasher, roots, manager.Outbound)
	publication, err := adapterV1.Snapshot(ctx)
	if err != nil || manual == nil {
		return publication, err
	}
	return filterManualSourcePublication(publication, manual), nil
}

func filterManualSourcePublication(publication SourcePublication, manual *nodefilter.Matcher) SourcePublication {
	if manual == nil {
		return publication
	}
	filtered := publication.Nodes[:0]
	excluded := 0
	for _, node := range publication.Nodes {
		match := manual.Match(node.SourceKey)
		for _, alias := range node.Aliases {
			match = match || manual.Match(alias)
		}
		if match {
			delete(publication.Bindings, node.NodeID)
			excluded++
			continue
		}
		filtered = append(filtered, node)
	}
	publication.Nodes = filtered
	publication.InputLeafCount = max(0, publication.InputLeafCount-excluded)
	return publication
}

// This is the only A48 adapter allowed to know official provider/group/option
// layouts. The rest of Adaptive consumes SourceSnapshot only.
type A48SourceRoot struct {
	Outbound adapter.Outbound
	Options  *option.Outbound
	Source   string
}

type A48SourceAdapterV1 struct {
	generation uint64
	hasher     *IdentityHasher
	roots      []A48SourceRoot
	resolve    func(string) (adapter.Outbound, bool)
}

func NewA48SourceAdapterV1(generation uint64, hasher *IdentityHasher, roots []A48SourceRoot, resolve func(string) (adapter.Outbound, bool)) *A48SourceAdapterV1 {
	return &A48SourceAdapterV1{generation: generation, hasher: hasher, roots: append([]A48SourceRoot(nil), roots...), resolve: resolve}
}

func (a *A48SourceAdapterV1) Snapshot(ctx context.Context) (SourcePublication, error) {
	if err := ctx.Err(); err != nil {
		return SourcePublication{}, err
	}
	if a.generation == 0 || a.hasher == nil || a.resolve == nil {
		return SourcePublication{}, errors.New("invalid A48 source adapter")
	}
	optionsByTag := make(map[string]*option.Outbound)
	for _, root := range a.roots {
		if root.Options != nil {
			copyOptions := *root.Options
			optionsByTag[root.Outbound.Tag()] = &copyOptions
		}
	}
	var leaves []A48SourceRoot
	seen := make(map[string]bool)
	for _, root := range a.roots {
		a.flatten(root, optionsByTag, make(map[string]bool), seen, &leaves)
	}
	result := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: a.generation, InputLeafCount: len(leaves), Nodes: make([]CanonicalNode, 0, len(leaves))}, Bindings: make(map[NodeID]ExecutionPort, len(leaves))}
	byID := make(map[NodeID]int)
	for _, leaf := range leaves {
		var id, endpointID NodeID
		var err error
		structured := leaf.Options != nil
		stable := structured || leaf.Source == "static"
		if structured {
			id, err = a.hasher.FromCanonicalOptions(leaf.Options.Type, leaf.Options.Options)
			if err == nil {
				endpointID, err = a.hasher.FromEndpointOptions(leaf.Options.Type, leaf.Options.Options)
			}
		} else {
			id = a.hasher.FromRuntimeDescriptor(leaf.Outbound.Type(), leaf.Outbound.Tag(), leaf.Outbound.Network(), leaf.Outbound.Dependencies())
			endpointID = id
		}
		if err != nil {
			return SourcePublication{}, err
		}
		if index, loaded := byID[id]; loaded {
			result.Nodes[index].Aliases = appendUnique(result.Nodes[index].Aliases, leaf.Outbound.Tag())
			result.DuplicatesSuppressed++
			continue
		}
		byID[id] = len(result.Nodes)
		result.Bindings[id] = leaf.Outbound
		transports := make([]string, 0, len(leaf.Outbound.Network()))
		for _, network := range leaf.Outbound.Network() {
			transports = append(transports, N.NetworkName(network))
		}
		result.Nodes = append(result.Nodes, CanonicalNode{NodeID: id, EndpointID: endpointID, SourceKey: leaf.Outbound.Tag(), Aliases: append([]string(nil), leaf.Outbound.Tag()), Transport: transports, Metadata: SourceMetadata(leaf.Source), IdentityStable: stable})
	}
	endpointCounts := make(map[NodeID]int, len(result.Nodes))
	for _, node := range result.Nodes {
		endpointCounts[node.EndpointID]++
	}
	for index := range result.Nodes {
		count := endpointCounts[result.Nodes[index].EndpointID]
		if count > 1 {
			result.Nodes[index].EndpointConflictCount = count
			if result.Nodes[index].Metadata == nil {
				result.Nodes[index].Metadata = make(map[string]string)
			}
			result.Nodes[index].Metadata["endpoint_conflict"] = "true"
		}
	}
	return result, nil
}

func SourceMetadata(source string) map[string]string {
	if source == "" {
		return nil
	}
	return map[string]string{"source": source}
}

func (a *A48SourceAdapterV1) flatten(root A48SourceRoot, optionsByTag map[string]*option.Outbound, stack, seen map[string]bool, leaves *[]A48SourceRoot) {
	tag := root.Outbound.Tag()
	if tag == "" || stack[tag] {
		return
	}
	if group, loaded := root.Outbound.(adapter.OutboundGroup); loaded {
		stack[tag] = true
		for _, childTag := range group.All() {
			child, ok := a.resolve(childTag)
			if ok {
				a.flatten(A48SourceRoot{Outbound: child, Options: optionsByTag[childTag], Source: root.Source}, optionsByTag, stack, seen, leaves)
			}
		}
		delete(stack, tag)
		return
	}
	if seen[tag] {
		return
	}
	seen[tag] = true
	if root.Options == nil {
		root.Options = optionsByTag[tag]
	}
	*leaves = append(*leaves, root)
}
