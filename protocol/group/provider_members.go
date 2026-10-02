package group

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

// groupOutboundSnapshot is an immutable membership view. Provider callbacks
// build a complete replacement and publish it atomically; readers never
// observe a half-updated tags/map pair and removed provider members cannot be
// reached through a stale map.
type groupOutboundSnapshot struct {
	tags      []string
	outbounds map[string]adapter.Outbound
}

// sameOutboundIdentity keeps a selected runtime member attached to the same
// authenticated endpoint across provider refreshes. Display tags are allowed
// to gain or lose a numeric suffix, so a tag-only comparison can silently keep
// dialing a retired object after a reorder. DialIdentity is the strongest
// key; EndpointIdentity is the credential-free fallback used by legacy
// providers.
func sameOutboundIdentity(left, right adapter.Outbound) bool {
	if left == nil || right == nil {
		return false
	}
	leftDial, leftHasDial := left.(adapter.OutboundWithDialIdentity)
	rightDial, rightHasDial := right.(adapter.OutboundWithDialIdentity)
	if leftHasDial || rightHasDial {
		return leftHasDial && rightHasDial && leftDial.DialIdentity() != "" && leftDial.DialIdentity() == rightDial.DialIdentity()
	}
	leftEndpoint, leftHasEndpoint := left.(adapter.OutboundWithEndpointIdentity)
	rightEndpoint, rightHasEndpoint := right.(adapter.OutboundWithEndpointIdentity)
	if leftHasEndpoint || rightHasEndpoint {
		return leftHasEndpoint && rightHasEndpoint && leftEndpoint.EndpointIdentity() != "" && leftEndpoint.EndpointIdentity() == rightEndpoint.EndpointIdentity()
	}
	return left.Tag() == right.Tag()
}

func newGroupOutboundSnapshot(tags []string, outbounds map[string]adapter.Outbound) *groupOutboundSnapshot {
	copyTags := append([]string(nil), tags...)
	copyOutbounds := make(map[string]adapter.Outbound, len(outbounds))
	for tag, detour := range outbounds {
		copyOutbounds[tag] = detour
	}
	return &groupOutboundSnapshot{tags: copyTags, outbounds: copyOutbounds}
}

func (s *groupOutboundSnapshot) all() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.tags...)
}

// groupProviderSource is the shared provider expansion used by selector and
// url-test groups. Smart and load-balance carry their own historically grown
// variants; this helper gives the simpler groups the same member semantics
// (providers + use_all_providers + include/exclude regex) without touching
// those implementations.
type groupProviderSource struct {
	manager         adapter.ProviderManager
	providers       map[string]adapter.Provider
	providerTags    []string
	useAllProviders bool
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	outboundsCache  map[string][]adapter.Outbound
	handles         map[string]*list.Element[adapter.ProviderUpdateCallback]
	managerObserver adapter.ProviderManagerObserver
	managerHandle   *list.Element[adapter.ProviderManagerUpdateCallback]
	callback        adapter.ProviderUpdateCallback
	access          sync.Mutex
	registered      bool
	closed          bool
}

func newGroupProviderSource(ctx context.Context, options option.GroupCommonOption) *groupProviderSource {
	return &groupProviderSource{
		manager:         service.FromContext[adapter.ProviderManager](ctx),
		providers:       make(map[string]adapter.Provider),
		providerTags:    options.Providers,
		useAllProviders: options.UseAllProviders,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		outboundsCache:  make(map[string][]adapter.Outbound),
		handles:         make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
	}
}

// has reports whether the group is provider-backed at all. Without this the
// provider update callback must reject everything.
func (s *groupProviderSource) has() bool {
	if s == nil {
		return false
	}
	s.access.Lock()
	defer s.access.Unlock()
	return s.hasLocked()
}

func (s *groupProviderSource) hasLocked() bool {
	return len(s.providerTags) > 0 || s.useAllProviders
}

// providerMemberAllowed is the single membership filter contract shared by
// every group type. Provider refresh code must apply include first as a
// positive selector and exclude as a hard veto; keeping this decision here
// prevents Smart's health-aware catalog from drifting from selector,
// url-test, or load-balance.
func providerMemberAllowed(tag string, include, exclude *regexp.Regexp) bool {
	return providerAdapter.MemberAllowed(tag, include, exclude)
}

// register subscribes to provider updates and resolves the configured tags.
func (s *groupProviderSource) register(callback adapter.ProviderUpdateCallback) error {
	if s == nil {
		return nil
	}
	s.access.Lock()
	if !s.hasLocked() {
		s.access.Unlock()
		return nil
	}
	if s.closed {
		s.access.Unlock()
		return E.New("outbound provider source is closed")
	}
	if s.registered {
		s.access.Unlock()
		return nil
	}
	manager := s.manager
	useAll := s.useAllProviders
	configuredTags := append([]string(nil), s.providerTags...)
	s.access.Unlock()
	if manager == nil {
		return E.New("missing outbound provider manager")
	}
	// ProviderManager is an interface owned by another lifecycle. Resolve it
	// outside source.access: a custom manager is allowed to synchronously notify
	// observers from Providers/Get, and source callbacks must never re-enter its
	// own mutex while we hold ours.
	resolved, providerTags, err := resolveProviderSet(manager, useAll, configuredTags)
	if err != nil {
		return err
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return E.New("outbound provider source is closed")
	}
	if s.registered {
		s.access.Unlock()
		return nil
	}
	// Publish the resolved set before calling provider code. Provider callback
	// registration is external and may synchronously notify; holding the source
	// mutex across that call can deadlock the callback while it rebuilds a group.
	// Handles are attached by attachProviderCallback after the lock is released.
	for _, tag := range providerTags {
		s.providers[tag] = resolved[tag]
		s.handles[tag] = nil
	}
	s.providerTags = providerTags
	s.callback = callback
	s.registered = true
	manager = s.manager
	useAll = s.useAllProviders
	s.access.Unlock()
	for _, tag := range providerTags {
		s.attachProviderCallback(tag, resolved[tag], callback)
	}
	if useAll {
		if observer, ok := manager.(adapter.ProviderManagerObserver); ok {
			handle := observer.RegisterProviderCallback(s.onProviderManagerUpdated)
			s.access.Lock()
			if s.closed || !s.registered {
				s.access.Unlock()
				if handle != nil {
					observer.UnregisterProviderCallback(handle)
				}
				return nil
			}
			s.managerObserver = observer
			s.managerHandle = handle
			s.access.Unlock()
		}
	}
	return nil
}

func resolveProviderSet(manager adapter.ProviderManager, useAll bool, configuredTags []string) (map[string]adapter.Provider, []string, error) {
	resolved := make(map[string]adapter.Provider)
	var providerTags []string
	if useAll {
		for _, provider := range manager.Providers() {
			if provider == nil || provider.Tag() == "" {
				continue
			}
			// Aggregate providers are synthetic live views. Including them in
			// use_all_providers together with their leaf sources would duplicate
			// every endpoint and make selection depend on declaration order. They
			// remain available through an explicit providers reference.
			if provider.Type() == C.ProviderTypeAggregate {
				continue
			}
			tag := provider.Tag()
			if _, exists := resolved[tag]; exists {
				continue
			}
			providerTags = append(providerTags, tag)
			resolved[tag] = provider
		}
		return resolved, providerTags, nil
	}
	for i, tag := range configuredTags {
		if _, exists := resolved[tag]; exists {
			continue
		}
		provider, loaded := manager.Get(tag)
		if !loaded || provider == nil {
			return nil, nil, E.New("outbound provider ", i, " not found: ", tag)
		}
		providerTags = append(providerTags, tag)
		resolved[tag] = provider
	}
	return resolved, providerTags, nil
}

// attachProviderCallback performs the provider call without holding source
// state. A provider is allowed to notify synchronously from RegisterCallback;
// in that case the callback observes the already-published provider set.
func (s *groupProviderSource) attachProviderCallback(tag string, provider adapter.Provider, callback adapter.ProviderUpdateCallback) {
	if provider == nil {
		return
	}
	handle := provider.RegisterCallback(callback)
	s.access.Lock()
	if s.closed || !s.registered || s.providers[tag] != provider {
		s.access.Unlock()
		if handle != nil {
			provider.UnregisterCallback(handle)
		}
		return
	}
	s.handles[tag] = handle
	s.access.Unlock()
}

// onProviderManagerUpdated reconciles use_all_providers without polling. The
// manager callback only reports a set change; outbound-list changes continue
// to use each provider's existing callback.
func (s *groupProviderSource) onProviderManagerUpdated() {
	if s == nil {
		return
	}
	s.access.Lock()
	if s.closed || !s.registered || !s.useAllProviders || s.manager == nil {
		s.access.Unlock()
		return
	}
	manager := s.manager
	s.access.Unlock()
	// Providers is an external manager call; never hold source.access while
	// resolving the new set.
	desired, providerTags, err := resolveProviderSet(manager, true, nil)
	if err != nil {
		return
	}
	s.access.Lock()
	if s.closed || !s.registered || !s.useAllProviders || s.manager != manager {
		s.access.Unlock()
		return
	}
	var removedProviders []adapter.Provider
	var removedHandles []*list.Element[adapter.ProviderUpdateCallback]
	var addedProviders []struct {
		tag      string
		provider adapter.Provider
	}
	changed := false
	for tag, provider := range s.providers {
		desiredProvider, exists := desired[tag]
		if exists && desiredProvider == provider {
			continue
		}
		removedProviders = append(removedProviders, provider)
		removedHandles = append(removedHandles, s.handles[tag])
		delete(s.providers, tag)
		delete(s.handles, tag)
		delete(s.outboundsCache, tag)
		changed = true
	}
	for _, tag := range providerTags {
		if _, exists := s.providers[tag]; exists {
			continue
		}
		provider := desired[tag]
		s.providers[tag] = provider
		s.handles[tag] = nil
		addedProviders = append(addedProviders, struct {
			tag      string
			provider adapter.Provider
		}{tag: tag, provider: provider})
		changed = true
	}
	s.providerTags = providerTags
	callback := s.callback
	s.access.Unlock()
	for index, provider := range removedProviders {
		if provider != nil && removedHandles[index] != nil {
			provider.UnregisterCallback(removedHandles[index])
		}
	}
	for _, added := range addedProviders {
		s.attachProviderCallback(added.tag, added.provider, callback)
	}
	if changed && callback != nil {
		_ = callback("")
	}
}

func (s *groupProviderSource) hasProvider(tag string) bool {
	if s == nil {
		return false
	}
	s.access.Lock()
	defer s.access.Unlock()
	return !s.closed && s.providers[tag] != nil
}

// close unregisters every callback and makes late provider notifications
// harmless. Unregistration happens outside the source lock because provider
// implementations may synchronize their own callback list.
func (s *groupProviderSource) close() {
	if s == nil {
		return
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return
	}
	s.closed = true
	s.registered = false
	providers := make(map[string]adapter.Provider, len(s.providers))
	handles := make(map[string]*list.Element[adapter.ProviderUpdateCallback], len(s.handles))
	managerObserver := s.managerObserver
	managerHandle := s.managerHandle
	for tag, provider := range s.providers {
		providers[tag] = provider
	}
	for tag, handle := range s.handles {
		handles[tag] = handle
	}
	clear(s.handles)
	clear(s.providers)
	clear(s.outboundsCache)
	s.providerTags = nil
	s.manager = nil
	s.managerObserver = nil
	s.managerHandle = nil
	s.callback = nil
	s.access.Unlock()
	if managerObserver != nil && managerHandle != nil {
		managerObserver.UnregisterProviderCallback(managerHandle)
	}
	for tag, handle := range handles {
		if provider := providers[tag]; provider != nil && handle != nil {
			provider.UnregisterCallback(handle)
		}
	}
}

// memberOutbounds returns the deduplicated provider-contributed members with
// their tags, re-filtering only the provider that reported an update.
func (s *groupProviderSource) memberOutbounds(updatedTag string) (tags []string, outbounds []adapter.Outbound) {
	if s == nil {
		return nil, nil
	}
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil, nil
	}
	providerTags := append([]string(nil), s.providerTags...)
	type providerSnapshot struct {
		tag      string
		provider adapter.Provider
		cached   []adapter.Outbound
		useCache bool
		refresh  bool
	}
	snapshots := make([]providerSnapshot, 0, len(providerTags))
	for _, providerTag := range providerTags {
		provider := s.providers[providerTag]
		cached, useCache := s.outboundsCache[providerTag]
		// An empty update tag means a complete rebuild (startup, or a
		// membership change that can affect every provider).  Incremental
		// callbacks refresh only the provider that reported the change and
		// reuse the immutable filtered cache for all others.
		refresh := updatedTag == "" || providerTag == updatedTag || !useCache
		snapshots = append(snapshots, providerSnapshot{
			tag:      providerTag,
			provider: provider,
			cached:   append([]adapter.Outbound(nil), cached...),
			useCache: useCache,
			refresh:  refresh,
		})
	}
	exclude, include := s.exclude, s.include
	s.access.Unlock()

	// Provider.Outbounds is external code and may take its own lifecycle lock or
	// synchronously notify listeners. Read it outside source.access, then publish
	// the immutable cache only if the provider is still owned by this source.
	for _, snapshot := range snapshots {
		members := snapshot.cached
		if !snapshot.useCache {
			members = nil
		}
		if snapshot.provider != nil && snapshot.refresh {
			members = make([]adapter.Outbound, 0)
			for _, detour := range snapshot.provider.Outbounds() {
				if detour == nil {
					continue
				}
				tag := detour.Tag()
				if !providerMemberAllowed(tag, include, exclude) {
					continue
				}
				members = append(members, detour)
			}
			s.access.Lock()
			if !s.closed && s.providers[snapshot.tag] == snapshot.provider {
				s.outboundsCache[snapshot.tag] = append([]adapter.Outbound(nil), members...)
			}
			s.access.Unlock()
		}
		s.access.Lock()
		owned := !s.closed && (snapshot.provider == nil || s.providers[snapshot.tag] == snapshot.provider)
		s.access.Unlock()
		if !owned {
			continue
		}
		for _, detour := range members {
			if detour == nil {
				continue
			}
			tags = append(tags, detour.Tag())
			outbounds = append(outbounds, detour)
		}
	}
	s.access.Lock()
	closed := s.closed
	// A close or manager reconciliation that happened while provider code ran
	// invalidates the assembled view; the next callback will rebuild it.
	s.access.Unlock()
	if closed {
		return nil, nil
	}
	return tags, outbounds
}

// renamedOutbound delegates everything except the tag, which carries the
// deduplicating suffix. Panel entries, history keys and SelectOutbound all
// key on the renamed tag while dialing still goes through the real member.
type renamedOutbound struct {
	adapter.Outbound
	tag          string
	identity     string
	dialIdentity string
}

func (o *renamedOutbound) Tag() string              { return o.tag }
func (o *renamedOutbound) EndpointIdentity() string { return o.identity }
func (o *renamedOutbound) DialIdentity() string     { return o.dialIdentity }

// renameProviderMembers assigns every provider member a unique, panel-visible
// tag. When a member collides with an occupied tag (an explicit member, or a
// same-named node from another provider) it keeps its name and gains a
// " #N" suffix, matching how clash renames duplicate provider nodes.
func renameProviderMembers(members []adapter.Outbound, occupied map[string]struct{}) (tags []string, renamed []adapter.Outbound) {
	// Assign suffixes by endpoint identity, not by provider enumeration order.
	// Refreshes are allowed to reorder a subscription; the display tag must not
	// make a different endpoint inherit the previous selector/history entry.
	indicesByTag := make(map[string][]int)
	for index, member := range members {
		if member != nil {
			indicesByTag[member.Tag()] = append(indicesByTag[member.Tag()], index)
		}
	}
	assigned := make(map[int]string, len(members))
	for baseTag, indices := range indicesByTag {
		sort.SliceStable(indices, func(i, j int) bool {
			left, right := members[indices[i]], members[indices[j]]
			return providerMemberIdentity(left) < providerMemberIdentity(right)
		})
		nextSuffix := 1
		if _, taken := occupied[baseTag]; taken {
			nextSuffix = 2
		}
		for _, index := range indices {
			tag := baseTag
			if nextSuffix > 1 {
				tag = baseTag + " #" + strconv.Itoa(nextSuffix)
			}
			for {
				if _, taken := occupied[tag]; !taken {
					break
				}
				nextSuffix++
				tag = baseTag + " #" + strconv.Itoa(nextSuffix)
			}
			occupied[tag] = struct{}{}
			assigned[index] = tag
			nextSuffix++
		}
	}
	for index, member := range members {
		if member == nil {
			continue
		}
		tag := assigned[index]
		if tag != member.Tag() {
			member = &renamedOutbound{Outbound: member, tag: tag, identity: providerMemberIdentity(member), dialIdentity: providerMemberDialIdentity(member)}
		}
		tags = append(tags, tag)
		renamed = append(renamed, member)
	}
	return tags, renamed
}

func providerMemberIdentity(member adapter.Outbound) string {
	if member == nil {
		return ""
	}
	if identified, ok := member.(adapter.OutboundWithEndpointIdentity); ok {
		if identity := identified.EndpointIdentity(); identity != "" {
			return identity
		}
	}
	// Legacy providers do not expose structured options. Their tag is the only
	// safe identity available; it still avoids order-dependent suffix churn.
	return member.Tag()
}

func providerMemberDialIdentity(member adapter.Outbound) string {
	if member == nil {
		return ""
	}
	if identified, ok := member.(adapter.OutboundWithDialIdentity); ok {
		if identity := identified.DialIdentity(); identity != "" {
			return identity
		}
	}
	return providerMemberIdentity(member)
}
