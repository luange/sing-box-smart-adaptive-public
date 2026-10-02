package aggregate

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

func RegisterProvider(registry *providerAdapter.Registry) {
	providerAdapter.Register[option.ProviderAggregateOptions](registry, C.ProviderTypeAggregate, NewProvider)
}

var _ adapter.Provider = (*Provider)(nil)

// Provider is a live, non-owning view over one or more providers. It keeps
// source providers independently registered and only republishes their
// current outbound objects, so an aggregate does not duplicate connections,
// health portraits, or subscription storage.
type Provider struct {
	ctx     context.Context
	logger  log.ContextLogger
	manager adapter.ProviderManager
	tag     string

	configuredTags []string
	useAll         bool
	include        *regexp.Regexp
	exclude        *regexp.Regexp

	access          sync.RWMutex
	children        map[string]adapter.Provider
	childHandles    map[string]*list.Element[adapter.ProviderUpdateCallback]
	managerObserver adapter.ProviderManagerObserver
	managerHandle   *list.Element[adapter.ProviderManagerUpdateCallback]
	members         []adapter.Outbound
	memberByTag     map[string]adapter.Outbound
	updatedAt       time.Time
	revision        uint64
	closed          bool
	started         bool

	callbackAccess sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]
}

func NewProvider(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderAggregateOptions) (adapter.Provider, error) {
	if len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, E.New("aggregate provider requires providers or use_all_providers")
	}
	manager := service.FromContext[adapter.ProviderManager](ctx)
	if manager == nil {
		return nil, E.New("missing outbound provider manager")
	}
	return &Provider{
		ctx:            ctx,
		logger:         logFactory.NewLogger(F.ToString("provider/aggregate", "[", tag, "]")),
		manager:        manager,
		tag:            tag,
		configuredTags: append([]string(nil), options.Providers...),
		useAll:         options.UseAllProviders,
		include:        (*regexp.Regexp)(options.Include),
		exclude:        (*regexp.Regexp)(options.Exclude),
		children:       make(map[string]adapter.Provider),
		childHandles:   make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		memberByTag:    make(map[string]adapter.Outbound),
	}, nil
}

func (p *Provider) Type() string { return C.ProviderTypeAggregate }
func (p *Provider) Tag() string  { return p.tag }

func (p *Provider) Outbounds() []adapter.Outbound {
	p.access.RLock()
	defer p.access.RUnlock()
	return append([]adapter.Outbound(nil), p.members...)
}

func (p *Provider) Outbound(tag string) (adapter.Outbound, bool) {
	p.access.RLock()
	defer p.access.RUnlock()
	outbound, loaded := p.memberByTag[tag]
	return outbound, loaded
}

func (p *Provider) UpdatedAt() time.Time {
	p.access.RLock()
	defer p.access.RUnlock()
	return p.updatedAt
}

func (p *Provider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	p.callbackAccess.Lock()
	defer p.callbackAccess.Unlock()
	return p.callbacks.PushBack(callback)
}

func (p *Provider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbackAccess.Lock()
	defer p.callbackAccess.Unlock()
	p.callbacks.Remove(element)
}

func (p *Provider) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return E.New("aggregate provider is closed")
	}
	if p.started {
		p.access.Unlock()
		return nil
	}
	p.started = true
	p.access.Unlock()
	var observer adapter.ProviderManagerObserver
	var managerHandle *list.Element[adapter.ProviderManagerUpdateCallback]
	if candidate, ok := p.manager.(adapter.ProviderManagerObserver); ok {
		observer = candidate
		managerHandle = observer.RegisterProviderCallback(p.onManagerUpdated)
		p.access.Lock()
		if p.closed {
			p.access.Unlock()
			if managerHandle != nil {
				observer.UnregisterProviderCallback(managerHandle)
			}
			return nil
		}
		p.managerObserver = observer
		p.managerHandle = managerHandle
		p.access.Unlock()
	}
	if err := p.reconcile(true); err != nil {
		p.access.Lock()
		p.started = false
		p.managerObserver = nil
		p.managerHandle = nil
		p.access.Unlock()
		if observer != nil && managerHandle != nil {
			observer.UnregisterProviderCallback(managerHandle)
		}
		return err
	}
	return nil
}

// StartContext is the provider-manager lifecycle hook. ProviderManager
// starts provider implementations through this hook rather than calling the
// generic Lifecycle interface directly.
func (p *Provider) StartContext(context.Context, *adapter.HTTPStartContext) error {
	return p.Start(adapter.StartStateStart)
}

func (p *Provider) reconcile(strict bool) error {
	desired, err := p.resolveChildren(strict)
	if err != nil {
		return err
	}
	var removed []struct {
		provider adapter.Provider
		handle   *list.Element[adapter.ProviderUpdateCallback]
	}
	var added []struct {
		tag      string
		provider adapter.Provider
	}
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return nil
	}
	for tag, child := range p.children {
		if desired[tag] == child {
			continue
		}
		removed = append(removed, struct {
			provider adapter.Provider
			handle   *list.Element[adapter.ProviderUpdateCallback]
		}{child, p.childHandles[tag]})
		delete(p.children, tag)
		delete(p.childHandles, tag)
	}
	for tag, child := range desired {
		if p.children[tag] != nil {
			continue
		}
		p.children[tag] = child
		p.childHandles[tag] = nil
		added = append(added, struct {
			tag      string
			provider adapter.Provider
		}{tag, child})
	}
	p.revision++
	p.access.Unlock()
	for _, item := range removed {
		if item.provider != nil && item.handle != nil {
			item.provider.UnregisterCallback(item.handle)
		}
	}
	for _, item := range added {
		p.attachChild(item.tag, item.provider)
	}
	p.rebuild()
	return nil
}

func (p *Provider) resolveChildren(strict bool) (map[string]adapter.Provider, error) {
	desired := make(map[string]adapter.Provider)
	if p.useAll {
		for _, child := range p.manager.Providers() {
			if child == nil || child.Tag() == "" || child.Tag() == p.tag {
				continue
			}
			// Keep the graph acyclic. An aggregate is a live view, so allowing
			// aggregate-of-aggregate with use_all could create callback cycles and
			// duplicate the same endpoint repeatedly.
			if child.Type() == C.ProviderTypeAggregate {
				continue
			}
			desired[child.Tag()] = child
		}
		return desired, nil
	}
	for index, tag := range p.configuredTags {
		if tag == p.tag {
			return nil, E.New("aggregate provider cannot include itself: ", tag)
		}
		child, loaded := p.manager.Get(tag)
		if !loaded || child == nil {
			if !strict {
				continue
			}
			return nil, E.New("outbound provider ", index, " not found: ", tag)
		}
		if child.Type() == C.ProviderTypeAggregate {
			return nil, E.New("aggregate provider cannot contain aggregate provider: ", tag)
		}
		desired[tag] = child
	}
	return desired, nil
}

func (p *Provider) attachChild(tag string, child adapter.Provider) {
	if child == nil {
		return
	}
	handle := child.RegisterCallback(p.onChildUpdated)
	p.access.Lock()
	if p.closed || p.children[tag] != child {
		p.access.Unlock()
		if handle != nil {
			child.UnregisterCallback(handle)
		}
		return
	}
	p.childHandles[tag] = handle
	p.access.Unlock()
}

func (p *Provider) onManagerUpdated() {
	if p.isClosed() {
		return
	}
	if err := p.reconcile(false); err != nil && p.logger != nil {
		p.logger.Warn("aggregate provider refresh: ", err)
	}
}

func (p *Provider) onChildUpdated(string) error {
	if p.isClosed() {
		return nil
	}
	p.access.Lock()
	p.revision++
	p.access.Unlock()
	p.rebuild()
	return nil
}

func (p *Provider) rebuild() {
	p.access.RLock()
	if p.closed {
		p.access.RUnlock()
		return
	}
	revision := p.revision
	children := make([]struct {
		tag      string
		provider adapter.Provider
	}, 0, len(p.children))
	for tag, child := range p.children {
		children = append(children, struct {
			tag      string
			provider adapter.Provider
		}{tag, child})
	}
	include, exclude := p.include, p.exclude
	p.access.RUnlock()
	sort.Slice(children, func(i, j int) bool { return children[i].tag < children[j].tag })
	type member struct {
		base     string
		identity string
		outbound adapter.Outbound
	}
	var all []member
	var updatedAt time.Time
	for _, child := range children {
		if t := child.provider.UpdatedAt(); t.After(updatedAt) {
			updatedAt = t
		}
		for _, outbound := range child.provider.Outbounds() {
			if outbound == nil || outbound.Tag() == "" || !providerAdapter.MemberAllowed(outbound.Tag(), include, exclude) {
				continue
			}
			all = append(all, member{base: outbound.Tag(), identity: identity(outbound), outbound: outbound})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].base != all[j].base {
			return all[i].base < all[j].base
		}
		return all[i].identity < all[j].identity
	})
	members := make([]adapter.Outbound, 0, len(all))
	byTag := make(map[string]adapter.Outbound, len(all))
	seen := make(map[string]int)
	for _, item := range all {
		count := seen[item.base] + 1
		seen[item.base] = count
		tag := item.base
		if count > 1 {
			tag = F.ToString(item.base, " #", count)
		}
		if tag != item.outbound.Tag() {
			item.outbound = &renamedOutbound{Outbound: item.outbound, tag: tag, identity: item.identity, dialIdentity: dialIdentity(item.outbound)}
		}
		members = append(members, item.outbound)
		byTag[tag] = item.outbound
	}
	p.access.Lock()
	if p.closed || revision != p.revision {
		p.access.Unlock()
		return
	}
	p.members = members
	p.memberByTag = byTag
	p.updatedAt = updatedAt
	p.access.Unlock()
	p.notify()
}

func identity(outbound adapter.Outbound) string {
	if identified, ok := outbound.(adapter.OutboundWithEndpointIdentity); ok && identified.EndpointIdentity() != "" {
		return identified.EndpointIdentity()
	}
	return outbound.Type() + "\x00" + outbound.Tag()
}

func dialIdentity(outbound adapter.Outbound) string {
	if identified, ok := outbound.(adapter.OutboundWithDialIdentity); ok && identified.DialIdentity() != "" {
		return identified.DialIdentity()
	}
	return identity(outbound)
}

type renamedOutbound struct {
	adapter.Outbound
	tag          string
	identity     string
	dialIdentity string
}

func (o *renamedOutbound) Tag() string              { return o.tag }
func (o *renamedOutbound) EndpointIdentity() string { return o.identity }
func (o *renamedOutbound) DialIdentity() string     { return o.dialIdentity }

func (p *Provider) isClosed() bool {
	p.access.RLock()
	defer p.access.RUnlock()
	return p.closed
}

func (p *Provider) notify() {
	p.callbackAccess.Lock()
	callbacks := make([]adapter.ProviderUpdateCallback, 0, p.callbacks.Len())
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	p.callbackAccess.Unlock()
	for _, callback := range callbacks {
		_ = callback(p.tag)
	}
}

func (p *Provider) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	p.access.RLock()
	children := make([]struct {
		tag      string
		provider adapter.Provider
	}, 0, len(p.children))
	include, exclude := p.include, p.exclude
	for _, child := range p.children {
		children = append(children, struct {
			tag      string
			provider adapter.Provider
		}{child.Tag(), child})
	}
	p.access.RUnlock()
	sort.Slice(children, func(i, j int) bool { return children[i].tag < children[j].tag })

	// Build the same deterministic display namespace as rebuild().  A health
	// map from a child is keyed by its local tag, so merging those maps directly
	// would overwrite duplicate aliases (HK/HK #2).  The source tag makes the
	// join key unambiguous and the identity ordering keeps suffixes stable
	// across provider refreshes.
	type member struct {
		sourceTag string
		base      string
		identity  string
		display   string
	}
	all := make([]member, 0)
	for _, child := range children {
		for _, outbound := range child.provider.Outbounds() {
			if outbound == nil || outbound.Tag() == "" || !providerAdapter.MemberAllowed(outbound.Tag(), include, exclude) {
				continue
			}
			all = append(all, member{sourceTag: child.tag, base: outbound.Tag(), identity: identity(outbound)})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].base != all[j].base {
			return all[i].base < all[j].base
		}
		return all[i].identity < all[j].identity
	})
	seen := make(map[string]int)
	displayBySourceTag := make(map[string]string, len(all))
	for _, item := range all {
		count := seen[item.base] + 1
		seen[item.base] = count
		display := item.base
		if count > 1 {
			display = F.ToString(item.base, " #", count)
		}
		key := item.sourceTag + "\x00" + item.base
		if _, exists := displayBySourceTag[key]; !exists {
			displayBySourceTag[key] = display
		}
	}

	result := make(map[string]uint16)
	var errs []error
	for _, child := range children {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				errs = append(errs, err)
				break
			}
		}
		checks, err := child.provider.HealthCheck(ctx)
		if err != nil {
			errs = append(errs, E.Cause(err, "health check provider ", child.tag))
			continue
		}
		for tag, delay := range checks {
			if display, exists := displayBySourceTag[child.tag+"\x00"+tag]; exists {
				result[display] = delay
			}
		}
	}
	return result, errors.Join(errs...)
}

func (p *Provider) Close() error {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return nil
	}
	p.closed = true
	children := p.children
	handles := p.childHandles
	observer, managerHandle := p.managerObserver, p.managerHandle
	p.children = make(map[string]adapter.Provider)
	p.childHandles = make(map[string]*list.Element[adapter.ProviderUpdateCallback])
	p.members = nil
	p.memberByTag = make(map[string]adapter.Outbound)
	p.managerObserver = nil
	p.managerHandle = nil
	p.access.Unlock()
	p.callbackAccess.Lock()
	p.callbacks.Init()
	p.callbackAccess.Unlock()
	if observer != nil && managerHandle != nil {
		observer.UnregisterProviderCallback(managerHandle)
	}
	for tag, child := range children {
		if child != nil && handles[tag] != nil {
			child.UnregisterCallback(handles[tag])
		}
	}
	return nil
}
