package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry   adapter.OutboundRegistry
	endpoint   adapter.EndpointManager
	defaultTag string
	access     sync.RWMutex
	// scope and stage are the authoritative lifecycle frontier. Providers may
	// publish outbounds after the initial configuration has been constructed;
	// those outbounds must be brought through every already-completed stage
	// before they become visible to consumers such as Smart.
	scope                   *adapter.Scope
	stage                   adapter.StartStage
	started                 bool
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		m.access.Unlock()
		return E.New("outbound manager already started at ", m.stage)
	}
	m.scope = scope
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := m.outbounds
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		err := m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
		if err != nil {
			return err
		}
	} else {
		for _, outbound := range outbounds {
			lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
			if !isLifecycle {
				continue
			}
			name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			err := scope.Start(name, lifecycle, stage)
			if err != nil {
				return err
			}
		}
	}
	m.access.Lock()
	m.started = true
	m.stage = stage
	m.access.Unlock()
	return nil
}

// startDynamicOutbound advances a just-created outbound through the lifecycle
// frontier captured by Start.  In particular, a provider can create members
// after the manager's initialize phase but before or after its start phase.
// Leaving such members merely registered makes the control plane advertise
// objects whose protocol clients were never initialized.
func (m *Manager) startDynamicOutbound(scope *adapter.Scope, stage adapter.StartStage, outbound adapter.Outbound) error {
	if scope == nil {
		return nil
	}
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if isLifecycle {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, currentStage := range adapter.ListStartStages {
			if currentStage > stage {
				break
			}
			if err := scope.Start(name, lifecycle, currentStage); err != nil {
				return E.Cause(err, "start dynamic ", name)
			}
		}
		return nil
	}
	if stage < adapter.StartStateStart {
		return nil
	}
	name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
	if starter, ok := outbound.(adapter.SimpleLifecycle); ok {
		if err := starter.Start(); err != nil {
			return E.Cause(err, "start dynamic ", name)
		}
		scope.Add(starter.Close)
	}
	return nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, outboundToStart := range outbounds {
			outboundTag := outboundToStart.Tag()
			if started[outboundTag] {
				continue
			}
			dependencies := outboundToStart.Dependencies()
			for _, dependency := range dependencies {
				if !started[dependency] {
					continue startOne
				}
			}
			started[outboundTag] = true
			canContinue = true
			if endpoint, isEndpoint := outboundToStart.(adapter.Endpoint); isEndpoint {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
				continue
			}
			name := "outbound/" + outboundToStart.Type() + "[" + outboundTag + "]"
			if lifecycle, isLifecycle := outboundToStart.(adapter.Lifecycle); isLifecycle {
				err := scope.Start(name, lifecycle, adapter.StartStateStart)
				if err != nil {
					return err
				}
			} else if starter, isStarter := outboundToStart.(adapter.SimpleLifecycle); isStarter {
				if err := starter.Start(); err != nil {
					return E.Cause(err, "start ", name)
				}
				scope.Add(starter.Close)
			}
		}
		if len(started) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !started[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !started[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	// Do not hold the registry lock while running lifecycle callbacks. A
	// protocol initializer is allowed to resolve a detour through this manager.
	m.access.RLock()
	scope, stage, started := m.scope, m.stage, m.started
	m.access.RUnlock()
	if started {
		if err = m.startDynamicOutbound(scope, stage, outbound); err != nil {
			_ = common.Close(outbound)
			return err
		}
	}
	m.access.Lock()
	previous := m.outboundByTag[tag]
	if previous != nil {
		m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool { return it.Tag() != tag })
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if previous != nil {
		// Provider refreshes are upserts. Publish the fully initialized
		// replacement first, then retire the old leaf so no observer sees a
		// transient missing tag.
		if err = common.Close(previous); err != nil {
			return E.Cause(err, "close replaced outbound: ", tag)
		}
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	if tag == m.defaultTag || (m.defaultOutbound != nil && m.defaultOutbound.Tag() == tag) {
		m.access.Unlock()
		return E.New("cannot remove default outbound: ", tag)
	}
	outbound, found := m.outboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrNotExist
	}
	delete(m.outboundByTag, tag)
	m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool { return it.Tag() != tag })
	m.access.Unlock()
	if closer, ok := outbound.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
