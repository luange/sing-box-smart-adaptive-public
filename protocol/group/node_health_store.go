package group

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// smartHealthStoreConfig is deliberately core-scoped. A leaf can appear in
// more than one Smart group, so circuit evidence cannot legitimately use a
// different policy depending on which group happened to observe it first.
type smartHealthStoreConfig struct {
	halfLife        time.Duration
	breakerFailures int
	breakerCooldown time.Duration
	retention       time.Duration
	maxEntries      int
}

func (c smartHealthStoreConfig) equal(other smartHealthStoreConfig) bool {
	return c == other
}

type smartHealthStoreReference struct {
	store     *nodeHealthStore
	config    smartHealthStoreConfig
	refs      int
	smartRefs int
}

var smartHealthStores struct {
	sync.Mutex
	byManager map[uintptr]*smartHealthStoreReference
}

// acquireSmartHealthStore returns the one NodeHealthStore for an outbound
// manager/runtime. It has no package-global fallback shared by tests or
// unrelated sing-box instances: without a stable manager identity the caller
// receives an isolated store.
func defaultNodeHealthStoreConfig() smartHealthStoreConfig {
	return smartHealthStoreConfig{
		halfLife:        defaultSmartHalfLife,
		breakerFailures: defaultSmartBreakerFailures,
		breakerCooldown: defaultSmartBreakerCooldown,
		retention:       defaultSmartHistoryRetention,
		maxEntries:      defaultSmartMaxHistoryEntries,
	}
}

// acquireNodeHealthStore obtains a reference for policies which contribute or
// consume shared leaf health but do not own Smart's scoring policy.  The first
// Smart owner may later replace these defaults with its configured policy.
func acquireNodeHealthStore(manager adapter.OutboundManager) (*nodeHealthStore, func()) {
	store, release, _ := acquireHealthStore(manager, defaultNodeHealthStoreConfig(), false)
	return store, release
}

func acquireSmartHealthStore(_ context.Context, manager adapter.OutboundManager, config smartHealthStoreConfig) (*nodeHealthStore, func(), bool) {
	return acquireHealthStore(manager, config, true)
}

func acquireHealthStore(manager adapter.OutboundManager, config smartHealthStoreConfig, smartOwner bool) (*nodeHealthStore, func(), bool) {
	managerKey := outboundManagerIdentity(manager)
	if managerKey == 0 {
		store := newSmartStore(config.halfLife, config.breakerFailures, config.breakerCooldown)
		store.setBounds(config.retention, config.maxEntries)
		return store, func() { store.clear() }, true
	}
	smartHealthStores.Lock()
	if smartHealthStores.byManager == nil {
		smartHealthStores.byManager = make(map[uintptr]*smartHealthStoreReference)
	}
	reference := smartHealthStores.byManager[managerKey]
	created := false
	if reference == nil {
		store := newSmartStore(config.halfLife, config.breakerFailures, config.breakerCooldown)
		store.setBounds(config.retention, config.maxEntries)
		reference = &smartHealthStoreReference{store: store, config: config}
		smartHealthStores.byManager[managerKey] = reference
		created = true
	} else if smartOwner && !reference.config.equal(config) {
		// A newly constructed Smart policy is the configuration authority for
		// this runtime. This makes overlapping reload safe: the replacement
		// adopts the existing evidence while immediately applying its new
		// limits, rather than waiting for the retiring instance to close.
		reference.config = config
		reference.store.setPolicy(config.halfLife, config.breakerFailures, config.breakerCooldown)
		reference.store.setBounds(config.retention, config.maxEntries)
	}
	reference.refs++
	if smartOwner {
		reference.smartRefs++
	}
	store := reference.store
	matchingConfig := !smartOwner || reference.config.equal(config)
	smartHealthStores.Unlock()

	var once sync.Once
	return store, func() {
		once.Do(func() {
			closeStore := false
			smartHealthStores.Lock()
			if current := smartHealthStores.byManager[managerKey]; current == reference {
				current.refs--
				if smartOwner {
					current.smartRefs--
				}
				if current.refs <= 0 {
					delete(smartHealthStores.byManager, managerKey)
					closeStore = true
				}
			}
			smartHealthStores.Unlock()
			if closeStore {
				store.clear()
			}
		})
	}, matchingConfig || created
}

// sharedNodeHealthStore returns the runtime-owned health authority without
// taking a lifecycle reference. Every group policy can create the authority;
// the first Smart owner supplies its scoring and retention configuration.
func sharedNodeHealthStore(manager adapter.OutboundManager) *nodeHealthStore {
	managerKey := outboundManagerIdentity(manager)
	if managerKey == 0 {
		return nil
	}
	smartHealthStores.Lock()
	reference := smartHealthStores.byManager[managerKey]
	smartHealthStores.Unlock()
	if reference == nil {
		return nil
	}
	return reference.store
}

// SharedNodeHealthStatus exposes aggregate, credential-safe health-store
// diagnostics to API adapters. It returns false until a group policy has
// created the runtime store; callers must treat that as "not initialized",
// not an empty or unhealthy node pool.
func SharedNodeHealthStatus(manager adapter.OutboundManager) (adapter.SmartHealthStoreStatus, bool) {
	store := sharedNodeHealthStore(manager)
	if store == nil {
		return adapter.SmartHealthStoreStatus{}, false
	}
	return store.status(), true
}

func SharedNodeHealthEntries(manager adapter.OutboundManager, limit int) ([]adapter.SmartHealthEntry, bool) {
	store := sharedNodeHealthStore(manager)
	if store == nil {
		return nil, false
	}
	return store.entries(limit), true
}

func SharedNodeHealthEvents(manager adapter.OutboundManager, limit int) ([]adapter.SmartHealthEvent, bool) {
	store := sharedNodeHealthStore(manager)
	if store == nil {
		return nil, false
	}
	return store.events(limit), true
}

func nodeHealthProfileID(outbound adapter.Outbound) string {
	return nodeHealthProfileIDForNetwork(outbound, N.NetworkTCP)
}

// nodeHealthProfileIDForNetwork resolves nested policy groups to the leaf
// they will actually dial. A Selector -> URLTest chain must report the same
// credential identity as Smart's direct leaf, never a transient group tag.
func nodeHealthProfileIDForNetwork(outbound adapter.Outbound, network string) string {
	outbound = nodeHealthLeaf(outbound, network)
	if outbound == nil {
		return ""
	}
	_, dialIdentity := groupProfileIdentity(outbound)
	if dialIdentity != "" && dialIdentity != outbound.Tag() {
		return "dial:" + dialIdentity
	}
	return outbound.Tag()
}

func nodeHealthLeaf(outbound adapter.Outbound, network string) adapter.Outbound {
	seen := make(map[string]struct{})
	for depth := 0; outbound != nil && depth < 16; depth++ {
		selector, isSelector := outbound.(interface{ Selected(string) adapter.Outbound })
		if !isSelector {
			return outbound
		}
		tag := outbound.Tag()
		if tag != "" {
			if _, exists := seen[tag]; exists {
				return outbound
			}
			seen[tag] = struct{}{}
		}
		selected := selector.Selected(network)
		if selected == nil {
			return outbound
		}
		outbound = selected
	}
	return outbound
}

func nodeHealthNetworkKey(network adapter.NetworkManager) string {
	if network == nil {
		return "network-default"
	}
	return smartNetworkFingerprint(network.DefaultNetworkInterface(), network.WIFIState())
}

// nodeHealthCircuitOpen only rejects candidates with confirmed data-plane
// breaker evidence. Unknown and merely slow nodes remain eligible so URLTest
// can establish fresh evidence and Selector never becomes an implicit policy.
func nodeHealthCircuitOpen(store *nodeHealthStore, networkKey string, outbound adapter.Outbound, transport string, now time.Time) bool {
	if store == nil || outbound == nil {
		return false
	}
	profile := nodeHealthProfileIDForNetwork(outbound, transport)
	if profile == "" {
		return false
	}
	return store.endpointDead(networkKey, profile, transport, now)
}

// recordSharedNodeHealthDial is the one data-plane evidence path shared by
// Smart-adjacent policies.  It intentionally distinguishes a caller cancel
// and a dashboard probe from an actual endpoint failure: only real protocol
// or transport failures may advance the common circuit breaker.
func recordSharedNodeHealthDial(manager adapter.OutboundManager, networkManager adapter.NetworkManager, selected adapter.Outbound, network string, dialErr error, elapsed time.Duration, requestCtx context.Context) {
	store := sharedNodeHealthStore(manager)
	if store == nil || selected == nil || isSmartRequestContextError(requestCtx, dialErr) {
		return
	}
	profile := nodeHealthProfileIDForNetwork(selected, network)
	if profile == "" {
		return
	}
	store.retainExternalProfile(profile)
	now := time.Now()
	networkKey := nodeHealthNetworkKey(networkManager)
	if dialErr == nil {
		store.observeDial(now, networkKey, "", profile, network, true, elapsed)
		return
	}
	failureType := smartFailureType(dialErr)
	if failureType == "protocol" || failureType == "hard_transport" {
		store.observeDialWithFailureType(now, networkKey, "", profile, network, false, elapsed, failureType)
		return
	}
	store.observeDialAdvisory(now, networkKey, "", profile, network, false, elapsed)
}
