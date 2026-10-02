package adaptive

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing/service"
)

func preparedLifecyclePool(t *testing.T, manager *RuntimeManager, groupID string) *AdaptivePool {
	t.Helper()
	health := NewHealthStore(time.Hour, 16)
	pool := &AdaptivePool{ctx: context.Background(), groupID: groupID, runtimeManager: manager, health: health, leases: NewSessionLeaseManager(16), control: new(ControlState), policy: NewPolicyEngine(health, 1, "fallback"), policyMaxAttempts: 1, manualFailure: "fallback", catalog: NewCatalogPort(), publishPhase: publishPhasePrepared}
	source := portSource(1, portNode(NodeID{100}, "node"))
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	pool.preparedIdentity, err = manager.PrepareEpoch(groupID, pool.health, pool.leases, pool.control, identitySource)
	if err != nil {
		t.Fatal(err)
	}
	pool.preparedExecution, err = pool.catalog.PrepareCommitted(source, pool.preparedIdentity.Identity())
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestRuntimeManagerSharesStateAcrossPublishedEpochs(t *testing.T) {
	manager := NewRuntimeManager()
	statePath := filepath.Join(t.TempDir(), "group-state")
	newPool := func() *AdaptivePool {
		health := NewHealthStore(time.Hour, 32)
		pool := &AdaptivePool{
			statePath:         statePath,
			groupID:           "group",
			runtimeManager:    manager,
			health:            health,
			leases:            NewSessionLeaseManager(32),
			control:           new(ControlState),
			policy:            NewPolicyEngine(health, 3, "fallback"),
			policyMaxAttempts: 3,
			manualFailure:     "fallback",
			catalog:           NewCatalogPort(),
			publishPhase:      publishPhasePrepared,
		}
		source := portSource(1, portNode(NodeID{9}, "node"))
		identitySource, err := IdentityFromSource(source.SourceSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		pool.preparedIdentity, err = manager.PrepareEpoch(pool.groupID, pool.health, pool.leases, pool.control, identitySource)
		if err != nil {
			t.Fatal(err)
		}
		pool.preparedExecution, err = pool.catalog.PrepareCommitted(source, pool.preparedIdentity.Identity())
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}
	first := newPool()
	if err := first.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	first.health.Observe(Observation{NodeID: NodeID{1}, Scope: ScopeEndpoint, Outcome: OutcomeSuccess})
	first.control.access.Lock()
	first.control.pinned = NodeID{2}
	first.control.pinnedTag = "node"
	first.control.access.Unlock()

	second := newPool()
	if err := second.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	if second.health != first.health || second.leases != first.leases || second.control != first.control {
		t.Fatal("published generation did not attach stable group state")
	}
	if status := second.health.Endpoint(NodeID{1}); status.Health != HealthHealthy || status.Breaker != BreakerClosed {
		t.Fatalf("health did not survive generation publish: %+v", status)
	}
	if pinned := second.pinnedNodeID(); pinned == nil || *pinned != (NodeID{2}) {
		t.Fatalf("manual control did not survive generation publish: %v", pinned)
	}
}

func TestContextWithDefaultRuntimeManagerIsIdempotent(t *testing.T) {
	ctx := ContextWithDefaultRuntimeManager(context.Background())
	first := service.PtrFromContext[RuntimeManager](ctx)
	ctx = ContextWithDefaultRuntimeManager(ctx)
	second := service.PtrFromContext[RuntimeManager](ctx)
	if first == nil || first != second {
		t.Fatal("runtime manager context was replaced")
	}
}

func TestCommittedVersionTransitionRetiresHealthAndLeaseOnlyAfterApply(t *testing.T) {
	manager := NewRuntimeManager()
	health := NewHealthStore(time.Hour, 32)
	leases := NewSessionLeaseManager(32)
	nodeID := NodeID{70}
	firstPrepared, err := manager.PrepareEpoch("group", health, leases, new(ControlState), identitySnapshot(1, IdentityNode{NodeID: nodeID}))
	if err != nil {
		t.Fatal(err)
	}
	_, first, err := firstPrepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	v1 := first.Handles[nodeID]
	epochLease, err := manager.AcquireEpoch("group", first.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer epochLease.Release()
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: v1.Slot, NodeVersion: v1.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	leaseKey := SessionKey{9}
	leases.ReplaceHandle(leaseKey, NodeHandle{}, v1, "service", ModeAdaptive, time.Hour, time.Now())

	rollbackPrepared, err := manager.PrepareRevision("group", first.EpochID, identitySnapshot(2, IdentityNode{NodeID: nodeID}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = rollbackPrepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if err = rollbackPrepared.Rollback(); err != nil {
		t.Fatal(err)
	}
	if health.EndpointHandle(v1).Breaker != BreakerOpen {
		t.Fatal("rollback cleared v1 health")
	}
	if lease, loaded := leases.Peek(leaseKey, time.Now()); !loaded || lease.NodeSlot != v1.Slot || lease.NodeVersion != v1.Version {
		t.Fatal("rollback cleared v1 lease")
	}

	committedPrepared, err := manager.PrepareRevision("group", first.EpochID, identitySnapshot(2, IdentityNode{NodeID: nodeID}))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := committedPrepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(second.VersionTransitions) != 1 || len(second.RetiredHandles) != 1 {
		t.Fatalf("missing committed version delta: %+v", second)
	}
	if epochLease.ValidateObservation(first.Revision, nodeID, v1.Slot, v1.Version) {
		t.Fatal("retiring v1 lease accepted evidence after v2 became current")
	}
	pool := &AdaptivePool{health: health, leases: leases}
	pool.applyCommittedTransitions(second)
	if status := health.EndpointHandle(v1); status.Health != HealthUnknown {
		t.Fatalf("committed v1 health not retired: %+v", status)
	}
	if _, loaded := leases.Peek(leaseKey, time.Now()); loaded {
		t.Fatal("committed v1 lease not retired")
	}
}

func TestSourceUpdateDuringPublishCannotCreateRollbackRevision(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "phase-group")
	if err := pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	if err := pool.onSourceUpdated(); err != nil {
		t.Fatal(err)
	}
	pool.lifecycleAccess.Lock()
	dirty, phase := pool.sourceDirty, pool.publishPhase
	pool.lifecycleAccess.Unlock()
	if !dirty || phase != publishPhasePublishing {
		t.Fatalf("source update escaped publishing barrier: dirty=%v phase=%v", dirty, phase)
	}
	manager.access.RLock()
	revision := manager.groups["phase-group"].identity.nextRevision
	manager.access.RUnlock()
	if revision != 1 {
		t.Fatalf("provider callback committed an extra revision: %d", revision)
	}
	pool.OnRuntimeEpochPublishRollback()
	manager.access.RLock()
	_, retained := manager.groups["phase-group"]
	manager.access.RUnlock()
	if retained || pool.catalog.Snapshot() != nil {
		t.Fatal("rollback retained aborted stable identity or execution catalog")
	}
}

func TestIdentityKeyPersistenceFailurePreventsStableCommit(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "key-group")
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool.statePath = filepath.Join(blocker, "adaptive-state")
	pool.identityKeyNew = true
	if err := pool.persistPreparedIdentityKey(); err == nil {
		t.Fatal("identity key persistence failure was ignored")
	}
	if err := pool.OnRuntimeEpochPublish(); err == nil {
		t.Fatal("publish committed without durable identity key")
	}
	manager.access.RLock()
	_, committed := manager.groups["key-group"]
	manager.access.RUnlock()
	if committed || pool.catalog.Snapshot() != nil {
		t.Fatal("identity key failure polluted stable state/catalog")
	}
}
