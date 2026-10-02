package adaptive

import (
	"errors"
	"testing"
	"time"
)

func identitySnapshot(generation uint64, nodes ...IdentityNode) IdentitySnapshot {
	return IdentitySnapshot{SourceGeneration: generation, Nodes: nodes}
}

func prepareEpochForTest(t *testing.T, manager *RuntimeManager, group string, snapshot IdentitySnapshot) RuntimeIdentity {
	t.Helper()
	prepared, err := manager.PrepareEpoch(group, NewHealthStore(time.Hour, 32), NewSessionLeaseManager(32), new(ControlState), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestCrossEpochEvidenceIdentityUsesStableRevisionAllocator(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{42}, IdentityStable: true}
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	second := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	if first.EpochID == second.EpochID || first.Revision == second.Revision {
		t.Fatalf("cross-epoch identity collided: first=%+v second=%+v", first, second)
	}
	if first.Handles[node.NodeID].Slot != second.Handles[node.NodeID].Slot || first.Handles[node.NodeID].Version != second.Handles[node.NodeID].Version {
		t.Fatal("stable node did not retain slot/version across epoch")
	}
	manager.RetireEpoch("group", first.EpochID)
	if manager.ValidateObservation("group", first.EpochID, first.Revision, node.NodeID, first.Handles[node.NodeID].Slot, first.Handles[node.NodeID].Version) {
		t.Fatal("retired epoch evidence was accepted")
	}
}

func TestPreparedEpochAbortAndStaleCommitDoNotAdvanceIdentity(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{1}, IdentityStable: true}
	first, err := manager.PrepareEpoch("group", NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), identitySnapshot(1, node))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.PrepareEpoch("group", NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), identitySnapshot(1, node))
	if err != nil {
		t.Fatal(err)
	}
	_, committed, err := first.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = second.Commit(); !errors.Is(err, ErrPreparedIdentityStale) {
		t.Fatalf("concurrent stale prepare was not rejected: %v", err)
	}
	third := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	if third.EpochID != committed.EpochID+1 || third.Revision != committed.Revision+1 {
		t.Fatalf("aborted/stale prepare advanced allocators: committed=%+v next=%+v", committed, third)
	}
}

func TestRevisionRejectsSourceGenerationRollbackWithoutAdvance(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{2}, IdentityStable: true}
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(7, node))
	if _, err := manager.PrepareRevision("group", first.EpochID, identitySnapshot(7, node)); !errors.Is(err, ErrSourceGenerationOutOfOrder) {
		t.Fatalf("same source generation accepted: %v", err)
	}
	prepared, err := manager.PrepareRevision("group", first.EpochID, identitySnapshot(8, node))
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != first.Revision+1 {
		t.Fatalf("rejected generation advanced revision: first=%d second=%d", first.Revision, second.Revision)
	}
}

func TestRetiringEpochRequiresValidLease(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{3}, IdentityStable: true}
	identity := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	lease, err := manager.AcquireEpoch("group", identity.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	manager.RetireEpoch("group", identity.EpochID)
	handle := identity.Handles[node.NodeID]
	if manager.ValidateObservation("group", identity.EpochID, identity.Revision, node.NodeID, handle.Slot, handle.Version) {
		t.Fatal("unleased observation entered retiring epoch")
	}
	if !lease.ValidateObservation(identity.Revision, node.NodeID, handle.Slot, handle.Version) {
		t.Fatal("valid epoch lease did not preserve retiring observation")
	}
	lease.Release()
	if lease.ValidateObservation(identity.Revision, node.NodeID, handle.Slot, handle.Version) {
		t.Fatal("released lease still accepted observation")
	}
}

func TestLeaseValidationDoesNotLeakRuntimeManagerReadLock(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{30}, IdentityStable: true}
	identity := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	lease, err := manager.AcquireEpoch("group", identity.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	handle := identity.Handles[node.NodeID]
	if !lease.ValidateObservation(identity.Revision, node.NodeID, handle.Slot, handle.Version) {
		t.Fatal("lease validation failed")
	}
	done := make(chan struct{})
	go func() {
		manager.RetireEpoch("group", identity.EpochID)
		lease.Release()
		prepared, prepareErr := manager.PrepareEpoch("group", NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), identitySnapshot(1, node))
		if prepareErr == nil {
			_, _, prepareErr = prepared.Commit()
		}
		if prepareErr != nil {
			t.Errorf("writer path failed after validation: %v", prepareErr)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ValidateObservation leaked RuntimeManager read lock")
	}
}

func TestPreparedCatalogCommitDoesNotOverwriteConcurrentEpochLifecycle(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{31}, IdentityStable: true}
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
	lease, err := manager.AcquireEpoch("group", first.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := manager.PrepareEpoch("group", NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), identitySnapshot(1, node))
	if err != nil {
		t.Fatal(err)
	}
	manager.RetireEpoch("group", first.EpochID)
	if _, _, err = prepared.Commit(); err != nil {
		t.Fatal(err)
	}
	handle := first.Handles[node.NodeID]
	if !lease.ValidateObservation(first.Revision, node.NodeID, handle.Slot, handle.Version) {
		t.Fatal("catalog commit lost concurrent retiring lease state")
	}
	manager.access.Lock()
	epoch := manager.groups["group"].epochs[first.EpochID]
	if epoch == nil || epoch.lifecycle != EpochRetiring || epoch.refCount != 1 {
		t.Fatalf("catalog commit overwrote lifecycle mutation: %+v", epoch)
	}
	manager.access.Unlock()
	lease.Release()
	manager.access.Lock()
	_, retained := manager.groups["group"].epochs[first.EpochID]
	manager.access.Unlock()
	if retained {
		t.Fatal("retired epoch survived final lease release")
	}
}

func TestIdentityLineageStableUnstableAndRemoveReadd(t *testing.T) {
	manager := NewRuntimeManager()
	stableID, unstableID := NodeID{4}, NodeID{5}
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: stableID, IdentityStable: true}, IdentityNode{NodeID: unstableID}))
	second := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: stableID, IdentityStable: true}, IdentityNode{NodeID: unstableID}))
	if first.Handles[stableID] != second.Handles[stableID] {
		t.Fatal("stable handle changed across epoch")
	}
	if second.Handles[unstableID].Version <= first.Handles[unstableID].Version {
		t.Fatal("unstable handle version did not advance")
	}
	_ = prepareEpochForTest(t, manager, "group", identitySnapshot(1))
	readded := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: stableID, IdentityStable: true}))
	if readded.Handles[stableID].Version <= second.Handles[stableID].Version {
		t.Fatal("remove/re-add did not advance version")
	}
}

func TestThousandRetiredEpochsAreReclaimed(t *testing.T) {
	manager := NewRuntimeManager()
	manager.RegisterGroup("group")
	defer manager.UnregisterGroup("group")
	node := IdentityNode{NodeID: NodeID{6}, IdentityStable: true}
	for index := 0; index < 1000; index++ {
		identity := prepareEpochForTest(t, manager, "group", identitySnapshot(1, node))
		manager.RetireEpoch("group", identity.EpochID)
	}
	manager.access.Lock()
	state := manager.groups["group"]
	epochs, lineage := len(state.epochs), len(state.identity.lineage)
	manager.access.Unlock()
	if epochs != 0 || lineage != 1 {
		t.Fatalf("retired identity state grew without bound: epochs=%d lineage=%d", epochs, lineage)
	}
}

func TestRetiredLineageIsBoundedWithoutReaddABA(t *testing.T) {
	manager := NewRuntimeManager()
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: NodeID{1}, IdentityStable: true}))
	manager.access.Lock()
	manager.groups["group"].identity.maxRetired = 2
	manager.access.Unlock()
	for generation := uint64(2); generation <= 8; generation++ {
		prepared, err := manager.PrepareRevision("group", first.EpochID, identitySnapshot(generation, IdentityNode{NodeID: NodeID{byte(generation)}, IdentityStable: true}))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = prepared.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	manager.access.RLock()
	state := manager.groups["group"].identity
	lineage, queued := len(state.lineage), len(state.retiredQueued)
	manager.access.RUnlock()
	if lineage > 3 || queued > 2 {
		t.Fatalf("retired lineage exceeded bound: lineage=%d queued=%d", lineage, queued)
	}
}

func TestSlotPreventsVersionABAAfterRetiredLineageEviction(t *testing.T) {
	manager := NewRuntimeManager()
	nodeID := NodeID{90}
	first := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	old := first.Handles[nodeID]
	lease, err := manager.AcquireEpoch("group", first.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	manager.access.Lock()
	manager.groups["group"].identity.maxRetired = 1
	manager.access.Unlock()
	_ = prepareEpochForTest(t, manager, "group", identitySnapshot(1))
	_ = prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: NodeID{91}, IdentityStable: true}))
	_ = prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: NodeID{92}, IdentityStable: true}))
	readded := prepareEpochForTest(t, manager, "group", identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	current := readded.Handles[nodeID]
	if current.Slot == old.Slot || current.Version != 1 || old.Version != 1 {
		t.Fatalf("test did not create slot ABA boundary: old=%+v current=%+v", old, current)
	}
	if lease.ValidateObservation(first.Revision, nodeID, old.Slot, old.Version) {
		t.Fatal("old epoch evidence validated after same NodeID/version moved to a new slot")
	}
	health := NewHealthStore(time.Hour, 8)
	health.Observe(Observation{NodeID: nodeID, NodeSlot: old.Slot, NodeVersion: old.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	if status := health.EndpointHandle(current); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("new slot inherited old breaker: %+v", status)
	}
	leases := NewSessionLeaseManager(8)
	key := SessionKey{90}
	leases.ReplaceHandle(key, NodeHandle{}, old, "service", ModeAdaptive, time.Hour, time.Now())
	stored, loaded := leases.Peek(key, time.Now())
	if !loaded || stored.NodeSlot == current.Slot {
		t.Fatalf("old lease unexpectedly rebound to new slot: %+v", stored)
	}
}
