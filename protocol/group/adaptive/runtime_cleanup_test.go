package adaptive

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func commitCleanupEpoch(t *testing.T, manager *RuntimeManager, groupID string) RuntimeIdentity {
	t.Helper()
	prepared, err := manager.PrepareEpoch(
		groupID,
		NewHealthStore(time.Hour, 8),
		NewSessionLeaseManager(8),
		new(ControlState),
		identitySnapshot(1, IdentityNode{NodeID: NodeID{1}, IdentityStable: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func waitForRuntimeStats(t *testing.T, manager *RuntimeManager, wantGroups, wantSchedulers, wantUsers int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		groups, schedulers, users := manager.RuntimeStats()
		if groups == wantGroups && schedulers == wantSchedulers && users == wantUsers {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime stats did not settle: got groups=%d schedulers=%d users=%d, want %d/%d/%d", groups, schedulers, users, wantGroups, wantSchedulers, wantUsers)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRuntimeManagerCleansIdleGroupAndCoordinator(t *testing.T) {
	manager := NewRuntimeManager()
	manager.RegisterGroup("idle")
	identity := commitCleanupEpoch(t, manager, "idle")
	manager.SchedulerCoordinator("idle")
	manager.RetireEpoch("idle", identity.EpochID)
	manager.UnregisterGroup("idle")
	waitForRuntimeStats(t, manager, 0, 0, 0)
}

func TestRuntimeManagerRetainsRetiringEpochUntilLeaseRelease(t *testing.T) {
	manager := NewRuntimeManager()
	manager.RegisterGroup("lease")
	identity := commitCleanupEpoch(t, manager, "lease")
	manager.SchedulerCoordinator("lease")
	lease, err := manager.AcquireEpoch("lease", identity.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	manager.RetireEpoch("lease", identity.EpochID)
	manager.UnregisterGroup("lease")
	waitForRuntimeStats(t, manager, 1, 1, 0)
	lease.Release()
	waitForRuntimeStats(t, manager, 0, 0, 0)
}

func TestRuntimeManagerWaitsForSchedulerDrainAndRejectsABADelete(t *testing.T) {
	manager := NewRuntimeManager()
	manager.RegisterGroup("drain")
	identity := commitCleanupEpoch(t, manager, "drain")
	coordinator := manager.SchedulerCoordinator("drain")
	token, err := coordinator.Claim(identity.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	scheduler := newOwnedProbeScheduler(context.Background(), coordinator, token, 1, 8)
	manager.RetireEpoch("drain", identity.EpochID)
	coordinator.Release(identity.EpochID, token.Generation)
	manager.UnregisterGroup("drain")
	waitForRuntimeStats(t, manager, 0, 1, 0)

	manager.RegisterGroup("drain")
	if err = scheduler.Close(); err != nil {
		t.Fatal(err)
	}
	waitForRuntimeStats(t, manager, 0, 1, 1)
	if current := manager.SchedulerCoordinator("drain"); current != coordinator {
		t.Fatal("drain waiter deleted coordinator after group was re-registered")
	}
	manager.UnregisterGroup("drain")
	waitForRuntimeStats(t, manager, 0, 0, 0)
}

func TestRuntimeManagerCleanupTenThousandGroups(t *testing.T) {
	manager := NewRuntimeManager()
	for index := 0; index < 10_000; index++ {
		groupID := fmt.Sprintf("churn-%d", index)
		manager.RegisterGroup(groupID)
		identity := commitCleanupEpoch(t, manager, groupID)
		manager.SchedulerCoordinator(groupID)
		manager.RetireEpoch(groupID, identity.EpochID)
		manager.UnregisterGroup(groupID)
	}
	waitForRuntimeStats(t, manager, 0, 0, 0)
}

func TestAdaptivePoolThousandPublishRetireCyclesLeaveNoRuntimeState(t *testing.T) {
	manager := NewRuntimeManager()
	for index := 0; index < 1000; index++ {
		groupID := fmt.Sprintf("publish-retire-%d", index)
		manager.RegisterGroup(groupID)
		pool := preparedLifecyclePool(t, manager, groupID)
		if err := pool.OnRuntimeEpochPublish(); err != nil {
			t.Fatalf("cycle %d publish failed: %v", index, err)
		}
		pool.OnRuntimeEpochPublishCommit()
		if err := pool.Close(); err != nil {
			t.Fatalf("cycle %d close failed: %v", index, err)
		}
	}
	waitForRuntimeStats(t, manager, 0, 0, 0)
}
