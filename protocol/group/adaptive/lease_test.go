package adaptive

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentFirstSessionHasSingleLeader(t *testing.T) {
	manager := NewSessionLeaseManager(128)
	key := SessionKey{1}
	nodeID := NodeID{9}
	var leaders atomic.Int64
	var waitGroup sync.WaitGroup
	errors := make(chan error, 100)
	for range 100 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			lease, reservation, err := manager.Reserve(context.Background(), key, time.Now())
			if err != nil {
				errors <- err
				return
			}
			if reservation != nil {
				leaders.Add(1)
				time.Sleep(5 * time.Millisecond)
				lease = reservation.Commit(nodeID, "youtube", ModeStrictAffinity, time.Minute, time.Now())
			}
			if lease.NodeID != nodeID {
				errors <- ErrNoEligibleCandidates
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if leaders.Load() != 1 {
		t.Fatalf("concurrent first session elected %d leaders", leaders.Load())
	}
}

func TestLeaseManagerIsBounded(t *testing.T) {
	manager := NewSessionLeaseManager(3)
	now := time.Now()
	for index := 0; index < 5; index++ {
		_, reservation, err := manager.Reserve(context.Background(), SessionKey{byte(index)}, now)
		if err != nil {
			t.Fatal(err)
		}
		reservation.Commit(NodeID{byte(index)}, "service", ModeAdaptive, time.Minute, now)
	}
	active, evictions := manager.Stats()
	if active != 3 || evictions != 2 {
		t.Fatalf("lease bound mismatch: active=%d evictions=%d", active, evictions)
	}
}

func TestLeaseRenewalSlidesExpiryWithoutChangingIdentity(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{7}
	handle := NodeHandle{NodeID: NodeID{9}, Slot: 3, Version: 4}
	now := time.Unix(1_700_000_000, 0)
	_, reservation, err := manager.Reserve(context.Background(), key, now)
	if err != nil {
		t.Fatal(err)
	}
	lease := reservation.CommitHandle(handle, "chatgpt_web", ModeStrictAffinity, time.Minute, now)
	renewed := manager.RenewHandle(key, handle, time.Hour, now.Add(30*time.Second))
	if renewed.NodeID != lease.NodeID || renewed.NodeSlot != lease.NodeSlot || renewed.NodeVersion != lease.NodeVersion {
		t.Fatalf("renewal changed identity: before=%+v after=%+v", lease, renewed)
	}
	if !renewed.ExpiresAt.Equal(now.Add(30*time.Second + time.Hour)) {
		t.Fatalf("renewal did not slide expiry: %v", renewed.ExpiresAt)
	}
	if changed := manager.RenewHandle(key, NodeHandle{NodeID: NodeID{8}}, time.Hour, now); changed != (SessionLease{}) {
		t.Fatalf("mismatched identity renewed lease: %+v", changed)
	}
}

func TestControlClearRejectsStaleReservationCommit(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{1}
	_, reservation, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manager.Clear()
	committed := reservation.Commit(NodeID{1}, "youtube", ModeStrictAffinity, time.Minute, time.Now())
	if committed != (SessionLease{}) {
		t.Fatalf("stale reservation unexpectedly committed: %+v", committed)
	}
	if _, loaded := manager.Peek(key, time.Now()); loaded {
		t.Fatal("stale reservation restored a lease after control change")
	}
}

func TestLeaseClearWakesExistingWaiter(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{9}
	_, first, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || first == nil {
		t.Fatalf("first reservation failed: reservation=%v err=%v", first, err)
	}

	woke := make(chan *LeaseReservation, 1)
	errors := make(chan error, 1)
	go func() {
		_, reservation, reserveErr := manager.Reserve(context.Background(), key, time.Now())
		if reserveErr != nil {
			errors <- reserveErr
			return
		}
		woke <- reservation
	}()

	deadline := time.Now().Add(time.Second)
	for {
		manager.access.Lock()
		pending := manager.pending[key]
		waiters := 0
		if pending != nil {
			waiters = pending.waiters
		}
		manager.access.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not enter pending state")
		}
		time.Sleep(time.Millisecond)
	}

	manager.Clear()
	select {
	case err = <-errors:
		t.Fatal(err)
	case second := <-woke:
		if second == nil {
			t.Fatal("woken waiter did not reserve the cleared lease")
		}
		second.Abort()
	case <-time.After(time.Second):
		t.Fatal("clear did not wake pending waiter")
	}

	first.Abort()
}

func TestOldReservationCannotCloseNewGenerationPending(t *testing.T) {
	manager := NewSessionLeaseManager(8)
	key := SessionKey{10}
	_, first, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || first == nil {
		t.Fatalf("first reservation failed: reservation=%v err=%v", first, err)
	}

	manager.Clear()
	_, second, err := manager.Reserve(context.Background(), key, time.Now())
	if err != nil || second == nil {
		t.Fatalf("second reservation failed: reservation=%v err=%v", second, err)
	}
	if committed := first.Commit(NodeID{1}, "stale", ModeAdaptive, time.Minute, time.Now()); committed != (SessionLease{}) {
		t.Fatalf("old generation committed over new pending: %+v", committed)
	}
	first.Abort()

	thirdResult := make(chan SessionLease, 1)
	thirdError := make(chan error, 1)
	go func() {
		lease, reservation, reserveErr := manager.Reserve(context.Background(), key, time.Now())
		if reserveErr != nil {
			thirdError <- reserveErr
			return
		}
		if reservation != nil {
			thirdError <- ErrNoEligibleCandidates
			return
		}
		thirdResult <- lease
	}()

	deadline := time.Now().Add(time.Second)
	for {
		manager.access.Lock()
		pending := manager.pending[key]
		waiters := 0
		if pending != nil {
			waiters = pending.waiters
		}
		manager.access.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("third reservation did not wait on second")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case lease := <-thirdResult:
		t.Fatalf("old reservation woke third before second commit: %+v", lease)
	case err = <-thirdError:
		t.Fatal(err)
	default:
	}

	expected := NodeID{2}
	second.Commit(expected, "youtube", ModeStrictAffinity, time.Minute, time.Now())
	select {
	case lease := <-thirdResult:
		if lease.NodeID != expected {
			t.Fatalf("third received wrong lease: %+v", lease)
		}
	case err = <-thirdError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("second commit did not wake third")
	}
}
