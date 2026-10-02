package interrupt

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterruptSelectiveTargetsPreviousCandidateAndKeepsLongActive(t *testing.T) {
	group := NewGroup()
	now := time.Now()
	var peers []net.Conn
	add := func(key string, createdAt, lastActive time.Time) net.Conn {
		left, right := net.Pipe()
		peers = append(peers, right)
		wrapped := group.NewConnWithKey(left, true, false, key)
		item := wrapped.(*Conn).element.Value
		item.createdAt = createdAt
		item.lastActive.Store(lastActive.UnixNano())
		return wrapped
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	for range 3 {
		add("old", now.Add(-20*time.Second), now.Add(-15*time.Second))
	}
	for range 4 {
		add("old", now.Add(-5*time.Second), now)
	}
	for range 3 {
		add("old", now.Add(-time.Minute), now)
	}
	add("new", now.Add(-time.Minute), now.Add(-time.Minute))

	result := group.InterruptSelective(InterruptPolicy{
		IdleThreshold: 10 * time.Second,
		LongConnAge:   30 * time.Second,
		TargetKey:     "old",
	})
	if result.Interrupted != 7 || result.Idle != 3 || result.Short != 4 {
		t.Fatalf("unexpected interrupted result: %+v", result)
	}
	if result.Kept != 4 || result.KeptLong != 3 {
		t.Fatalf("unexpected kept result: %+v", result)
	}
}

func TestInterruptSelectiveCountsGraceCloseWhenItHappens(t *testing.T) {
	group := NewGroup()
	left, right := net.Pipe()
	defer right.Close()
	group.NewConnWithKey(left, true, false, "old")
	var closed atomic.Uint64
	result := group.InterruptSelective(InterruptPolicy{
		IdleThreshold: time.Minute,
		LongConnAge:   time.Minute,
		GracePeriod:   10 * time.Millisecond,
		TargetKey:     "old",
		OnInterrupted: func() { closed.Add(1) },
	})
	if result.Interrupted != 0 || result.Deferred != 1 || closed.Load() != 0 {
		t.Fatalf("grace close counted before deadline: result=%+v closed=%d", result, closed.Load())
	}
	deadline := time.Now().Add(time.Second)
	for closed.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatal("grace close was not observed")
	}
}

func TestInterruptSelectiveForceAllOnlyTargetsSelectedCandidate(t *testing.T) {
	group := NewGroup()
	oldLeft, oldRight := net.Pipe()
	defer oldRight.Close()
	newLeft, newRight := net.Pipe()
	defer newRight.Close()
	group.NewConnWithKey(oldLeft, true, false, "old")
	group.NewConnWithKey(newLeft, true, false, "new")

	result := group.InterruptSelective(InterruptPolicy{ForceAll: true, TargetKey: "old"})
	if result.Interrupted != 1 || result.Kept != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestInterruptSelectiveDoesNotGloballyBlockConnectionAdmission(t *testing.T) {
	group := NewGroup()
	for index := 0; index < 4096; index++ {
		left, right := net.Pipe()
		t.Cleanup(func() { _ = right.Close() })
		key := fmt.Sprintf("candidate-%d", index%64)
		_ = group.NewConnWithKey(left, false, false, key)
	}
	done := make(chan struct{})
	go func() {
		group.InterruptSelective(InterruptPolicy{TargetKey: "candidate-1", ForceAll: true})
		close(done)
	}()
	left, right := net.Pipe()
	defer right.Close()
	started := time.Now()
	conn := group.NewConnWithKey(left, false, false, "unrelated-admission-key")
	defer conn.Close()
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("unrelated connection admission blocked by selective scan: %v", elapsed)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("selective interrupt did not complete")
	}
}
