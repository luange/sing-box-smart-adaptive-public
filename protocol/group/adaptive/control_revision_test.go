package adaptive

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdaptiveSelectionRevisionRejectsStaleWriter(t *testing.T) {
	pool := &AdaptivePool{control: new(ControlState), catalog: NewCatalogPort(), leases: NewSessionLeaseManager(8)}
	candidate := Candidate{ID: NodeID{12}, Handle: NodeHandle{NodeID: NodeID{12}, Slot: 1, Version: 1}, PrimaryTag: "node", Transport: []string{"tcp"}}
	installTestCatalog(pool.catalog, []Candidate{candidate}, newTestOutbound("node"))
	if !pool.SelectAdaptiveOutboundAt("node", 0) {
		t.Fatal("initial adaptive selection failed")
	}
	firstRevision := pool.AdaptiveSelectionRevision()
	if firstRevision == 0 || !pool.SelectAdaptiveOutboundAt("node", firstRevision) {
		t.Fatal("matching revision update failed")
	}
	if pool.SelectAdaptiveOutboundAt("node", firstRevision) {
		t.Fatal("stale adaptive writer was accepted")
	}
	if pool.AdaptiveSelectionRevision() != firstRevision+1 {
		t.Fatalf("control revision did not advance exactly once: %d", pool.AdaptiveSelectionRevision())
	}
}

func TestAdaptiveServiceOverrideUsesControlRevisionAndTTL(t *testing.T) {
	pool := &AdaptivePool{control: new(ControlState), resolver: NewServiceResolver(testIdentityHasher(t), ModeAdaptive)}
	if err := pool.SetAdaptiveServiceOverride("youtube", string(ModeBulk), time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if pool.AdaptiveSelectionRevision() != 1 || len(pool.AdaptiveServiceOverrides()) != 1 {
		t.Fatalf("service override was not committed: revision=%d overrides=%v", pool.AdaptiveSelectionRevision(), pool.AdaptiveServiceOverrides())
	}
	if err := pool.SetAdaptiveServiceOverride("youtube", string(ModeAdaptive), time.Minute, 0); err == nil {
		t.Fatal("stale service override writer was accepted")
	}
	if err := pool.ClearAdaptiveServiceOverride("youtube", 1); err != nil {
		t.Fatal(err)
	}
	if len(pool.AdaptiveServiceOverrides()) != 0 || pool.AdaptiveSelectionRevision() != 2 {
		t.Fatalf("service override was not cleared: revision=%d overrides=%v", pool.AdaptiveSelectionRevision(), pool.AdaptiveServiceOverrides())
	}
}

func TestAdaptiveSelectionRevisionZeroIsCompareAndSwap(t *testing.T) {
	pool := &AdaptivePool{control: new(ControlState), catalog: NewCatalogPort(), leases: NewSessionLeaseManager(8)}
	candidate := Candidate{ID: NodeID{13}, Handle: NodeHandle{NodeID: NodeID{13}, Slot: 1, Version: 1}, PrimaryTag: "node", Transport: []string{"tcp"}}
	installTestCatalog(pool.catalog, []Candidate{candidate}, newTestOutbound("node"))
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			if pool.SelectAdaptiveOutboundAt("node", 0) {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || pool.AdaptiveSelectionRevision() != 1 {
		t.Fatalf("revision zero was not CAS-protected: successes=%d revision=%d", successes.Load(), pool.AdaptiveSelectionRevision())
	}
}
