package v3

import "testing"

func TestBankPublisherDoubleBuffer(t *testing.T) {
	p := NewBankPublisher()
	if p.ActiveBank() != 0 || p.Generation() != 1 {
		t.Fatalf("start bank=%d gen=%d", p.ActiveBank(), p.Generation())
	}
	inactive, ok := p.BeginCompile()
	if !ok || inactive != 1 {
		t.Fatalf("inactive=%d ok=%v", inactive, ok)
	}
	if _, ok := p.BeginCompile(); ok {
		t.Fatal("concurrent compile must fail")
	}
	gen, active := p.Commit()
	if gen != 2 || active != 1 {
		t.Fatalf("after commit gen=%d active=%d", gen, active)
	}
	// Old generation entries must not match new snapshot.
	bank, g := p.Snapshot()
	if bank != 1 || g != 2 {
		t.Fatalf("snapshot bank=%d gen=%d", bank, g)
	}
}

func TestBankPublisherAbort(t *testing.T) {
	p := NewBankPublisher()
	_, ok := p.BeginCompile()
	if !ok {
		t.Fatal("begin")
	}
	p.AbortCompile()
	if p.ActiveBank() != 0 || p.Generation() != 1 {
		t.Fatal("abort must not flip")
	}
	if _, ok := p.BeginCompile(); !ok {
		t.Fatal("should allow compile after abort")
	}
}

func TestBankPublisherSyncGeneration(t *testing.T) {
	p := NewBankPublisher()
	p.SyncGeneration(17)
	if got := p.Generation(); got != 17 {
		t.Fatalf("generation=%d want 17", got)
	}
	p.SyncGeneration(9)
	if got := p.Generation(); got != 17 {
		t.Fatalf("stale generation regressed publisher to %d", got)
	}
	if _, ok := p.BeginCompile(); !ok {
		t.Fatal("begin")
	}
	gen, bank := p.Commit()
	if gen != 18 || bank != 1 {
		t.Fatalf("after sync commit gen=%d bank=%d", gen, bank)
	}
}
