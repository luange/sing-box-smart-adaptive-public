package v3

import "sync/atomic"

// BankPublisher implements double-buffer policy publish (design §7.1).
// Never mutates the active bank in place.
type BankPublisher struct {
	active     atomic.Uint32 // 0 or 1
	generation atomic.Uint32
	compiling  atomic.Uint32 // 1 while inactive bank is being filled
}

// NewBankPublisher starts at bank 0, generation 1.
func NewBankPublisher() *BankPublisher {
	p := &BankPublisher{}
	p.generation.Store(1)
	return p
}

// ActiveBank returns the currently live bank index.
func (p *BankPublisher) ActiveBank() uint32 {
	if p == nil {
		return 0
	}
	return p.active.Load()
}

// Generation returns the live policy generation.
func (p *BankPublisher) Generation() uint32 {
	if p == nil {
		return 0
	}
	return p.generation.Load()
}

// InactiveBank is the bank currently safe to fill.
func (p *BankPublisher) InactiveBank() uint32 {
	return 1 - p.ActiveBank()
}

// BeginCompile marks inactive bank fill. Concurrent BeginCompile fails.
func (p *BankPublisher) BeginCompile() (inactive uint32, ok bool) {
	if p == nil {
		return 0, false
	}
	if !p.compiling.CompareAndSwap(0, 1) {
		return 0, false
	}
	return p.InactiveBank(), true
}

// AbortCompile releases the compile lock without flipping banks.
func (p *BankPublisher) AbortCompile() {
	if p == nil {
		return
	}
	p.compiling.Store(0)
}

// SyncGeneration advances the in-process publisher to a generation committed
// by another publisher (for example the live kernel sink).  Stale snapshots
// are ignored: moving backwards could make an old flow/DNS generation valid
// again after a reload. The Lifecycle serializes this operation with all
// MemoryBackend publishes, so the compare-and-swap cannot invalidate an
// in-flight bank transaction.
func (p *BankPublisher) SyncGeneration(generation uint32) {
	if p == nil || generation == 0 {
		return
	}
	for {
		current := p.generation.Load()
		if current != 0 && generation < current {
			return
		}
		if p.generation.CompareAndSwap(current, generation) {
			return
		}
	}
}

// Commit flips active_bank and bumps generation atomically from the caller's
// perspective: generation is incremented first is wrong — we set generation then
// bank so old flow entries (keyed by old gen) miss immediately after bank flip.
// Order: store new generation, then active bank, then clear compiling.
func (p *BankPublisher) Commit() (generation uint32, active uint32) {
	if p == nil {
		return 0, 0
	}
	newGen := p.generation.Load() + 1
	if newGen == 0 {
		newGen = 1
	}
	newActive := p.InactiveBank()
	p.generation.Store(newGen)
	p.active.Store(newActive)
	p.compiling.Store(0)
	return newGen, newActive
}

// Snapshot is a stable view for writing Control.
func (p *BankPublisher) Snapshot() (bank uint32, generation uint32) {
	if p == nil {
		return 0, 0
	}
	// Read generation then bank; worst case a concurrent Commit makes us write
	// an older bank with newer gen once — next packet still fails gen check on flows.
	g := p.generation.Load()
	b := p.active.Load()
	return b, g
}
