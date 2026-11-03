//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
)

// TestProtectHitsZeroDefault documents Module C.1 counter baseline without a live Backend.
func TestProtectHitsZeroDefault(t *testing.T) {
	var b *Backend
	if b.ProtectHits() != 0 {
		t.Fatalf("nil backend ProtectHits=%d", b.ProtectHits())
	}
}

// TestVerdictStubStats ensures VerdictBackend nil-safe Stats/Export for tests.
func TestVerdictBackendNilSafe(t *testing.T) {
	var v *VerdictBackend
	_ = v.Stats()
	_ = v.Export()
	v.Skip()
	if v.Generation() != 0 {
		t.Fatal("nil generation")
	}
}
