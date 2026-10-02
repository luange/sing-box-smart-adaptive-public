//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestVerdictExportRingWrap(t *testing.T) {
	v := &VerdictBackend{}
	// Write more than cap.
	const n = verdictExportCap + 44
	for i := 0; i < n; i++ {
		dest := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), uint16(i%65535+1))
		v.recordExport(outVerdictKey{Family: 2, Protocol: 6, Port: dest.Port()}, outVerdictValue{
			Verdict:    OutVerdictDIRECT,
			Generation: 1,
			ExpireNs:   uint64(i),
		}, dest)
	}
	out := v.Export()
	if len(out) != verdictExportCap {
		t.Fatalf("len=%d want %d", len(out), verdictExportCap)
	}
	// Oldest should be write index (n - cap) → ExpireNs = n-cap
	wantOldest := uint64(n - verdictExportCap)
	if out[0].ExpireNs != wantOldest {
		t.Fatalf("oldest ExpireNs=%d want %d", out[0].ExpireNs, wantOldest)
	}
	if out[len(out)-1].ExpireNs != uint64(n-1) {
		t.Fatalf("newest ExpireNs=%d want %d", out[len(out)-1].ExpireNs, n-1)
	}
	// Monotonic sequence in export order.
	for i := 1; i < len(out); i++ {
		if out[i].ExpireNs != out[i-1].ExpireNs+1 {
			t.Fatalf("not sequential at %d: %d then %d", i, out[i-1].ExpireNs, out[i].ExpireNs)
		}
	}
}
