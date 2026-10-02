//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"unsafe"
)

func TestSpliceABI(t *testing.T) {
	if unsafe.Sizeof(spliceKey{}) != spliceKeySize {
		t.Fatalf("spliceKey size=%d want %d", unsafe.Sizeof(spliceKey{}), spliceKeySize)
	}
	if unsafe.Sizeof(spliceControl{}) != spliceControlSize {
		t.Fatalf("spliceControl size=%d want %d", unsafe.Sizeof(spliceControl{}), spliceControlSize)
	}
	// Q10: kernel enum slots 0..5 + COUNT == 6 (pairs with native/splice.bpf.c).
	if spliceStatCount != 6 {
		t.Fatalf("spliceStatCount=%d want 6", spliceStatCount)
	}
}

func TestOutVerdictABI(t *testing.T) {
	if unsafe.Sizeof(outVerdictKey{}) != outVerdictKeySize {
		t.Fatalf("outVerdictKey size=%d want %d", unsafe.Sizeof(outVerdictKey{}), outVerdictKeySize)
	}
	if unsafe.Sizeof(outVerdictValue{}) != outVerdictValueSize {
		t.Fatalf("outVerdictValue size=%d want %d", unsafe.Sizeof(outVerdictValue{}), outVerdictValueSize)
	}
	if unsafe.Sizeof(outVerdictControl{}) != outVerdictControlSize {
		t.Fatalf("outVerdictControl size=%d want %d", unsafe.Sizeof(outVerdictControl{}), outVerdictControlSize)
	}
}

// TestSpliceStatIndexValues pins the Go splice stat indices to the enum
// order in native/splice.bpf.c and native/singbox_ebpf_out.h. The indices
// are duplicated in three places; reordering one without the others would
// keep every size test green while pointing userspace counters at the wrong
// kernel slots.
func TestSpliceStatIndexValues(t *testing.T) {
	expected := map[string]int{
		"PairsCreated":     0,
		"PairsReleased":    1,
		"Redirects":        2,
		"RedirectFailures": 3,
		"PeerMisses":       4,
		"Passthrough":      5,
	}
	actual := map[string]int{
		"PairsCreated":     spliceStatPairsCreated,
		"PairsReleased":    spliceStatPairsReleased,
		"Redirects":        spliceStatRedirects,
		"RedirectFailures": spliceStatRedirectFailures,
		"PeerMisses":       spliceStatPeerMisses,
		"Passthrough":      spliceStatPassthrough,
	}
	for name, want := range expected {
		if actual[name] != want {
			t.Fatalf("spliceStat%s = %d, kernel enum expects %d (sync native/splice.bpf.c, singbox_ebpf_out.h, outbound_abi.go)", name, actual[name], want)
		}
	}
	if spliceStatCount != 6 {
		t.Fatalf("spliceStatCount = %d, kernel expects 6", spliceStatCount)
	}
}
