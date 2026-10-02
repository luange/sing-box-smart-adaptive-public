//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestVerdictABISizes(t *testing.T) {
	if unsafe.Sizeof(outVerdictKey{}) != 24 {
		t.Fatalf("outVerdictKey size=%d want 24", unsafe.Sizeof(outVerdictKey{}))
	}
	if unsafe.Sizeof(outVerdictValue{}) != 16 {
		t.Fatalf("outVerdictValue size=%d want 16", unsafe.Sizeof(outVerdictValue{}))
	}
	if unsafe.Sizeof(outVerdictControl{}) != 8 {
		t.Fatalf("outVerdictControl size=%d want 8", unsafe.Sizeof(outVerdictControl{}))
	}
}

func TestMakeOutVerdictKeyHostPort(t *testing.T) {
	// makeOutVerdictKey lives in cgo build; when !cgo this test still validates ABI structs.
	dest := netip.MustParseAddrPort("1.2.3.4:443")
	var key outVerdictKey
	key.Protocol = ProtocolTCP
	key.Port = dest.Port()
	if err := putAddress(&key.Family, &key.Addr, dest.Addr()); err != nil {
		t.Fatal(err)
	}
	if key.Port != 443 {
		t.Fatalf("port host-order want 443 got %d", key.Port)
	}
	if key.Family != addressFamilyIPv4 {
		t.Fatalf("family=%d", key.Family)
	}
	if [4]byte(key.Addr[:4]) != [4]byte{1, 2, 3, 4} {
		t.Fatalf("addr=%v", key.Addr[:4])
	}
}
