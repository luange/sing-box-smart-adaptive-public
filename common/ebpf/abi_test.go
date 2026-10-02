package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestRedirectABI(t *testing.T) {
	if size := unsafe.Sizeof(redirectKey{}); size != 20 {
		t.Fatalf("unexpected redirect key size: %d", size)
	}
	// originalDestination doubles as the read buffer for the 32-byte
	// sb_shared_original_dst shared-network map value: its first 32 bytes
	// must stay layout-identical (family/protocol/port/addr/flags/reserved/
	// socket_cookie) so the trailing module-A UID fields are simply never
	// written by the shorter lookup. The SocketCookie offset assertion below
	// pins that prefix contract.
	if size := unsafe.Sizeof(originalDestination{}); size != 40 {
		t.Fatalf("unexpected original destination size: %d", size)
	}
	if offset := unsafe.Offsetof(redirectKey{}.RedirectAddr); offset != 4 {
		t.Fatalf("unexpected redirect address offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestination{}.Addr); offset != 4 {
		t.Fatalf("unexpected original address offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestination{}.Flags); offset != 20 {
		t.Fatalf("unexpected original flags offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestination{}.SocketCookie); offset != 24 {
		t.Fatalf("unexpected socket cookie offset: %d", offset)
	}
	if offset := unsafe.Offsetof(originalDestination{}.UID); offset != 32 {
		t.Fatalf("unexpected UID offset: %d", offset)
	}

	key, err := makeRedirectKey(
		ProtocolUDP,
		netip.MustParseAddrPort("[::ffff:127.2.3.4]:65532"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.RedirectPort != 65532 {
		t.Fatalf("unexpected redirect key header: %+v", key)
	}
	if [4]byte(key.RedirectAddr[:4]) != [4]byte{127, 2, 3, 4} {
		t.Fatalf("unexpected redirect address: %v", key.RedirectAddr)
	}
}

// Bypass CIDR LPM key sizes are covered in policy_abi_test.go (with_ebpf).
