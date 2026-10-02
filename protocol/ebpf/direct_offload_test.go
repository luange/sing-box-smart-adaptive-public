//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCollectDirectOffloadAddrsSkipsPrivate(t *testing.T) {
	meta := adapter.InboundContext{
		Destination: M.SocksaddrFromNetIP(netip.MustParseAddrPort("10.0.0.1:443")),
		DestinationAddresses: []netip.Addr{
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("1.1.1.1"), // dupe
		},
	}
	addrs := collectDirectOffloadAddrs(meta)
	if len(addrs) != 1 || addrs[0].String() != "1.1.1.1" {
		t.Fatalf("got %#v", addrs)
	}
}

func TestDirectOffloadStableLeafTypes(t *testing.T) {
	if !isStableDirectLeafType(C.TypeDirect) || !isStableDirectLeafType(C.TypeEBPF) {
		t.Fatal("direct/ebpf must be stable")
	}
	if isStableDirectLeafType(C.TypeTrojan) || isStableDirectLeafType("smart") {
		t.Fatal("proxy/smart must not be stable direct")
	}
}

func TestNoteRoutedDirectNilSafe(t *testing.T) {
	var i *Inbound
	i.NoteRoutedDirect(adapter.InboundContext{}, nil)
	i = &Inbound{}
	// No outbound / wrong inbound type must no-op without panic.
	i.NoteRoutedDirect(adapter.InboundContext{InboundType: C.TypeMixed}, nil)
	i.NoteRoutedDirect(adapter.InboundContext{InboundType: C.TypeEBPF}, nil)
}
