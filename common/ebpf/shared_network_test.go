//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestSharedNetworkABI(t *testing.T) {
	if size := unsafe.Sizeof(sharedNetworkControl{}); size != 44 {
		t.Fatalf("unexpected shared-network control size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkRedirectKey{}); size != 40 {
		t.Fatalf("unexpected shared-network redirect key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkFlowKey{}); size != 40 {
		t.Fatalf("unexpected shared-network flow key size: %d", size)
	}
	if size := unsafe.Sizeof(sharedNetworkFlowValue{}); size != 16 {
		t.Fatalf("unexpected shared-network flow value size: %d", size)
	}
	if sharedNetworkFlagDNSHijack != 1<<4 {
		t.Fatalf("unexpected shared-network DNS flag: %#x", sharedNetworkFlagDNSHijack)
	}
	if sharedNetworkFlagDropUDP443 != 1<<5 {
		t.Fatalf("unexpected shared-network drop UDP/443 flag: %#x", sharedNetworkFlagDropUDP443)
	}
	if sharedNetworkFlagSocketAssign != 1<<6 {
		t.Fatalf("unexpected shared-network socket-assign flag: %#x", sharedNetworkFlagSocketAssign)
	}
	if sharedNetworkFlagFlowDirect != 1<<7 {
		t.Fatalf("unexpected shared-network flow-direct flag: %#x", sharedNetworkFlagFlowDirect)
	}
}

func TestNormalizeDNSObservationName(t *testing.T) {
	valid := map[string]string{
		"Example.COM.":            "example.com",
		"_acme-challenge.Example": "_acme-challenge.example",
		"service-name.example":    "service-name.example",
	}
	for input, want := range valid {
		if got := normalizeDNSObservationName(input); got != want {
			t.Fatalf("normalizeDNSObservationName(%q)=%q, want %q", input, got, want)
		}
	}
	invalid := []string{
		"",
		".",
		"-leading.example",
		"trailing-.example",
		"bad label.example",
		"bad/.example",
	}
	for _, input := range invalid {
		if got := normalizeDNSObservationName(input); got != "" {
			t.Fatalf("normalizeDNSObservationName(%q)=%q, want rejection", input, got)
		}
	}
}

func TestMakeSharedNetworkRedirectKey(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.43.10:53000")
	redirect := netip.MustParseAddrPort("127.200.1.2:65531")
	key, err := makeSharedNetworkRedirectKey(ProtocolUDP, client, redirect)
	if err != nil {
		t.Fatal(err)
	}
	if key.Family != addressFamilyIPv4 || key.Protocol != ProtocolUDP ||
		key.ClientPort != client.Port() || key.RedirectPort != redirect.Port() {
		t.Fatalf("unexpected redirect key: %+v", key)
	}
	if got := netip.AddrFrom4([4]byte(key.ClientAddr[:4])); got != client.Addr() {
		t.Fatalf("unexpected client address: %s", got)
	}
	if got := netip.AddrFrom4([4]byte(key.RedirectAddr[:4])); got != redirect.Addr() {
		t.Fatalf("unexpected redirect address: %s", got)
	}
	_, err = makeSharedNetworkRedirectKey(
		ProtocolUDP,
		client,
		netip.MustParseAddrPort("[fd53:696e:672d:626f::1]:65531"),
	)
	if err == nil {
		t.Fatal("expected mixed address families to be rejected")
	}
}

func TestMakeSharedNetworkFlowKeyCoversTCPUDPAndBothFamilies(t *testing.T) {
	cases := []struct {
		name                string
		protocol            uint8
		source, destination netip.AddrPort
		family              uint8
	}{
		{"tcp4", ProtocolTCP, netip.MustParseAddrPort("192.0.2.10:41000"), netip.MustParseAddrPort("198.51.100.10:443"), addressFamilyIPv4},
		{"udp4", ProtocolUDP, netip.MustParseAddrPort("192.0.2.10:41001"), netip.MustParseAddrPort("198.51.100.10:443"), addressFamilyIPv4},
		{"tcp6", ProtocolTCP, netip.MustParseAddrPort("[2001:db8::10]:41000"), netip.MustParseAddrPort("[2001:db8::20]:443"), addressFamilyIPv6},
		{"udp6", ProtocolUDP, netip.MustParseAddrPort("[2001:db8::10]:41001"), netip.MustParseAddrPort("[2001:db8::20]:443"), addressFamilyIPv6},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			key, err := makeSharedNetworkFlowKey(testCase.protocol, testCase.source, testCase.destination)
			if err != nil {
				t.Fatal(err)
			}
			if key.Family != testCase.family || key.Protocol != testCase.protocol ||
				key.ClientPort != testCase.source.Port() || key.OriginalPort != testCase.destination.Port() {
				t.Fatalf("unexpected flow key: %+v", key)
			}
		})
	}
	_, err := makeSharedNetworkFlowKey(ProtocolTCP, cases[0].source, cases[2].destination)
	if err == nil {
		t.Fatal("expected mixed address families to be rejected")
	}
}

func TestCompileSharedHostPrefixes(t *testing.T) {
	ipv4, ipv6 := compileSharedHostPrefixes([]netip.Addr{
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:192.0.2.3"),
	})
	wantIPv4 := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("192.0.2.2/32"),
		netip.MustParsePrefix("192.0.2.3/32"),
	}
	wantIPv6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}
	if len(ipv4) != len(wantIPv4) {
		t.Fatalf("unexpected IPv4 host prefixes: %v", ipv4)
	}
	for index := range wantIPv4 {
		if ipv4[index] != wantIPv4[index] {
			t.Fatalf("unexpected IPv4 host prefixes: %v", ipv4)
		}
	}
	if len(ipv6) != 1 || ipv6[0] != wantIPv6[0] {
		t.Fatalf("unexpected IPv6 host prefixes: %v", ipv6)
	}
}

func TestV3HostPrefixCapacity(t *testing.T) {
	addresses := make([]netip.Addr, v3HostMapCapacity+1)
	for index := range addresses {
		addresses[index] = netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)})
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if err := validateV3HostPrefixes(ipv4, ipv6); err == nil {
		t.Fatalf("accepted %d IPv4 host prefixes beyond map capacity", len(ipv4))
	}
}

func TestV3SharedRuntimeStatsPreserveV2Semantics(t *testing.T) {
	raw := make([]uint64, 29)
	raw[0] = 2  // static direct
	raw[1] = 3  // flow direct
	raw[2] = 5  // FakeIP direct
	raw[3] = 7  // DNS hint direct
	raw[5] = 11 // ordinary map-miss proxy handoff; not an error
	raw[7] = 13 // parse failure
	raw[8] = 17 // successful socket assignment
	raw[9] = 19 // socket assignment failure
	raw[10] = 23 // blocked packets
	raw[12] = 29 // redirect-map capacity reject
	raw[13] = 31 // security bypass
	raw[14] = 37 // established bypass

	got := v3SharedRuntimeStats(raw, 41)
	want := SharedNetworkRuntimeStats{
		IngressRedirects:     17,
		IngressBypass:        48,
		IngressDrops:         23,
		SocketAssignments:    17,
		SocketAssignFailures: 19,
		FlowUpdateFailures:   29,
		FallbackOpen:         48,
		EstablishedBypass:    37,
		ParseFailures:        13,
		PolicyBypass:         17,
		OriginalDstLost:      41,
	}
	if got != want {
		t.Fatalf("V3 stats mapping mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}
