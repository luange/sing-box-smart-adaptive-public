package v3

import (
	"net/netip"
	"testing"
	"time"
)

func TestCanonicalPrefixNormalizesMappedIPv4(t *testing.T) {
	mapped := netip.PrefixFrom(netip.MustParseAddr("::ffff:203.0.113.9"), 128)
	got, err := CanonicalPrefix(mapped)
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParsePrefix("203.0.113.9/32")
	if got != want {
		t.Fatalf("canonical prefix=%v want %v", got, want)
	}
	key, err := PrefixToLPM4(mapped)
	if err != nil {
		t.Fatal(err)
	}
	if key.PrefixLen != 32 || key.Addr != [4]byte{203, 0, 113, 9} {
		t.Fatalf("mapped prefix produced wrong lpm key: %+v", key)
	}
}

func TestCanonicalPrefixRejectsPartialMappedNetwork(t *testing.T) {
	if _, err := CanonicalPrefix(netip.MustParsePrefix("::ffff:203.0.113.0/95")); err == nil {
		t.Fatal("partial IPv4-mapped network must not become a policy key")
	}
}

func TestPublishStaticAtomicAndGeneration(t *testing.T) {
	b := NewMemoryBackend()
	prefix := netip.MustParsePrefix("1.1.1.1/32")
	compiled, rejected, err := CompileStatic([]CompileInput{{
		Destination: prefix,
		Verdict:     VerdictDirect,
		Kind:        RuleKindStatic,
		PolicyID:    7,
	}}, 1)
	if err != nil || len(rejected) != 0 || len(compiled) != 1 {
		t.Fatalf("compile err=%v rejected=%d compiled=%d", err, len(rejected), len(compiled))
	}
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.Control.PolicyGeneration != 2 || b.Control.ActiveBank != 1 {
		t.Fatalf("control %+v", b.Control)
	}
	v := b.LookupStatic(netip.MustParseAddr("1.1.1.1"), ProtocolTCP, 443)
	if v == nil || v.Verdict != uint8(VerdictDirect) || v.Generation != 2 {
		t.Fatalf("lookup %+v", v)
	}
	// Second publish flips bank again; old bank entries not consulted.
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.Control.PolicyGeneration != 3 || b.Control.ActiveBank != 0 {
		t.Fatalf("second %+v", b.Control)
	}
}

func TestCompileRejectsDomainAndGroup(t *testing.T) {
	_, rejected, err := CompileStatic([]CompileInput{
		{Destination: netip.MustParsePrefix("1.1.1.1/32"), Verdict: VerdictDirect, DomainBound: true},
		{Destination: netip.MustParsePrefix("2.2.2.2/32"), Verdict: VerdictDirect, LeafIsGroup: true},
		{Destination: netip.MustParsePrefix("3.3.3.3/32"), Verdict: VerdictDirect, UsesSniff: true},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 3 {
		t.Fatalf("rejected=%d", len(rejected))
	}
}

func TestFlowLearnBareDirectOnly(t *testing.T) {
	b := NewMemoryBackend()
	client := netip.MustParseAddrPort("10.0.0.2:12345")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: false,
	}, 100)
	if err == nil {
		t.Fatal("expected reject non-bare direct")
	}
	if err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, 100); err != nil {
		t.Fatal(err)
	}
	// generation miss after reload
	_ = b.PublishStatic(nil)
	key := FlowKey{
		Family: AFInet, Protocol: ProtocolTCP, Direction: 0,
		SPort: 12345, DPort: 443,
		SAddr: [16]byte{10, 0, 0, 2}, DAddr: [16]byte{8, 8, 8, 8},
	}
	if b.LookupFlow(key) != nil {
		t.Fatal("old generation flow must miss after policy commit")
	}
}

func TestFlowModelReleasedOnGenerationChange(t *testing.T) {
	b := NewMemoryBackend()
	client := netip.MustParseAddrPort("10.0.0.2:12345")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, 100); err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 2 {
		t.Fatalf("expected bidirectional flow entries, got %d", len(b.Flows))
	}
	if err := b.PublishStatic(nil); err != nil {
		t.Fatal(err)
	}
	if len(b.Flows) != 0 {
		t.Fatalf("stale flow entries retained after generation change: %d", len(b.Flows))
	}
}

func TestGenerationInvalidatesAllLearnedModelRows(t *testing.T) {
	b := NewMemoryBackend()
	if err := b.MergeDynamicDirect(netip.MustParsePrefix("203.0.113.9/32"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := b.PublishMACPolicies([]MACPolicyEntry{{Key: MACKey{Addr: [6]byte{1, 2, 3, 4, 5, 6}}}}); err != nil {
		t.Fatal(err)
	}
	if len(b.dynamicDirects4) != 1 || len(b.MACPolicies) != 1 {
		t.Fatalf("setup rows missing: dynamic=%d mac=%d", len(b.dynamicDirects4), len(b.MACPolicies))
	}
	b.InvalidateGeneration(b.Control.PolicyGeneration + 1)
	if len(b.dynamicDirects4) != 0 || len(b.dynamicDirects6) != 0 || len(b.MACPolicies) != 0 {
		t.Fatalf("stale learned rows survived generation change: dynamic4=%d dynamic6=%d mac=%d", len(b.dynamicDirects4), len(b.dynamicDirects6), len(b.MACPolicies))
	}
}

func TestPublishMACPoliciesCountsUniqueNormalizedKeys(t *testing.T) {
	b := NewMemoryBackend()
	key := MACKey{Addr: [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}
	entries := make([]MACPolicyEntry, MaxSourcePolicies+1)
	for i := range entries {
		entries[i] = MACPolicyEntry{Key: key, Value: MACPolicyValue{Verdict: uint8(VerdictDirect)}}
	}
	if err := b.PublishMACPolicies(entries); err != nil {
		t.Fatalf("duplicate keys should consume one map slot: %v", err)
	}
	if len(b.MACPolicies) != 1 {
		t.Fatalf("unique MAC snapshot size=%d want 1", len(b.MACPolicies))
	}
}

func TestFlowModelBounded(t *testing.T) {
	b := NewMemoryBackend()
	for i := 0; i < maxMemoryFlowEntries/2+64; i++ {
		client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), uint16(1000+i))
		dest := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, byte(i)}), 443)
		if err := b.PublishFlow(FlowPublishRequest{
			Client: client, Destination: dest, Protocol: ProtocolTCP,
			Verdict: VerdictDirect, LeafIsBareDirect: true,
		}, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.Flows) > maxMemoryFlowEntries {
		t.Fatalf("flow model exceeded bound: got=%d max=%d", len(b.Flows), maxMemoryFlowEntries)
	}
}

func TestFlowRevokeOnFailure(t *testing.T) {
	b := NewMemoryBackend()
	client := netip.MustParseAddrPort("10.0.0.2:12345")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := b.PublishFlow(FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ProtocolTCP,
		Verdict: VerdictDirect, LeafIsBareDirect: true,
	}, 100); err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeFlow(client, dest, ProtocolTCP); err != nil {
		t.Fatal(err)
	}
	key := FlowKey{
		Family: AFInet, Protocol: ProtocolTCP, Direction: 0,
		SPort: 12345, DPort: 443,
		SAddr: [16]byte{10, 0, 0, 2}, DAddr: [16]byte{8, 8, 8, 8},
	}
	if b.LookupFlow(key) != nil {
		t.Fatal("revoked")
	}
}

func TestIPv4IPv6FlowSymmetric(t *testing.T) {
	b := NewMemoryBackend()
	c4 := netip.MustParseAddrPort("10.0.0.2:1000")
	d4 := netip.MustParseAddrPort("1.1.1.1:443")
	c6 := netip.MustParseAddrPort("[fd00::2]:1000")
	d6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	for _, req := range []FlowPublishRequest{
		{Client: c4, Destination: d4, Protocol: ProtocolUDP, Verdict: VerdictDirect, LeafIsBareDirect: true, TimeoutClass: "quic"},
		{Client: c6, Destination: d6, Protocol: ProtocolUDP, Verdict: VerdictDirect, LeafIsBareDirect: true, TimeoutClass: "quic"},
	} {
		if err := b.PublishFlow(req, 1); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLookupStaticIPv6HonorsProtocolAndPort(t *testing.T) {
	b := NewMemoryBackend()
	prefix := netip.MustParsePrefix("2001:db8::1/128")
	compiled, rejected, err := CompileStatic([]CompileInput{{
		Destination: prefix,
		Protocol:    ProtocolTCP,
		DPortMin:    443,
		DPortMax:    443,
		Verdict:     VerdictDirect,
		Kind:        RuleKindStatic,
	}}, 1)
	if err != nil || len(rejected) != 0 || len(compiled) != 1 {
		t.Fatalf("compile err=%v rejected=%d compiled=%d", err, len(rejected), len(compiled))
	}
	if err := b.PublishStatic(compiled); err != nil {
		t.Fatal(err)
	}
	if b.LookupStatic(prefix.Addr(), ProtocolUDP, 443) != nil {
		t.Fatal("IPv6 static rule matched the wrong protocol")
	}
	if b.LookupStatic(prefix.Addr(), ProtocolTCP, 80) != nil {
		t.Fatal("IPv6 static rule matched the wrong destination port")
	}
	if b.LookupStatic(prefix.Addr(), ProtocolTCP, 443) == nil {
		t.Fatal("IPv6 static rule did not match its protocol and port")
	}
}

func TestMergeDynamicDirectIsSeparateAndBounded(t *testing.T) {
	b := NewMemoryBackend()
	prefix := netip.MustParsePrefix("203.0.113.9/32")
	if err := b.MergeDynamicDirect(prefix, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := b.LookupStatic(prefix.Addr(), ProtocolTCP, 443); got != nil {
		t.Fatalf("dynamic policy leaked into static bank: %+v", got)
	}
	if got := b.LookupDynamicDirect(prefix.Addr(), ProtocolTCP, 443); got == nil || got.Generation != b.Control.PolicyGeneration {
		t.Fatalf("dynamic policy=%+v control=%+v", got, b.Control)
	}
	if err := b.MergeDynamicDirect(prefix, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := len(b.dynamicDirects4); got != 1 {
		t.Fatalf("duplicate merge grew IPv4 dynamic map: %d", got)
	}
	if got := len(b.dynamicDirects6); got != 0 {
		t.Fatalf("unexpected IPv6 dynamic rows: %d", got)
	}
}

func TestMergeDynamicDirectUsesIndependentFamilyCapacities(t *testing.T) {
	b := NewMemoryBackend()
	for i := 0; i < DefaultDynamicDirect; i++ {
		v4 := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		if err := b.MergeDynamicDirect(addrPrefix(v4), time.Minute); err != nil {
			t.Fatalf("IPv4 merge %d: %v", i, err)
		}
	}
	if err := b.MergeDynamicDirect(addrPrefix(netip.MustParseAddr("2001:db8::1")), time.Minute); err != nil {
		t.Fatalf("IPv6 capacity should be independent of IPv4: %v", err)
	}
	if len(b.dynamicDirects4) != DefaultDynamicDirect || len(b.dynamicDirects6) != 1 {
		t.Fatalf("unexpected family ledgers: v4=%d v6=%d", len(b.dynamicDirects4), len(b.dynamicDirects6))
	}
}

func TestPublishStaticRejectsPolicyCapacityWithoutCommit(t *testing.T) {
	b := NewMemoryBackend()
	policies := make([]CompiledPolicy, DefaultPolicyLPM+1)
	for i := range policies {
		n := uint32(i)
		addr := netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)})
		policies[i] = CompiledPolicy{
			Prefix: addrPrefix(addr),
			Value: PolicyValue{
				Verdict: uint8(VerdictDirect),
			},
		}
	}
	if err := b.PublishStatic(policies); err == nil {
		t.Fatal("oversized static policy unexpectedly committed")
	}
	if b.Publisher.Generation() != 1 || b.Control.PolicyGeneration != 1 || b.Control.ActiveBank != 0 {
		t.Fatalf("failed publish changed control state: control=%+v publisher=%d", b.Control, b.Publisher.Generation())
	}
	if len(b.Policy4[1]) != 0 || len(b.Policy6[1]) != 0 {
		t.Fatalf("failed publish left inactive entries: v4=%d v6=%d", len(b.Policy4[1]), len(b.Policy6[1]))
	}
}

func addrPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, 32).Masked()
}
