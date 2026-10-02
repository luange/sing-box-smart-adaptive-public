//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type stubDirectDialer struct {
	empty bool
}

func (d stubDirectDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}
func (d stubDirectDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}
func (d stubDirectDialer) IsEmpty() bool { return d.empty }

var _ N.Dialer = stubDirectDialer{}

func TestEvaluateVerdictLearn_Port53(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, adapter.InboundContext{},
		netip.MustParseAddrPort("1.1.1.1:53"))
	if ok || reason != verdictSkipPort53 {
		t.Fatalf("want skip port53, ok=%v reason=%d", ok, reason)
	}
}

func TestEvaluateVerdictLearn_SniffMetadataIPOnly(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute, allowWithSniff: false}
	meta := adapter.InboundContext{
		Protocol:     "tls",
		Domain:       "example.com",
		VerdictScope: adapter.RouteVerdictScopeDestinationIP,
	}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if !ok || reason != verdictSkipNone {
		t.Fatalf("IP-only scope must ignore sniff metadata, ok=%v reason=%d", ok, reason)
	}
	opts.allowWithSniff = true
	ok, reason = evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if !ok || reason != verdictSkipNone {
		t.Fatalf("allow_with_sniff should pass, ok=%v reason=%d", ok, reason)
	}
}

func TestEvaluateVerdictLearn_NonDirect(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{VerdictScope: adapter.RouteVerdictScopeDestinationIP}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: false}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipNonDirect {
		t.Fatalf("want skip non-direct, ok=%v reason=%d", ok, reason)
	}
}

func TestEvaluateVerdictLearn_ProcessUser(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{User: "alice", VerdictScope: adapter.RouteVerdictScopeDestinationIP}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipProcessUser {
		t.Fatalf("want skip process/user, ok=%v reason=%d", ok, reason)
	}
	meta = adapter.InboundContext{
		ProcessInfo:  &adapter.ConnectionOwner{ProcessID: 1},
		VerdictScope: adapter.RouteVerdictScopeDestinationIP,
	}
	ok, reason = evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipProcessUser {
		t.Fatalf("want skip process, ok=%v reason=%d", ok, reason)
	}
}

func TestEvaluateVerdictLearn_OK(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{VerdictScope: adapter.RouteVerdictScopeDestinationIP}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if !ok || reason != verdictSkipNone {
		t.Fatalf("want ok, ok=%v reason=%d", ok, reason)
	}
}

func TestEvaluateVerdictLearn_Off(t *testing.T) {
	opts := verdictLearnOptions{mode: "off"}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, adapter.InboundContext{},
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipDisabled {
		t.Fatalf("want disabled, ok=%v reason=%d", ok, reason)
	}
}

func TestVerdictInboundEligible(t *testing.T) {
	if !verdictInboundEligible(C.TypeEBPF) {
		t.Fatal("ebpf inbound must be eligible")
	}
	if !verdictInboundEligible(C.TypeMixed) {
		t.Fatal("mixed (shared-network) must be eligible at coordinator gate")
	}
	if verdictInboundEligible(C.TypeTun) || verdictInboundEligible(C.TypeSOCKS) || verdictInboundEligible("") {
		t.Fatal("tun/socks/empty must not poison verdict map")
	}
}

func TestMaybeLearnTCPCountsNonDirectAndAcceptsMixed(t *testing.T) {
	coord := &outboundCoordinator{
		verdictLearn: verdictLearnOptions{mode: "learn", ttl: time.Minute},
		// nil verdict backend: still counts invoke + non_direct before backend use
	}
	// non-direct leaves early after invoke
	coord.MaybeLearnTCP(context.Background(), stubDirectDialer{empty: false},
		adapter.InboundContext{InboundType: C.TypeEBPF},
		netip.MustParseAddrPort("1.2.3.4:443"))
	if coord.LearnInvoked() != 1 {
		t.Fatalf("invoked=%d", coord.LearnInvoked())
	}
	sr := coord.SkipReasonSnapshot()
	if sr[verdictSkipNonDirect] != 1 {
		t.Fatalf("non_direct skip=%d want 1", sr[verdictSkipNonDirect])
	}
	// mixed type must not be dropped at inbound-type gate
	coord.MaybeLearnTCP(context.Background(), stubDirectDialer{empty: false},
		adapter.InboundContext{InboundType: C.TypeMixed},
		netip.MustParseAddrPort("1.2.3.4:443"))
	if coord.LearnInvoked() != 2 {
		t.Fatalf("mixed invoke not counted: %d", coord.LearnInvoked())
	}
	// tun must not count as learn path
	before := coord.LearnInvoked()
	coord.MaybeLearnTCP(context.Background(), stubDirectDialer{empty: true},
		adapter.InboundContext{InboundType: C.TypeTun},
		netip.MustParseAddrPort("1.2.3.4:443"))
	if coord.LearnInvoked() != before {
		t.Fatal("tun must not enter learn path")
	}
}

func TestResolveLearnDestination_PreferMetadataIP(t *testing.T) {
	meta := adapter.InboundContext{
		Destination: M.ParseSocksaddrHostPort("10.20.20.3", 18080),
	}
	peer := netip.MustParseAddrPort("10.20.20.3:18080")
	got, reason := resolveLearnDestination(meta, peer)
	if got != peer || reason != verdictSkipNone {
		t.Fatalf("got %v reason=%d", got, reason)
	}
}

func TestResolveLearnDestination_AddrMismatch(t *testing.T) {
	meta := adapter.InboundContext{
		Destination: M.ParseSocksaddrHostPort("1.2.3.4", 443),
	}
	peer := netip.MustParseAddrPort("9.9.9.9:443")
	got, reason := resolveLearnDestination(meta, peer)
	if got.IsValid() || reason != verdictSkipAddrMismatch {
		t.Fatalf("want mismatch, got %v reason=%d", got, reason)
	}
}

func TestResolveLearnDestination_DestAddresses(t *testing.T) {
	meta := adapter.InboundContext{
		Destination:          M.ParseSocksaddrHostPort("example.com", 443),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	peer := netip.MustParseAddrPort("1.2.3.4:443")
	got, reason := resolveLearnDestination(meta, peer)
	if got != peer || reason != verdictSkipNone {
		t.Fatalf("got %v reason=%d", got, reason)
	}
	peer2 := netip.MustParseAddrPort("8.8.8.8:443")
	got, reason = resolveLearnDestination(meta, peer2)
	if got.IsValid() || reason != verdictSkipAddrMismatch {
		t.Fatalf("want mismatch, got %v reason=%d", got, reason)
	}
}

func TestResolveLearnDestination_NoMetadataDestReturnsNoDest(t *testing.T) {
	// N5: peer-only fallback removed.
	got, reason := resolveLearnDestination(adapter.InboundContext{}, netip.MustParseAddrPort("1.2.3.4:443"))
	if got.IsValid() || reason != verdictSkipNoDest {
		t.Fatalf("want noDest, got %v reason=%d", got, reason)
	}
}

func TestVerdictRouteInputsUnknownRefuses(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{MatchInputs: adapter.RouteMatchUnknown}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipSniff {
		t.Fatalf("unknown inputs must refuse, ok=%v reason=%d", ok, reason)
	}
}

func TestVerdictRouteInputsWithPortRefusesGlobalPromotion(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{MatchInputs: adapter.RouteMatchIP | adapter.RouteMatchPort}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipSniff {
		t.Fatalf("ip+port must refuse global promotion, ok=%v reason=%d", ok, reason)
	}
}

func TestVerdictRouteDestinationIPScopeAllows(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute}
	meta := adapter.InboundContext{
		MatchInputs:  adapter.RouteMatchIP | adapter.RouteMatchPort,
		VerdictScope: adapter.RouteVerdictScopeDestinationIP,
	}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if !ok || reason != verdictSkipNone {
		t.Fatalf("explicit destination-IP scope must allow, ok=%v reason=%d", ok, reason)
	}
}

func TestNormalizeOutboundOffloadVerdictMode(t *testing.T) {
	opts, _, err := normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Verdict.Mode != "off" {
		t.Fatalf("default mode=%s", opts.Verdict.Mode)
	}
	_, _, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Verdict: option.EBPFVerdictOptions{Mode: "bogus"},
	})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
	// W3: "dns" never implemented — reject with migration hint (not silent fallback).
	_, _, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Verdict: option.EBPFVerdictOptions{Mode: "dns"},
	})
	if err == nil {
		t.Fatal("expected dns mode error")
	}
	opts, _, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Verdict: option.EBPFVerdictOptions{
			Mode: "learn",
			TTL:  badoption.Duration(time.Minute),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Verdict.Mode != "learn" {
		t.Fatalf("mode=%s", opts.Verdict.Mode)
	}
}

func TestNormalizeOutboundOffloadHalfClosePassthrough(t *testing.T) {
	opts, _, err := normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Splice: option.EBPFSpliceOptions{
			Enabled:   true,
			HalfClose: "passthrough",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Splice.HalfClose != "passthrough" {
		t.Fatalf("half_close=%s", opts.Splice.HalfClose)
	}
}

func TestNormalizeOutboundOffloadCapacityClamp(t *testing.T) {
	// N3: max_pairs=8 must start (clamp to 16), not error.
	opts, warns, err := normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Splice: option.EBPFSpliceOptions{MaxPairs: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Splice.MaxPairs != outboundOffloadMinCapacity {
		t.Fatalf("max_pairs=%d want %d", opts.Splice.MaxPairs, outboundOffloadMinCapacity)
	}
	if len(warns) == 0 {
		t.Fatal("expected clamp warning")
	}
	opts, _, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Splice: option.EBPFSpliceOptions{MaxPairs: 0},
	})
	if err != nil || opts.Splice.MaxPairs != 0 {
		t.Fatalf("0 must stay 0 (default), got %d err=%v", opts.Splice.MaxPairs, err)
	}
	opts, warns, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Splice: option.EBPFSpliceOptions{MaxPairs: 999999},
	})
	if err != nil || opts.Splice.MaxPairs != outboundOffloadMaxPairsCap || len(warns) == 0 {
		t.Fatalf("clamp high max_pairs: %d warns=%v err=%v", opts.Splice.MaxPairs, warns, err)
	}
	opts, warns, err = normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Verdict: option.EBPFVerdictOptions{MaxEntries: 4},
	})
	if err != nil || opts.Verdict.MaxEntries != outboundOffloadMinCapacity || len(warns) == 0 {
		t.Fatalf("clamp low max_entries: %d warns=%v err=%v", opts.Verdict.MaxEntries, warns, err)
	}
}

func TestVerdictLearnOptionsFromDefaults(t *testing.T) {
	o := verdictLearnOptionsFrom(option.EBPFVerdictOptions{})
	if o.mode != "off" {
		t.Fatalf("mode=%s", o.mode)
	}
	if o.ttl != 5*time.Minute {
		t.Fatalf("ttl=%v", o.ttl)
	}
}

func TestVerdictLearnRefusesDomainRoutedDestination(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute, allowWithSniff: true}
	meta := adapter.InboundContext{
		MatchInputs: adapter.RouteMatchIP | adapter.RouteMatchDomain,
		Protocol:    "tls", // sniff on
	}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipSniff {
		t.Fatalf("domain+IP must refuse even with allow_with_sniff, ok=%v reason=%d", ok, reason)
	}
}

func TestAllowWithSniffDoesNotRelaxDomain(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute, allowWithSniff: true}
	meta := adapter.InboundContext{MatchInputs: adapter.RouteMatchDomain}
	ok, _ := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok {
		t.Fatal("allow_with_sniff must not open Domain MatchInputs")
	}
}

func TestVerdictLearnIPOnlyAllowsDespiteSniffMetadata(t *testing.T) {
	// Q3 P3: sniff filled Protocol but routing only evaluated IP/port → learn OK.
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute, allowWithSniff: false}
	meta := adapter.InboundContext{
		MatchInputs:  adapter.RouteMatchIP | adapter.RouteMatchPort,
		VerdictScope: adapter.RouteVerdictScopeDestinationIP,
		Protocol:     "tls",
		Client:       "chrome",
		SniffHost:    "example.com",
	}
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if !ok || reason != verdictSkipNone {
		t.Fatalf("IP-only MatchInputs must allow with sniff metadata, ok=%v reason=%d", ok, reason)
	}
}

func TestVerdictLearnUnknownScopeFailsClosedEvenWithLegacyMetadata(t *testing.T) {
	opts := verdictLearnOptions{mode: "learn", ttl: time.Minute, allowWithSniff: false}
	meta := adapter.InboundContext{Protocol: "tls"} // MatchInputs==0
	ok, reason := evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipSniff {
		t.Fatalf("unknown scope must refuse even with sniff metadata, ok=%v reason=%d", ok, reason)
	}
	opts.allowWithSniff = true
	ok, reason = evaluateVerdictLearn(opts, stubDirectDialer{empty: true}, meta,
		netip.MustParseAddrPort("1.2.3.4:443"))
	if ok || reason != verdictSkipSniff {
		t.Fatalf("allow_with_sniff must not manufacture route scope, ok=%v reason=%d", ok, reason)
	}
}

func TestNormalizeAllowWithSniffDeprecationWarning(t *testing.T) {
	_, warns, err := normalizeOutboundOffloadOptions(option.EBPFOutboundOffloadOptions{
		Verdict: option.EBPFVerdictOptions{Mode: "off", AllowWithSniff: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warns {
		if len(w) > 0 && (containsFold(w, "allow_with_sniff") || containsFold(w, "deprecated")) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected deprecation warning, got %v", warns)
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func TestResolveLearnDestination_MultiA(t *testing.T) {
	meta := adapter.InboundContext{
		Destination:          M.SocksaddrFrom(netip.MustParseAddr("1.2.3.4"), 443),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("1.2.3.5")},
	}
	peer := netip.MustParseAddrPort("1.2.3.5:443")
	got, reason := resolveLearnDestination(meta, peer)
	if reason != verdictSkipNone || got.Addr().String() != "1.2.3.4" || got.Port() != 443 {
		t.Fatalf("multi-A should learn original dest, got=%v reason=%d", got, reason)
	}
}
