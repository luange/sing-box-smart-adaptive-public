package group

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/dns/dnsmessage"
)

type smartUDPProbeFakeOutbound struct {
	*smartFakeOutbound
	probeCalls atomic.Int64
}

func newSmartUDPProbeFakeOutbound(tag string) *smartUDPProbeFakeOutbound {
	return &smartUDPProbeFakeOutbound{smartFakeOutbound: newSmartFakeOutboundNetworks(tag, []string{N.NetworkUDP}, nil)}
}

func (f *smartUDPProbeFakeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	f.probeCalls.Add(1)
	return &smartUDPProbePacketConn{}, nil
}

type smartUDPProbePacketConn struct {
	response []byte
}

func (c *smartUDPProbePacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	if len(c.response) == 0 {
		return 0, nil, errors.New("no DNS response")
	}
	count := copy(payload, c.response)
	return count, &net.UDPAddr{}, nil
}

func (c *smartUDPProbePacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return 0, err
	}
	question, err := parser.Question()
	if err != nil {
		return 0, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RCode: dnsmessage.RCodeSuccess})
	if err = builder.StartQuestions(); err != nil {
		return 0, err
	}
	if err = builder.Question(question); err != nil {
		return 0, err
	}
	c.response, err = builder.Finish()
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (*smartUDPProbePacketConn) Close() error                     { return nil }
func (*smartUDPProbePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*smartUDPProbePacketConn) SetDeadline(time.Time) error      { return nil }
func (*smartUDPProbePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*smartUDPProbePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestSmartTransportKeyKeepsAddressFamiliesSeparate(t *testing.T) {
	v4 := M.ParseSocksaddr("192.0.2.10:443")
	v6 := M.ParseSocksaddr("[2001:db8::10]:443")
	if got := smartTransportKey(N.NetworkTCP, v4); got != "tcp/ipv4" {
		t.Fatalf("IPv4 transport key = %q", got)
	}
	if got := smartTransportKey(N.NetworkTCP, v6); got != "tcp/ipv6" {
		t.Fatalf("IPv6 transport key = %q", got)
	}
	if got := smartTransportKey(N.NetworkTCP, M.ParseSocksaddr("example.com:443")); got != "tcp" {
		t.Fatalf("domain transport key = %q, want aggregate tcp", got)
	}
	if got := smartTransportKey(N.NetworkUDP+"6", M.Socksaddr{}); got != "udp/ipv6" {
		t.Fatalf("explicit UDPv6 transport key = %q", got)
	}
	if got := smartTransportBase("tcp/ipv6"); got != N.NetworkTCP {
		t.Fatalf("family transport base = %q", got)
	}
}

func TestSmartUDPRequiredResponsePackets(t *testing.T) {
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("dns.example:53")); got != 1 {
		t.Fatalf("DNS packet threshold = %d, want 1", got)
	}
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("video.example:443")); got != 3 {
		t.Fatalf("QUIC packet threshold = %d, want 3", got)
	}
	if got := smartUDPRequiredResponsePackets(M.ParseSocksaddr("stun.example:3478")); got != 3 {
		t.Fatalf("STUN packet threshold = %d, want 3", got)
	}
}

func TestSmartPolicyStateABIIsAdditive(t *testing.T) {
	if got := smartPolicyState("suspect"); got != 3 {
		t.Fatalf("suspect ABI state = %d, want 3", got)
	}
	if got := smartPolicyState("open"); got != 4 {
		t.Fatalf("open ABI state = %d, want 4", got)
	}
	if got := smartPolicyState("half_open"); got != 5 {
		t.Fatalf("half-open ABI state = %d, want additive state 5", got)
	}
}

func TestSmartAddressFamilyHealthIsIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	for range 3 {
		store.observeDial(now, "network", "", "node", "tcp/ipv4", false, time.Second)
	}
	store.observeDial(now, "network", "", "node", "tcp/ipv6", true, 30*time.Millisecond)
	v4 := store.estimate(now, "network", "", "node", "tcp/ipv4", 3)
	v6 := store.estimate(now, "network", "", "node", "tcp/ipv6", 3)
	if v4.State != "open" {
		t.Fatalf("IPv4 failure did not open only the IPv4 circuit: %+v", v4)
	}
	if v6.State == "open" || v6.Reliability <= v4.Reliability {
		t.Fatalf("IPv6 evidence was contaminated by IPv4 failures: v4=%+v v6=%+v", v4, v6)
	}
}

func TestSmartProbeBudgetPrefersUsedAndStaleCandidates(t *testing.T) {
	candidates := make([]adapter.Outbound, 8)
	for index := range candidates {
		candidates[index] = newSmartFakeOutbound("candidate-"+itoaSmall(index), nil)
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	for range 5 {
		smart.noteCandidateUse("candidate-7", now)
	}
	selected := smart.selectProbeCandidates(candidates, 4, smartProbeDashboard)
	if len(selected) != 4 {
		t.Fatalf("selected %d candidates, want 4", len(selected))
	}
	if selected[0].Tag() != "candidate-7" {
		t.Fatalf("most-used candidate was not prioritized: %s", selected[0].Tag())
	}
}

func TestSmartUseScoreDecaysWhenSelectingProbeCandidates(t *testing.T) {
	candidates := []adapter.Outbound{
		newSmartFakeOutbound("recent", nil),
		newSmartFakeOutbound("stale", nil),
		newSmartFakeOutbound("unused", nil),
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	smart.access.Lock()
	smart.useScores = map[string]smartUseScore{
		"recent": {Score: 1, LastUsed: now.Add(-5 * time.Minute)},
		"stale":  {Score: 100, LastUsed: now.Add(-smartUseScoreDecayWindow - time.Minute)},
	}
	smart.access.Unlock()
	selected := smart.selectProbeCandidates(candidates, 2, smartProbeDashboard)
	if selected[0].Tag() != "recent" {
		t.Fatalf("stale use score was not decayed before ranking: %q", selected[0].Tag())
	}
}

func TestSmartProbeBudgetDeduplicatesEndpointAliases(t *testing.T) {
	candidates := []adapter.Outbound{
		newSmartFakeOutbound("line-a", nil),
		newSmartFakeOutbound("line-a (2)", nil),
		newSmartFakeOutbound("line-b", nil),
		newSmartFakeOutbound("line-c", nil),
	}
	smart := newTestSmart(candidates...)
	setSmartCandidateIdentities(smart, map[string]string{
		"line-a":     "endpoint-a",
		"line-a (2)": "endpoint-a",
		"line-b":     "endpoint-b",
		"line-c":     "endpoint-c",
	})
	selected := smart.selectProbeCandidates(candidates, 3, smartProbeDashboard)
	if len(selected) != 3 {
		t.Fatalf("selected %d candidates, want 3 distinct endpoints", len(selected))
	}
	seen := make(map[string]struct{}, len(selected))
	for _, candidate := range selected {
		profileID := smart.candidateProfileID(candidate.Tag())
		if _, exists := seen[profileID]; exists {
			t.Fatalf("probe budget selected endpoint alias twice: %q", profileID)
		}
		seen[profileID] = struct{}{}
	}
}

func TestSmartBackgroundProbeRotatesBoundedColdCatalog(t *testing.T) {
	candidates := make([]adapter.Outbound, 20)
	for index := range candidates {
		candidates[index] = newSmartFakeOutbound("candidate-"+itoaSmall(index), nil)
	}
	smart := newTestSmart(candidates...)
	seenCold := make(map[string]struct{}, len(candidates))
	for range 5 {
		selected := smart.selectProbeCandidates(candidates, 1, smartProbeBackground)
		if len(selected) != defaultSmartColdProbeBudget {
			t.Fatalf("cold catalog selected %d candidates, want %d", len(selected), defaultSmartColdProbeBudget)
		}
		for _, candidate := range selected {
			seenCold[candidate.Tag()] = struct{}{}
		}
	}
	if len(seenCold) != len(candidates) {
		t.Fatalf("slow cold sweeps covered %d of %d candidates", len(seenCold), len(candidates))
	}
	now := time.Now()
	smart.access.Lock()
	if smart.probeLastAt == nil {
		smart.probeLastAt = make(map[string]time.Time)
	}
	if smart.useScores == nil {
		smart.useScores = make(map[string]smartUseScore)
	}
	for index, candidate := range candidates {
		metadata := smart.candidateMetadataByTag[candidate.Tag()]
		probeID := metadata.identity
		if probeID == "" {
			probeID = candidate.Tag()
		}
		profileID := metadata.profileID
		if profileID == "" {
			profileID = candidate.Tag()
		}
		smart.probeLastAt[probeID] = now.Add(-time.Duration(index) * time.Minute)
		if index < 8 {
			smart.useScores[profileID] = smartUseScore{Score: float64(20 - index), LastUsed: now}
		}
	}
	smart.access.Unlock()
	selected := smart.selectProbeCandidates(candidates, 16, smartProbeBackground)
	if len(selected) != 12 {
		t.Fatalf("warm regular test selected %d candidates, want 12", len(selected))
	}
	for index := 0; index < 6; index++ {
		if selected[index].Tag() != candidates[index].Tag() {
			t.Fatalf("most-used slot %d = %q, want %q", index, selected[index].Tag(), candidates[index].Tag())
		}
	}
}

func TestSmartBackgroundProbeFitsSlowCycleDeadline(t *testing.T) {
	candidates := make([]adapter.Outbound, 32)
	for index := range candidates {
		candidates[index] = newSmartFakeOutbound("slow-"+itoaSmall(index), nil)
	}
	smart := newTestSmart(candidates...)
	smart.probeTimeout = 8 * time.Second
	smart.probeCycleTimeout = 30 * time.Second
	smart.probeConcurrency = 2
	seen := make(map[string]struct{}, len(candidates))
	for range 6 {
		selected := smart.selectProbeCandidates(candidates, 16, smartProbeBackground)
		if len(selected) != 6 {
			t.Fatalf("slow cycle scheduled %d candidates, want capacity 6", len(selected))
		}
		for _, candidate := range selected {
			seen[candidate.Tag()] = struct{}{}
		}
	}
	if len(seen) != len(candidates) {
		t.Fatalf("rotating slow cycles covered %d of %d candidates", len(seen), len(candidates))
	}
}

func TestSmartUDPProbeBudgetRotatesWithoutStarvingUnknownCandidates(t *testing.T) {
	candidates := make([]adapter.Outbound, 6)
	identities := make(map[string]string, len(candidates))
	for index := range candidates {
		tag := "udp-node-" + itoaSmall(index)
		candidates[index] = newSmartFakeOutboundNetworks(tag, []string{N.NetworkUDP}, nil)
		identities[tag] = tag
	}
	smart := newTestSmart(candidates...)
	setSmartCandidateIdentities(smart, identities)

	seen := make(map[string]struct{}, len(candidates))
	for round := 0; round < 3; round++ {
		selected := smart.selectUDPProbeCandidates(candidates, 2)
		if len(selected) != 2 {
			t.Fatalf("round %d selected %d candidates, want 2", round, len(selected))
		}
		for _, candidate := range selected {
			if _, exists := seen[candidate.Tag()]; exists {
				t.Fatalf("UDP probe rotation repeated %q before covering the catalog", candidate.Tag())
			}
			seen[candidate.Tag()] = struct{}{}
			smart.noteUDPCandidateProbe(candidate.Tag(), time.Now())
		}
	}
	if len(seen) != len(candidates) {
		t.Fatalf("UDP probe rotation covered %d/%d candidates", len(seen), len(candidates))
	}
}

func TestSmartUDPProbeBudgetDeduplicatesEndpointAliases(t *testing.T) {
	candidates := []adapter.Outbound{
		newSmartFakeOutboundNetworks("line-a", []string{N.NetworkUDP}, nil),
		newSmartFakeOutboundNetworks("line-a (2)", []string{N.NetworkUDP}, nil),
		newSmartFakeOutboundNetworks("line-b", []string{N.NetworkUDP}, nil),
	}
	smart := newTestSmart(candidates...)
	setSmartCandidateIdentities(smart, map[string]string{
		"line-a":     "endpoint-a",
		"line-a (2)": "endpoint-a",
		"line-b":     "endpoint-b",
	})
	selected := smart.selectUDPProbeCandidates(candidates, 2)
	if len(selected) != 2 {
		t.Fatalf("selected %d candidates, want 2 distinct endpoints", len(selected))
	}
	seen := make(map[string]struct{}, len(selected))
	for _, candidate := range selected {
		profileID := smart.candidateProfileID(candidate.Tag())
		if _, exists := seen[profileID]; exists {
			t.Fatalf("UDP probe budget selected endpoint alias twice: %q", profileID)
		}
		seen[profileID] = struct{}{}
	}
}

func TestSmartUDPProbeBudgetIsUsedByProductionPath(t *testing.T) {
	fakes := make([]*smartUDPProbeFakeOutbound, 6)
	candidates := make([]adapter.Outbound, len(fakes))
	identities := make(map[string]string, len(fakes))
	for index := range fakes {
		tag := "udp-production-" + itoaSmall(index)
		fakes[index] = newSmartUDPProbeFakeOutbound(tag)
		candidates[index] = fakes[index]
		identities[tag] = tag
	}
	smart := newTestSmart(candidates...)
	setSmartCandidateIdentities(smart, identities)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 3 {
		smart.probeUDPWithBudget(ctx, smartProbeTransportCoverage, candidates, 2)
	}
	for index, fake := range fakes {
		if got := fake.probeCalls.Load(); got != 2 {
			// One catalog visit checks both UDP address families.
			t.Fatalf("candidate %d was probed %d times, want two family checks", index, got)
		}
	}
}

func TestSmartUseScoreTracksTCPButNotUDP(t *testing.T) {
	candidate := newSmartFakeOutboundNetworks("node", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	smart := newTestSmart(candidate)
	smart.markSelected(candidate, "network", "site", "site", "udp/ipv4", nil, 0, false)
	smart.access.RLock()
	if len(smart.useScores) != 0 {
		smart.access.RUnlock()
		t.Fatalf("UDP selection unexpectedly changed TCP use score: %+v", smart.useScores)
	}
	smart.access.RUnlock()
	smart.markSelected(candidate, "network", "site", "site", N.NetworkTCP, nil, 0, false)
	smart.access.RLock()
	defer smart.access.RUnlock()
	if usage := smart.useScores["node"]; usage.Score != 1 {
		t.Fatalf("TCP selection use score = %v, want 1", usage.Score)
	}
}
