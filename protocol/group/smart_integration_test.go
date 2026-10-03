package group

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/nodefilter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/group/trafficfamily"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

func TestNormalizeSmartProbeURLAvoidsRecursiveDNS(t *testing.T) {
	if got := normalizeSmartProbeURL(""); got != defaultSmartProbeURL {
		t.Fatalf("empty probe URL = %q, want %q", got, defaultSmartProbeURL)
	}
	if got := normalizeSmartProbeURL("https://www.gstatic.com/generate_204"); got != defaultSmartProbeURL {
		t.Fatalf("legacy gstatic probe URL = %q, want %q", got, defaultSmartProbeURL)
	}
	const custom = "https://probe.example.invalid/health"
	if got := normalizeSmartProbeURL(custom); got != custom {
		t.Fatalf("custom probe URL = %q, want %q", got, custom)
	}
}

func TestSmartProbeFallbackSelection(t *testing.T) {
	if got, err := normalizeSmartProbeFallbackURL(defaultSmartProbeURL, nil); err != nil || got != defaultSmartProbeFallbackURL {
		t.Fatalf("default fallback = %q, %v", got, err)
	}
	if got, err := normalizeSmartProbeFallbackURL("https://1.1.1.1/cdn-cgi/trace", nil); err != nil || got != defaultSmartProbeURL {
		t.Fatalf("explicit primary fallback = %q, %v", got, err)
	}
	empty := ""
	if got, err := normalizeSmartProbeFallbackURL(defaultSmartProbeURL, &empty); err != nil || got != "" {
		t.Fatalf("explicit single-target mode = %q, %v", got, err)
	}
	invalid := "http://example.com/health"
	if _, err := normalizeSmartProbeFallbackURL(defaultSmartProbeURL, &invalid); err == nil {
		t.Fatal("non-HTTPS fallback was accepted")
	}
}

func TestSmartProbeProfileSeparatesFallbackContracts(t *testing.T) {
	first := &Smart{probeURL: "https://primary.example/health", probeFallbackURL: "https://backup-a.example/health"}
	second := &Smart{probeURL: first.probeURL, probeFallbackURL: "https://backup-b.example/health"}
	firstKey := nodeProfileKey("same-credential", first.probeProfileLink(N.NetworkTCP), 0)
	secondKey := nodeProfileKey("same-credential", second.probeProfileLink(N.NetworkTCP), 0)
	if firstKey == secondKey {
		t.Fatal("distinct fallback targets reused one authenticated probe result")
	}
}

func TestSmartProbeFallbackRetainsDeadlineAndReportsFailures(t *testing.T) {
	smart := &Smart{probeURL: "https://primary.example/health", probeFallbackURL: "https://fallback.example/health", probeTimeout: 400 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	started := time.Now()
	delay, err := smart.probeTargetsWithFallback(ctx, func(attemptCtx context.Context, target string) (uint16, error) {
		if target == smart.probeURL {
			<-attemptCtx.Done()
			return 0, attemptCtx.Err()
		}
		return 25, nil
	})
	if err != nil || delay != 25 || time.Since(started) >= 400*time.Millisecond {
		t.Fatalf("fallback did not receive reserved time: delay=%d err=%v elapsed=%v", delay, err, time.Since(started))
	}
	status := smart.probeTargetSnapshot()
	if status[0].TargetHost != "primary.example" || status[0].Timeouts != 1 || status[0].Failures != 1 ||
		status[1].TargetHost != "fallback.example" || status[1].Successes != 1 {
		t.Fatalf("probe target evidence lost: %+v", status)
	}
	smart.noteProbeTargetResult(0, smart.probeURL, errors.New("unexpected HTTP response status: 403"))
	if got := smart.probeTargetSnapshot()[0].HTTPFailures; got != 1 {
		t.Fatalf("HTTP probe rejection class = %d, want 1", got)
	}
}

func TestSmartStatusExposesProbeTargetsWithoutFullURLs(t *testing.T) {
	smart := newTestSmart()
	smart.probeURL = "https://primary.example/health?token=private"
	smart.probeFallbackURL = "https://fallback.example/generate_204"
	smart.noteProbeTargetResult(0, smart.probeURL, errors.New("unexpected HTTP response status: 403"))
	smart.noteProbeTargetResult(1, smart.probeFallbackURL, nil)
	status := smart.SmartStatus()
	if len(status.ProbeTargets) != 2 || status.ProbeTargets[0].TargetHost != "primary.example" ||
		status.ProbeTargets[0].HTTPFailures != 1 || status.ProbeTargets[1].Successes != 1 {
		t.Fatalf("probe target status missing: %+v", status.ProbeTargets)
	}
	if strings.Contains(fmt.Sprint(status.ProbeTargets), "private") {
		t.Fatal("probe status leaked the configured URL query")
	}
}

type smartFakeOutbound struct {
	outbound.Adapter
	dialError error
	dialDelay time.Duration
	dials     atomic.Int64
	peers     chan net.Conn
}

type smartFakeGroup struct {
	*smartFakeOutbound
	children []string
}

func (g *smartFakeGroup) Now() string {
	if len(g.children) == 0 {
		return ""
	}
	return g.children[0]
}

func (g *smartFakeGroup) All() []string {
	return append([]string(nil), g.children...)
}

type smartFakeOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

type smartFakeProvider struct {
	adapter.Provider
	tag       string
	outbounds []adapter.Outbound
	callbacks list.List[adapter.ProviderUpdateCallback]
}

func (p *smartFakeProvider) Tag() string { return p.tag }

func (p *smartFakeProvider) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), p.outbounds...)
}

func (p *smartFakeProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return p.callbacks.PushBack(callback)
}

func (p *smartFakeProvider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}

func (p *smartFakeProvider) update(outbounds ...adapter.Outbound) error {
	p.outbounds = append([]adapter.Outbound(nil), outbounds...)
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		if err := element.Value(p.tag); err != nil {
			return err
		}
	}
	return nil
}

func (p *smartFakeProvider) callbackCount() int {
	return p.callbacks.Len()
}

type smartFakeProviderManager struct {
	adapter.ProviderManager
	provider adapter.Provider
}

func (m *smartFakeProviderManager) Providers() []adapter.Provider {
	return []adapter.Provider{m.provider}
}

func (m *smartFakeProviderManager) Get(tag string) (adapter.Provider, bool) {
	if m.provider != nil && m.provider.Tag() == tag {
		return m.provider, true
	}
	return nil, false
}

func (m *smartFakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	candidate, loaded := m.byTag[tag]
	return candidate, loaded
}

func newSmartFakeOutbound(tag string, dialError error) *smartFakeOutbound {
	return newSmartFakeOutboundNetworks(tag, []string{N.NetworkTCP}, dialError)
}

func newSmartFakeOutboundNetworks(tag string, networks []string, dialError error) *smartFakeOutbound {
	return &smartFakeOutbound{
		Adapter:   outbound.NewAdapter(C.TypeDirect, tag, networks, nil),
		dialError: dialError,
		peers:     make(chan net.Conn, 8),
	}
}

func (f *smartFakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	f.dials.Add(1)
	if f.dialDelay > 0 {
		timer := time.NewTimer(f.dialDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if f.dialError != nil {
		return nil, f.dialError
	}
	local, peer := net.Pipe()
	f.peers <- peer
	return local, nil
}

func (f *smartFakeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func newTestSmart(candidates ...adapter.Outbound) *Smart {
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	for _, candidate := range candidates {
		candidateByTag[candidate.Tag()] = candidate
	}
	smart := &Smart{
		Adapter:              outbound.NewAdapter(C.TypeSmart, "smart-test", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:                  context.Background(),
		candidates:           candidates,
		candidateByTag:       candidateByTag,
		control:              &smartControlState{},
		lastSelected:         make(map[string]string),
		affinity:             make(map[string]smartAffinity),
		switchChallenges:     make(map[string]smartSwitchChallenge),
		performanceCooldown:  make(map[string]time.Time),
		halfOpen:             make(map[string]struct{}),
		store:                newSmartStore(time.Hour, 1, time.Minute),
		maxAttempts:          3,
		attemptTimeout:       time.Second,
		probeTimeout:         100 * time.Millisecond,
		siteStickiness:       time.Minute,
		switchConfirm:        30 * time.Second,
		switchConfirmSamples: 3,
		switchCooldown:       10 * time.Minute,
		switchMargin:         0.10,
		exploration:          0,
		minSamples:           3,
		maxHistoryEntries:    50000,
		interruptGroup:       interruptGroupForTest(),
		families:             trafficfamily.NewResolver(),
	}
	// Keep integration tests on the same policy owner as production builds when
	// the smart_zig CI tag is present. Untagged tests intentionally exercise the
	// host-only path without constructing a production Smart outbound; packaged
	// builds use smart_zig,production_smart.
	smart.policyBackend = newSmartPolicyBackend(smartPolicyBackendConfig{
		Exploration:         smart.exploration,
		SwitchMargin:        smart.switchMargin,
		SwitchConfirm:       smart.switchConfirmSamples,
		SwitchConfirmWindow: smart.switchConfirm.Milliseconds(),
		SwitchCooldown:      smart.switchCooldown.Milliseconds(),
		MinSamples:          smart.minSamples,
	})
	return smart
}

func TestSmartActiveProbeFailureDoesNotOpenDataPlaneBreaker(t *testing.T) {
	candidate := newSmartFakeOutbound("candidate-a", nil)
	smart := newTestSmart(candidate)
	now := time.Now()
	for index := 0; index < 8; index++ {
		smart.observeProbeResult(false, now.Add(time.Duration(index)*time.Second), "network", "", candidate.Tag(), N.NetworkTCP, false, time.Second)
	}
	if smart.store.candidateDead("network", "", candidate.Tag(), N.NetworkTCP, now.Add(10*time.Second)) {
		t.Fatal("active probe failures opened the real data-plane breaker")
	}
}

func TestSmartSharedProbeFailureRemainsEligible(t *testing.T) {
	candidate := newSmartFakeOutbound("candidate-a", nil)
	smart := newTestSmart(candidate)
	smart.probeURL = defaultSmartProbeURL
	setSmartCandidateIdentities(smart, map[string]string{candidate.Tag(): "endpoint-a"})
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	smart.probeRegistry = registry
	probeKey := smart.candidateMetadataByTag[candidate.Tag()].probeKey
	registry.entries[probeKey] = &nodeProfileEntry{result: nodeProfileResult{
		success:     false,
		completedAt: time.Now(),
		nextProbeAt: time.Now().Add(time.Minute),
		failures:    nodeProfileDeadFailures,
	}}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if len(ranks) != 1 || !ranks[0].eligible || ranks[0].status.State == "open" {
		t.Fatalf("shared probe failure hard-opened Smart candidate: %+v", ranks)
	}
	if !ranks[0].activeProbeDegraded {
		t.Fatal("shared probe degradation was not retained as advisory evidence")
	}
}

func setSmartCandidateIdentities(s *Smart, identities map[string]string) {
	s.candidateMetadataByTag = make(map[string]smartCandidateMetadata, len(identities))
	for tag, identity := range identities {
		s.candidateMetadataByTag[tag] = s.buildCandidateMetadata(tag, identity)
	}
}

func interruptGroupForTest() *interrupt.Group {
	return interrupt.NewGroup()
}

func TestSmartDialFailsOverWithinSameRequest(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	destination := M.ParseSocksaddr("example.com:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	smart.store.observeDial(time.Now(), smart.networkFingerprint(), siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)

	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-second.peers
	defer peer.Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("unexpected dial counts: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != "second" {
		t.Fatalf("expected second selected, got %q", smart.Now())
	}
}

func TestSmartDialFailureRequestsBackgroundRecovery(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.probeNow = make(chan struct{}, 1)
	destination := M.ParseSocksaddr("example.com:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	// Surge deliberately shuffles equally unmeasured policies. Give the failing
	// endpoint site evidence so this test proves the failure wakeup rather than
	// accidentally depending on candidate input order.
	smart.store.observeDial(time.Now(), smart.networkFingerprint(), siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)

	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer (<-second.peers).Close()
	select {
	case <-smart.probeNow:
	default:
		t.Fatal("real dial failure did not request a background recovery probe")
	}
}

func TestSmartConcurrentDialFailuresCoalesceRecoveryWake(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", errors.New("dial failed"))
	smart := newTestSmart(first, second)
	smart.probeNow = make(chan struct{}, 1)
	destination := M.ParseSocksaddr("example.com:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	smart.store.observeDial(time.Now(), smart.networkFingerprint(), siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)

	_, _ = smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if got := len(smart.probeNow); got != 1 {
		t.Fatalf("failure burst queued %d recovery probes, want 1", got)
	}
}

func TestSmartDialHedgesSlowCandidateWithinSameRequest(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	first.dialDelay = 400 * time.Millisecond
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.attemptTimeout = 900 * time.Millisecond
	destination := M.ParseSocksaddr("example.com:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	smart.store.observeDial(time.Now(), smart.networkFingerprint(), siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)
	smart.store.observeDial(time.Now(), smart.networkFingerprint(), siteKey, second.Tag(), N.NetworkTCP, true, 100*time.Millisecond)

	startedAt := time.Now()
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if elapsed := time.Since(startedAt); elapsed >= first.dialDelay {
		t.Fatalf("Smart waited for slow candidate instead of hedging: elapsed=%s", elapsed)
	}
	peer := <-second.peers
	defer peer.Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("unexpected dial counts: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != "second" {
		t.Fatalf("expected hedged candidate selected, got %q", smart.Now())
	}
}

func TestSmartWaitsForProviderStartup(t *testing.T) {
	provider := &smartFakeProvider{tag: "airport"}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}

	if err := smart.Start(); err != nil {
		t.Fatalf("smart rejected provider warming state: %v", err)
	}
	if status := smart.SmartStatus(); status.Reason != "warming: waiting for provider candidates" {
		t.Fatalf("unexpected warming status: %q", status.Reason)
	}

	candidate := newSmartFakeOutbound("airport/hk", nil)
	if err := provider.update(candidate); err != nil {
		t.Fatalf("provider update failed: %v", err)
	}
	if all := smart.All(); len(all) != 1 || all[0] != candidate.Tag() {
		t.Fatalf("provider candidates were not installed: %v", all)
	}
	status := smart.SmartStatus()
	if status.CandidateCount != 1 || status.Reason != "warming: candidates loaded, awaiting observations" {
		t.Fatalf("provider readiness status was not published: %+v", status)
	}
}

func TestSmartCloseUnregistersProviderCallback(t *testing.T) {
	candidate := newSmartFakeOutbound("airport/hk", nil)
	provider := &smartFakeProvider{tag: "airport", outbounds: []adapter.Outbound{candidate}}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}
	if err := smart.Start(); err != nil {
		t.Fatal(err)
	}
	if provider.callbackCount() != 1 {
		t.Fatalf("expected one provider callback, got %d", provider.callbackCount())
	}
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.callbackCount() != 0 {
		t.Fatalf("retired Smart callback remained registered: %d", provider.callbackCount())
	}
	if err := provider.update(candidate); err != nil {
		t.Fatalf("provider update after Smart close failed: %v", err)
	}
}

func TestSmartProviderRefreshClearsRemovedLatestCandidate(t *testing.T) {
	first := newSmartFakeOutbound("airport/old", nil)
	provider := &smartFakeProvider{tag: "airport", outbounds: []adapter.Outbound{first}}
	smart := newTestSmart()
	smart.provider = &smartFakeProviderManager{provider: provider}
	smart.outbound = &smartFakeOutboundManager{byTag: make(map[string]adapter.Outbound)}
	smart.providers = make(map[string]adapter.Provider)
	smart.outboundsCache = make(map[string][]adapter.Outbound)
	smart.providerTags = []string{"airport"}
	if err := smart.Start(); err != nil {
		t.Fatal(err)
	}
	defer smart.Close()
	smart.latest.Store(first)
	if smart.Now() != first.Tag() {
		t.Fatal("latest candidate was not visible before provider refresh")
	}
	second := newSmartFakeOutbound("airport/new", nil)
	if err := provider.update(second); err != nil {
		t.Fatal(err)
	}
	if smart.Now() != "" {
		t.Fatalf("removed provider candidate remained selected: %q", smart.Now())
	}
}

type smartBlockingPacketOutbound struct {
	outbound.Adapter
}

func newSmartBlockingPacketOutbound(tag string) *smartBlockingPacketOutbound {
	return &smartBlockingPacketOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkUDP}, nil),
	}
}

func (o *smartBlockingPacketOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (o *smartBlockingPacketOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSmartUDPAttemptUsesAttemptTimeout(t *testing.T) {
	candidate := newSmartBlockingPacketOutbound("slow-udp")
	smart := newTestSmart(candidate)
	smart.maxAttempts = 1
	smart.attemptTimeout = 25 * time.Millisecond
	startedAt := time.Now()
	_, err := smart.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err == nil {
		t.Fatal("expected UDP attempt timeout")
	}
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("UDP attempt ignored attempt_timeout: %v", elapsed)
	}
}

func TestSmartUDPParentCancellationDoesNotPenalizeCandidate(t *testing.T) {
	candidate := newSmartBlockingPacketOutbound("cancelled-udp")
	smart := newTestSmart(candidate)
	smart.maxAttempts = 1
	smart.attemptTimeout = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := smart.ListenPacket(ctx, M.ParseSocksaddr("1.1.1.1:53"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected parent cancellation, got %v", err)
	}
	smart.store.access.RLock()
	defer smart.store.access.RUnlock()
	for key := range smart.store.metrics {
		if key.Candidate == candidate.Tag() {
			t.Fatalf("parent cancellation recorded a node failure: %+v", key)
		}
	}
}

func TestSmartDialParentCancellationDoesNotPenalizeCandidate(t *testing.T) {
	// Both the parent context and the worker result are ready at the same time
	// here. The adaptive dialer must prefer the request cancellation regardless
	// of which ready case the scheduler selects; otherwise a canceled request
	// is recorded as node health evidence roughly half the time.
	for attempt := 0; attempt < 64; attempt++ {
		candidate := newSmartParentCanceledDialOutbound("cancelled-tcp-" + strconv.Itoa(attempt))
		smart := newTestSmart(candidate)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dialAttempt := smartDialAttempt{candidate: candidate}
		_, _, _, _ = smart.dialContextAdaptive(
			ctx,
			N.NetworkTCP,
			M.ParseSocksaddr("example.com:443"),
			[]smartDialAttempt{dialAttempt},
			"network",
			"site",
			N.NetworkTCP,
		)
		smart.store.access.RLock()
		for key := range smart.store.metrics {
			if key.Candidate == candidate.Tag() {
				smart.store.access.RUnlock()
				t.Fatalf("parent cancellation recorded a node failure: %+v", key)
			}
		}
		smart.store.access.RUnlock()
	}
}

type smartParentCanceledDialOutbound struct {
	outbound.Adapter
}

func newSmartParentCanceledDialOutbound(tag string) *smartParentCanceledDialOutbound {
	return &smartParentCanceledDialOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
}

func (o *smartParentCanceledDialOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return nil, ctx.Err()
}

func (*smartParentCanceledDialOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type smartCanceledProbeOutbound struct {
	outbound.Adapter
}

func newSmartCanceledProbeOutbound(tag string) *smartCanceledProbeOutbound {
	return &smartCanceledProbeOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
}

func (o *smartCanceledProbeOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*smartCanceledProbeOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestSmartProbeCancellationDoesNotDeadlockDispatcher(t *testing.T) {
	candidates := make([]adapter.Outbound, 64)
	for index := range candidates {
		candidates[index] = newSmartCanceledProbeOutbound("probe-" + strconv.Itoa(index))
	}
	smart := newTestSmart(candidates...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		_, _ = smart.probe(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled Smart probe deadlocked while dispatching candidates")
	}
}

func TestSmartProbeDeadlineCommitsCompletedObservations(t *testing.T) {
	fast := newSmartFakeOutbound("probe-fast", nil)
	slow := newSmartFakeOutbound("probe-slow", nil)
	smart := newTestSmart(fast, slow)
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	registry.probe = func(ctx context.Context, _ string, candidate adapter.Outbound) (uint16, error) {
		if candidate.Tag() == fast.Tag() {
			return 12, nil
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	smart.probeRegistry = registry
	setSmartCandidateIdentities(smart, map[string]string{
		fast.Tag(): fast.Tag(),
		slow.Tag(): slow.Tag(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result, err := smart.probe(ctx)
	// New contract: the caller deadline returns the partial map with a nil
	// error so panels render it; the portrait sweep continues in the
	// background and commits every observation that already completed.
	if err != nil {
		t.Fatalf("partial cycle must not surface the caller deadline, got %v", err)
	}
	if result[fast.Tag()] != 12 {
		t.Fatalf("completed probe missing from result: %v", result)
	}
	estimate := smart.store.estimate(time.Now(), smart.networkFingerprint(), "", fast.Tag(), N.NetworkTCP, smart.minSamples)
	if estimate.State == "unknown" || estimate.Samples == 0 {
		t.Fatalf("completed observation was discarded at deadline: %+v", estimate)
	}
	status := smart.SmartStatus()
	foundObserved := false
	for _, candidate := range status.Candidates {
		if candidate.Tag == fast.Tag() && candidate.Samples > 0 {
			foundObserved = true
			break
		}
	}
	if !foundObserved {
		t.Fatalf("completed observation was not published without traffic: %+v", status)
	}
}

func TestSmartRequestProbeCoalesces(t *testing.T) {
	smart := &Smart{probeNow: make(chan struct{}, 1)}
	smart.requestProbe()
	smart.requestProbe()
	if got := len(smart.probeNow); got != 1 {
		t.Fatalf("queued probes=%d, want 1", got)
	}
}

func TestSmartBasicProbeFailuresRemainAdvisory(t *testing.T) {
	candidate := newSmartFakeOutbound("bootstrap-candidate", nil)
	smart := newTestSmart(candidate)
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	smart.probeRegistry = registry
	setSmartCandidateIdentities(smart, map[string]string{candidate.Tag(): candidate.Tag()})
	smart.access.RLock()
	key := smart.candidateMetadataByTag[candidate.Tag()].probeKey
	smart.access.RUnlock()
	registry.entries[key] = &nodeProfileEntry{result: nodeProfileResult{
		success: false, failures: 1, nextProbeAt: time.Now().Add(time.Minute),
	}}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || ranks[0].status.State == "open" {
		t.Fatalf("one basic-probe failure must not remove the cold-start candidate: %+v", ranks)
	}
	registry.entries[key].result.failures = nodeProfileDeadFailures
	ranks, _, _, _ = smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || !ranks[0].eligible || ranks[0].status.State == "open" || !ranks[0].activeProbeDegraded {
		t.Fatalf("confirmed active-probe failure must degrade without isolating the candidate: %+v", ranks)
	}
}

func TestSmartDoesNotConsumeOtherGroupPassiveFailure(t *testing.T) {
	candidate := newSmartFakeOutbound("shared-passive", nil)
	smart := newTestSmart(candidate)
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	smart.probeRegistry = registry
	setSmartCandidateIdentities(smart, map[string]string{candidate.Tag(): candidate.Tag()})
	registry.recordPassive(groupTCPPassiveProfileKey(candidate), false, 0, groupPassiveFailureTTL)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || !ranks[0].eligible || ranks[0].status.State == "open" {
		t.Fatalf("shared passive state from another group isolated Smart candidate: %+v", ranks)
	}
	registry.recordPassive(groupTCPPassiveProfileKey(candidate), true, 0, 0)
	ranks, _, _, _ = smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 1 || ranks[0].status.State == "open" {
		t.Fatalf("shared passive TCP recovery did not restore Smart candidate: %+v", ranks)
	}
}

func TestSmartSiteFailureDoesNotQuarantineSharedGroupProfile(t *testing.T) {
	for _, testCase := range []struct {
		name, transport string
	}{
		{name: "tcp", transport: N.NetworkTCP},
		{name: "udp", transport: N.NetworkUDP},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := newSmartFakeOutbound("shared-"+testCase.name, nil)
			smart := newTestSmart(candidate)
			registry := newNodeProfileRegistry(context.Background())
			defer registry.close()
			smart.probeRegistry = registry
			setSmartCandidateIdentities(smart, map[string]string{candidate.Tag(): candidate.Tag()})
			key := groupTCPPassiveProfileKey(candidate, testCase.transport)
			if testCase.transport == N.NetworkUDP {
				key = groupUDPProfileKey(candidate)
			}
			smart.observeDataPlaneFailureWithType(time.Now(), "network", "service:example", candidate.Tag(), testCase.transport, time.Second, "transport")
			if registry.passiveFailureActive(key) {
				t.Fatal("one website's timeout quarantined a shared URLTest/LoadBalance credential")
			}
			smart.observeDataPlaneFailureWithType(time.Now(), "network", "service:example", candidate.Tag(), testCase.transport, time.Second, "protocol")
			if !registry.passiveFailureActive(key) {
				t.Fatal("authoritative protocol failure did not reach shared transport health")
			}
		})
	}
}

func TestSmartAllOpenRecoveryUsesHalfOpenBasicProbe(t *testing.T) {
	first := newSmartFakeOutbound("recovery-first", nil)
	second := newSmartFakeOutbound("recovery-second", nil)
	smart := newTestSmart(first, second)
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	registry.probe = func(_ context.Context, _ string, candidate adapter.Outbound) (uint16, error) {
		if candidate.Tag() == first.Tag() {
			return 25, nil
		}
		return 40, nil
	}
	smart.probeRegistry = registry
	setSmartCandidateIdentities(smart, map[string]string{first.Tag(): first.Tag(), second.Tag(): second.Tag()})
	now := time.Now()
	for _, candidate := range []adapter.Outbound{first, second} {
		smart.store.observeDial(now, smart.networkFingerprint(), "", candidate.Tag(), N.NetworkTCP, false, time.Second)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if len(ranks) != 2 || hasEligibleSmartRank(ranks) {
		t.Fatalf("expected all candidates to start open: %+v", ranks)
	}
	if !smart.recoverOpenCandidates(context.Background(), []adapter.Outbound{first, second}, N.NetworkTCP) {
		t.Fatal("half-open recovery did not find a reachable candidate")
	}
	ranks, _, _, _ = smart.rank(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if !hasEligibleSmartRank(ranks) || ranks[0].status.State == "open" {
		t.Fatalf("recovered candidate remained unavailable: %+v", ranks)
	}
}

func TestSmartEmergencyURLTestFallbackBypassesPassiveFloor(t *testing.T) {
	fast := newSmartFakeOutbound("fallback-fast", nil)
	slow := newSmartFakeOutbound("fallback-slow", nil)
	smart := newTestSmart(fast, slow)
	smart.maxAttempts = 2
	ranks := []smartRank{
		{outbound: slow, eligible: false, passiveThroughputLow: true, status: adapter.SmartCandidateStatus{Tag: slow.Tag(), State: "open"}},
		{outbound: fast, eligible: false, passiveThroughputLow: true, status: adapter.SmartCandidateStatus{Tag: fast.Tag(), State: "open"}},
	}
	recovered := []smartRecoveryCandidate{
		{candidate: fast, measured: 20 * time.Millisecond},
		{candidate: slow, measured: 80 * time.Millisecond},
	}
	fallback := smart.emergencyURLTestRanks(ranks, recovered)
	if len(fallback) != 2 {
		t.Fatalf("fallback ranks=%d, want 2", len(fallback))
	}
	if fallback[0].outbound != fast || fallback[1].outbound != slow {
		t.Fatalf("fallback order=%s,%s, want fast,slow", fallback[0].outbound.Tag(), fallback[1].outbound.Tag())
	}
	for _, rank := range fallback {
		if !rank.eligible || rank.status.State == "open" || rank.passiveThroughputLow {
			t.Fatalf("fallback rank remained gated: %+v", rank)
		}
		if rank.status.Reason != "URLTest emergency fallback" {
			t.Fatalf("fallback reason=%q", rank.status.Reason)
		}
	}
}

func TestSmartProbePublishesFirstSuccessBeforeCycleCompletes(t *testing.T) {
	fast := newSmartFakeOutbound("stream-fast", nil)
	slow := newSmartFakeOutbound("stream-slow", nil)
	smart := newTestSmart(fast, slow)
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	releaseSlow := make(chan struct{})
	registry.probe = func(_ context.Context, _ string, candidate adapter.Outbound) (uint16, error) {
		if candidate.Tag() == fast.Tag() {
			return 9, nil
		}
		<-releaseSlow
		return 10, nil
	}
	smart.probeRegistry = registry
	setSmartCandidateIdentities(smart, map[string]string{fast.Tag(): fast.Tag(), slow.Tag(): slow.Tag()})
	done := make(chan struct{})
	go func() {
		_, _ = smart.probe(context.Background())
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		status := smart.SmartStatus()
		published := false
		for _, candidate := range status.Candidates {
			if candidate.Tag == fast.Tag() && candidate.Samples > 0 {
				published = true
				break
			}
		}
		if published {
			break
		}
		if time.Now().After(deadline) {
			close(releaseSlow)
			t.Fatal("first successful basic probe was not published while the cycle remained active")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("probe cycle completed before the blocked candidate was released")
	default:
	}
	close(releaseSlow)
	<-done
}

func TestSmartProbeCoversEveryCandidateRegardlessOfGroupSize(t *testing.T) {
	candidates := make([]adapter.Outbound, 128)
	fakes := make([]*smartFakeOutbound, len(candidates))
	for index := range candidates {
		fakes[index] = newSmartFakeOutbound("probe-all-"+strconv.Itoa(index), errors.New("offline"))
		candidates[index] = fakes[index]
	}
	smart := newTestSmart(candidates...)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = smart.probe(ctx)
	for index, candidate := range fakes {
		if candidate.dials.Load() != 1 {
			t.Fatalf("candidate %d was probed %d times", index, candidate.dials.Load())
		}
	}
}

type smartObservedTestPacketConn struct {
	response []byte
	readErr  error
	writeErr error
}

type smartObservedTestPacketReaderWriter struct {
	*smartObservedTestPacketConn
}

func (*smartObservedTestPacketReaderWriter) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, nil
}

func (*smartObservedTestPacketReaderWriter) WritePacket(*buf.Buffer, M.Socksaddr) error {
	return nil
}

func (c *smartObservedTestPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if len(c.response) == 0 {
		return 0, nil, net.ErrClosed
	}
	count := copy(payload, c.response)
	return count, &net.UDPAddr{}, nil
}

func (c *smartObservedTestPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(payload), nil
}

func (*smartObservedTestPacketConn) Close() error                     { return nil }
func (*smartObservedTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*smartObservedTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*smartObservedTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*smartObservedTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestSmartObservedExtendedPacketWrapperIsRecognized(t *testing.T) {
	observed := newSmartObservedPacketConnWithWatchdogThreshold(
		&smartObservedTestPacketReaderWriter{smartObservedTestPacketConn: &smartObservedTestPacketConn{}},
		time.Now(), true, 1, 0, nil,
	)
	if _, ok := observed.(*smartObservedExtendedPacketConn); !ok {
		t.Fatalf("observed packet connection type=%T, want extended wrapper", observed)
	}
	if _, ok := observed.(smartObservedWrapper); !ok {
		t.Fatalf("extended packet wrapper %T does not advertise observation marker", observed)
	}
}

func TestSmartTransactionalUDPNoResponseReportsOnce(t *testing.T) {
	var failures atomic.Int64
	conn := newSmartObservedPacketConn(&smartObservedTestPacketConn{}, time.Now().Add(-2*time.Second), true, func(time.Duration) {
		failures.Add(1)
	})
	if _, err := conn.WriteTo([]byte("quic"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 1 {
		t.Fatalf("transactional UDP failure count=%d, want 1", failures.Load())
	}
}

func TestSmartTransactionalUDPClassifiesProtocolErrors(t *testing.T) {
	for _, test := range []struct {
		name           string
		expectResponse bool
		wantFailure    bool
		readErr        error
		writeErr       error
	}{
		{name: "read", expectResponse: true, wantFailure: true, readErr: errors.New("authentication failed, auth_str=bad")},
		{name: "write", wantFailure: true, writeErr: errors.New("UDP disabled by server")},
		{name: "one way", writeErr: errors.New("connection refused")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failures atomic.Int64
			conn := newSmartObservedPacketConn(&smartObservedTestPacketConn{
				readErr:  test.readErr,
				writeErr: test.writeErr,
			}, time.Now(), test.expectResponse, func(time.Duration) {
				failures.Add(1)
			})
			if test.readErr != nil {
				_, _, _ = conn.ReadFrom(make([]byte, 32))
			} else {
				_, _ = conn.WriteTo([]byte("payload"), &net.UDPAddr{})
			}
			want := int64(0)
			if test.wantFailure {
				want = 1
			}
			if failures.Load() != want {
				t.Fatalf("protocol UDP failure count=%d, want %d", failures.Load(), want)
			}
		})
	}
}

func TestSmartTransactionalUDPWatchdogReportsInFlightBlackhole(t *testing.T) {
	var failures atomic.Int64
	conn := newSmartObservedPacketConnWithWatchdog(&smartObservedTestPacketConn{}, time.Now(), true, 20*time.Millisecond, func(time.Duration) {
		failures.Add(1)
	})
	if _, err := conn.WriteTo([]byte("quic"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for failures.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if failures.Load() != 1 {
		t.Fatalf("in-flight UDP failure count=%d, want 1", failures.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 1 {
		t.Fatalf("watchdog failure was reported more than once: %d", failures.Load())
	}
}

func TestSmartQUICWatchdogWaitsForHandshakeDatagrams(t *testing.T) {
	var failures atomic.Int64
	conn := newSmartObservedPacketConnWithWatchdogThreshold(&smartObservedTestPacketConn{}, time.Now(), true, 3, 20*time.Millisecond, func(time.Duration) {
		failures.Add(1)
	})
	for range 2 {
		if _, err := conn.WriteTo([]byte("quic"), &net.UDPAddr{}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if failures.Load() != 0 {
		t.Fatalf("QUIC watchdog fired before the handshake packet threshold: %d", failures.Load())
	}
	if _, err := conn.WriteTo([]byte("quic"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for failures.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if failures.Load() != 1 {
		t.Fatalf("QUIC watchdog count=%d, want one after three datagrams", failures.Load())
	}
	_ = conn.Close()
}

func TestSmartUDPResponseAndOneWayTrafficDoNotFail(t *testing.T) {
	for _, test := range []struct {
		name           string
		expectResponse bool
		response       []byte
	}{
		{name: "transaction received response", expectResponse: true, response: []byte("ok")},
		{name: "one way UDP", expectResponse: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failures atomic.Int64
			conn := newSmartObservedPacketConn(&smartObservedTestPacketConn{response: test.response}, time.Now().Add(-2*time.Second), test.expectResponse, func(time.Duration) {
				failures.Add(1)
			})
			if _, err := conn.WriteTo([]byte("payload"), &net.UDPAddr{}); err != nil {
				t.Fatal(err)
			}
			if len(test.response) > 0 {
				buffer := make([]byte, 16)
				if _, _, err := conn.ReadFrom(buffer); err != nil {
					t.Fatal(err)
				}
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if failures.Load() != 0 {
				t.Fatalf("false UDP failure count=%d", failures.Load())
			}
		})
	}
}

func TestSmartPermanentPinSurvivesTransientFailureThenReleasesAtThreshold(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("dial failed"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound("first") {
		t.Fatal("failed to pin first")
	}

	destination := M.ParseSocksaddr("example.com:443")
	for attempt := 1; attempt <= smart.breakerFailures; attempt++ {
		conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		peer := <-second.peers
		peer.Close()
		status := smart.SmartStatus()
		if attempt < smart.breakerFailures && status.Pinned != "first" {
			t.Fatalf("transient failure %d prematurely cleared pin: %q", attempt, status.Pinned)
		}
		if attempt == smart.breakerFailures && status.Pinned != "" {
			t.Fatalf("confirmed failure did not release pin: %q", status.Pinned)
		}
	}
}

func TestSmartManualPinIgnoresPerformanceScore(t *testing.T) {
	first := newSmartFakeOutbound("manual-slow", nil)
	second := newSmartFakeOutbound("automatic-fast", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound(first.Tag()) {
		t.Fatal("failed to set manual pin")
	}
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("example.com:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 900*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 10*time.Millisecond)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if got := ranks[0].outbound.Tag(); got != first.Tag() {
		t.Fatalf("performance score overruled manual pin: got %q", got)
	}
}

func TestSmartDashboardProbeRetainsManualPin(t *testing.T) {
	first := newSmartFakeOutbound("manual", nil)
	second := newSmartFakeOutbound("automatic", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound(first.Tag()) {
		t.Fatal("failed to set manual pin")
	}
	// Make the pinned candidate look unusable to the normal state machine.  A
	// dashboard probe must still be read-only: it cannot release the pin or let
	// a one-off panel measurement replace it.
	now := time.Now()
	for range smart.store.breakerFailures {
		smart.store.observeDial(now, smart.networkFingerprint(), "", first.Tag(), N.NetworkTCP, false, time.Millisecond)
	}
	ranking, _, _, _ := smart.rankPooled(withSmartDashboardProbe(context.Background()), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	defer ranking.Release()
	if len(ranking.ranks) != 2 || ranking.ranks[0].outbound.Tag() != first.Tag() {
		t.Fatalf("dashboard probe changed incumbent: ranks=%v", ranking.ranks)
	}
	if got := smart.SmartStatus().Pinned; got != first.Tag() {
		t.Fatalf("dashboard probe released manual pin: %q", got)
	}
}

func TestSmartDashboardProbeDoesNotReplaceLatestBusinessDisplay(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)

	normal, _, _, _ := smart.rankPooled(context.Background(), N.NetworkTCP, M.ParseSocksaddr("www.youtube.com:443"))
	normal.Release()
	before := smart.SmartStatus()
	if before.Site != "service:youtube" || before.Selected == "" {
		t.Fatalf("normal business status was not published: %+v", before)
	}

	probe, _, _, _ := smart.rankPooled(withSmartDashboardProbe(context.Background()), N.NetworkTCP, M.ParseSocksaddr("api.openai.com:443"))
	probe.Release()
	after := smart.SmartStatus()
	if after.Site != before.Site || after.Selected != before.Selected || after.SelectionGeneration != before.SelectionGeneration {
		t.Fatalf("dashboard probe replaced latest business display: before=%+v after=%+v", before, after)
	}
}

func TestSmartDashboardDialDoesNotCommitSelection(t *testing.T) {
	first := newSmartFakeOutbound("manual", nil)
	second := newSmartFakeOutbound("automatic", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound(first.Tag()) {
		t.Fatal("failed to set manual pin")
	}

	conn, err := smart.DialContext(withSmartDashboardProbe(context.Background()), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-first.peers
	defer peer.Close()

	status := smart.SmartStatus()
	if status.Pinned != first.Tag() {
		t.Fatalf("dashboard dial changed manual pin: %q", status.Pinned)
	}
	if status.SwitchesTotal != 0 || status.FailureFailovers != 0 {
		t.Fatalf("dashboard dial changed switch accounting: %+v", status)
	}
}

func TestSmartDashboardDialFailureIsAdvisory(t *testing.T) {
	first := newSmartFakeOutbound("manual", errors.New("connection reset by peer"))
	second := newSmartFakeOutbound("automatic", nil)
	smart := newTestSmart(first, second)
	if !smart.SelectOutbound(first.Tag()) {
		t.Fatal("failed to set manual pin")
	}

	conn, err := smart.DialContext(withSmartDashboardProbe(context.Background()), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-second.peers
	defer peer.Close()

	status := smart.SmartStatus()
	if status.Pinned != first.Tag() {
		t.Fatalf("dashboard failure released manual pin: %q", status.Pinned)
	}
	if status.FailureFailovers != 0 {
		t.Fatalf("dashboard failure changed failover accounting: %+v", status)
	}
}

func TestSmartUnstartedHalfOpenAttemptReleasesReservation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	ranks := []smartRank{
		{outbound: first, eligible: true, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{outbound: second, eligible: true, status: adapter.SmartCandidateStatus{State: "half_open"}},
	}
	attempts := smart.collectDialAttempts(ranks, "network", "site", N.NetworkTCP)
	conn, _, _, ok := smart.dialContextAdaptive(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), attempts, "network", "site", N.NetworkTCP)
	if !ok {
		t.Fatal("expected first attempt to succeed")
	}
	conn.Close()
	peer := <-first.peers
	peer.Close()
	smart.access.Lock()
	defer smart.access.Unlock()
	if len(smart.halfOpen) != 0 {
		t.Fatalf("unstarted half-open reservation leaked: %d", len(smart.halfOpen))
	}
}

func TestSmartCapsConcurrentHalfOpenRecoveryLeases(t *testing.T) {
	outs := make([]*smartFakeOutbound, defaultSmartMaxHalfOpenProbes+1)
	for index := range outs {
		outs[index] = newSmartFakeOutbound(fmt.Sprintf("half-open-%d", index), nil)
	}
	candidates := make([]adapter.Outbound, len(outs))
	for index, candidate := range outs {
		candidates[index] = candidate
	}
	smart := newTestSmart(candidates...)
	ranks := make([]smartRank, len(outs))
	for index, candidate := range outs {
		ranks[index] = smartRank{
			outbound: candidate,
			eligible: true,
			status:   adapter.SmartCandidateStatus{State: "half_open"},
		}
	}
	for index := 0; index < defaultSmartMaxHalfOpenProbes; index++ {
		if !smart.reserveHalfOpen(ranks[index], "network", "site", N.NetworkTCP) {
			t.Fatalf("lease %d was denied before the group cap", index)
		}
	}
	if smart.reserveHalfOpen(ranks[len(ranks)-1], "network", "site", N.NetworkTCP) {
		t.Fatal("half-open lease cap was not enforced")
	}
	smart.releaseHalfOpen(outs[0].Tag(), "network", "site", N.NetworkTCP)
	if !smart.reserveHalfOpen(ranks[len(ranks)-1], "network", "site", N.NetworkTCP) {
		t.Fatal("released half-open lease was not reusable")
	}
}

func TestSmartDialAttemptsDeduplicatePathAliasesButKeepCredentialVariants(t *testing.T) {
	first := newSmartFakeOutbound("airport/HK", nil)
	alias := newSmartFakeOutbound("airport/HK #2", nil)
	credentialVariant := newSmartFakeOutbound("airport/HK #3", nil)
	smart := newTestSmart(first, alias, credentialVariant)
	ranks := []smartRank{
		{outbound: first, identity: "path:hk", dialIdentity: "dial:credential-a", eligible: true, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{outbound: alias, identity: "path:hk", dialIdentity: "dial:credential-a", eligible: true, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{outbound: credentialVariant, identity: "path:hk", dialIdentity: "dial:credential-b", eligible: true, status: adapter.SmartCandidateStatus{State: "healthy"}},
	}
	attempts := smart.collectDialAttempts(ranks, "network", "site", N.NetworkTCP)
	if len(attempts) != 2 {
		t.Fatalf("attempts=%d, want 2 distinct dial identities", len(attempts))
	}
	if attempts[0].candidate.Tag() != first.Tag() || attempts[1].candidate.Tag() != credentialVariant.Tag() {
		t.Fatalf("attempt order=%q,%q, want first alias then credential variant", attempts[0].candidate.Tag(), attempts[1].candidate.Tag())
	}
}

func TestSmartFixedPrimaryPreventsMinorOscillation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("video.example:443"))
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkTCP, true, 100*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkTCP, true, 95*time.Millisecond)
	}
	initialRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("video.example:443"))
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, initialRanks, 0, false)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("video.example:443"))
	if ranks[0].outbound.Tag() != "first" {
		t.Fatalf("expected fixed incumbent to remain primary, got %s", ranks[0].outbound.Tag())
	}
}

func TestSmartEquivalentSubscriptionLineRemainsFixedWhileHealthy(t *testing.T) {
	primary := newSmartFakeOutbound("airport/香港-广东专线 NeaRoute", nil)
	duplicate := newSmartFakeOutbound("airport/香港-广东专线 NeaRoute #deadbeef", nil)
	smart := newTestSmart(primary, duplicate)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("video.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, primary.Tag(), N.NetworkTCP, true, 200*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, duplicate.Tag(), N.NetworkTCP, true, 20*time.Millisecond)
	}
	smart.markSelected(primary, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].outbound.Tag() != primary.Tag() {
		t.Fatalf("canonical endpoint alias was not retained: %s", ranks[0].outbound.Tag())
	}
	if ranks[0].status.Reason != "equivalent subscription line retained" {
		t.Fatalf("unexpected equivalent-line reason: %q", ranks[0].status.Reason)
	}
}

func TestSmartCanonicalEndpointAliasDoesNotCountAsSwitch(t *testing.T) {
	primary := newSmartFakeOutbound("airport/HK #1", nil)
	duplicate := newSmartFakeOutbound("airport/HK #2", nil)
	smart := newTestSmart(primary, duplicate)
	setSmartCandidateIdentities(smart, map[string]string{
		primary.Tag():   "trojan://edge.example:443",
		duplicate.Tag(): "trojan://edge.example:443",
	})
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("search.example:443"))
	smart.markSelected(primary, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	smart.markSelected(duplicate, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	if got := smart.switchesTotal.Load(); got != 0 {
		t.Fatalf("canonical alias was counted as a switch: %d", got)
	}
	if got := smart.performanceSwitches.Load(); got != 0 {
		t.Fatalf("canonical alias was counted as a performance switch: %d", got)
	}
	smart.switchAuditAccess.Lock()
	auditCount := len(smart.switchAudit)
	smart.switchAuditAccess.Unlock()
	if auditCount != 0 {
		t.Fatalf("canonical alias produced switch audit entries: %d", auditCount)
	}
}

func TestSmartLateHealthyResultCannotOverwriteNewerSelection(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("search.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	// A newer request has already committed second. The late result below was
	// ranked while first was still the incumbent and must not roll it back.
	smart.markSelected(second, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	selectedAt := smart.lastSelectedAt[smartBusinessSelectionKey(networkKey, siteKey, N.NetworkTCP)]
	ranks := []smartRank{
		{outbound: first, eligible: true, status: adapter.SmartCandidateStatus{Tag: first.Tag(), State: "healthy", Score: 0.1}},
		{outbound: second, eligible: true, status: adapter.SmartCandidateStatus{Tag: second.Tag(), State: "healthy", Score: 0.2}},
	}
	smart.markSelectedWithSnapshot(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, "first", selectedAt.Add(-time.Second), true, ranks, 0, false)
	if got := smart.Now(); got != second.Tag() {
		t.Fatalf("late healthy result replaced newer selection: %s", got)
	}
	if got := smart.switchesTotal.Load(); got != 0 {
		t.Fatalf("stale healthy result counted as a switch: %d", got)
	}
}

func TestSmartEndpointIDIsStableAndOpaque(t *testing.T) {
	if got := smartEndpointID("endpoint:"+strings.Repeat("a", 64), 0); got != "endpoint:"+strings.Repeat("a", 64) {
		t.Fatalf("structured endpoint ID changed: %q", got)
	}
	identity := "trojan://edge.example:443"
	policyID := smartPolicyID(identity)
	got := smartEndpointID(identity, policyID)
	want := "policy:" + strconv.FormatUint(policyID, 16)
	if got != want {
		t.Fatalf("legacy endpoint ID = %q, want %q", got, want)
	}
	if strings.Contains(got, identity) || strings.Contains(got, "edge.example") {
		t.Fatalf("endpoint ID leaked provider identity: %q", got)
	}
}

func TestSmartSelectionGenerationAndDialEvidence(t *testing.T) {
	first := newSmartFakeOutbound("line-a", nil)
	second := newSmartFakeOutbound("line-b", nil)
	smart := newTestSmart(first, second)
	setSmartCandidateIdentities(smart, map[string]string{
		first.Tag():  "trojan://edge-a.example:443",
		second.Tag(): "trojan://edge-b.example:443",
	})
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("search.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	ranks := []smartRank{
		{outbound: first, identity: "trojan://edge-a.example:443", policyID: smartPolicyID("trojan://edge-a.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: first.Tag(), EndpointID: smartEndpointID("trojan://edge-a.example:443", smartPolicyID("trojan://edge-a.example:443")), State: "open"}},
		{outbound: second, identity: "trojan://edge-b.example:443", policyID: smartPolicyID("trojan://edge-b.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: second.Tag(), EndpointID: smartEndpointID("trojan://edge-b.example:443", smartPolicyID("trojan://edge-b.example:443")), State: "healthy"}},
	}
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, ranks, 0, false)
	statusKey := smartStatusSelectionKey(networkKey, siteDisplay, N.NetworkTCP)
	if got := smart.selectionGeneration[statusKey]; got != 1 {
		t.Fatalf("initial selection generation=%d, want 1", got)
	}
	smart.recordZigSelectedEndpoint(statusKey, ranks[0].status.EndpointID)
	smart.recordActualDial(statusKey, ranks[0].status.EndpointID, 1)
	smart.recordZigSelectedEndpoint(statusKey, ranks[1].status.EndpointID)
	smart.markSelected(second, networkKey, siteKey, siteDisplay, N.NetworkTCP, ranks, 1, true)
	if got := smart.selectionGeneration[statusKey]; got != 2 {
		t.Fatalf("failover selection generation=%d, want 2", got)
	}
	smart.recordActualDial(statusKey, ranks[0].status.EndpointID, 1)
	if got := smart.selectionMismatchTotal.Load(); got != 1 {
		t.Fatalf("selection mismatch count=%d, want 1", got)
	}
	status := smart.SmartStatus()
	if status.ActualDialEndpointID != ranks[0].status.EndpointID || status.SelectionGeneration != 2 {
		t.Fatalf("runtime dial evidence not exposed: %+v", status)
	}
}

func TestSmartSuccessfulFallbackCommitsDialEvidenceBeforeRecording(t *testing.T) {
	first := newSmartFakeOutbound("line-a", nil)
	second := newSmartFakeOutbound("line-b", nil)
	smart := newTestSmart(first, second)
	setSmartCandidateIdentities(smart, map[string]string{
		first.Tag():  "trojan://edge-a.example:443",
		second.Tag(): "trojan://edge-b.example:443",
	})
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("search.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	firstID := smartEndpointID(smart.candidateMetadataByTag[first.Tag()].identity, smart.candidateMetadataByTag[first.Tag()].policyID)
	secondID := smartEndpointID(smart.candidateMetadataByTag[second.Tag()].identity, smart.candidateMetadataByTag[second.Tag()].policyID)
	ranks := []smartRank{
		{outbound: first, identity: "trojan://edge-a.example:443", policyID: smartPolicyID("trojan://edge-a.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: first.Tag(), EndpointID: firstID, State: "open"}},
		{outbound: second, identity: "trojan://edge-b.example:443", policyID: smartPolicyID("trojan://edge-b.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: second.Tag(), EndpointID: secondID, State: "healthy"}},
	}
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, ranks, 0, false)
	statusKey := smartStatusSelectionKey(networkKey, siteDisplay, N.NetworkTCP)
	smart.recordActualDial(statusKey, firstID, 1)
	smart.store.openEndpointCircuit(time.Now(), networkKey, smart.candidateProfileID(first.Tag()), N.NetworkTCP)

	// The real dial result is recorded after the fallback commit. This must not
	// look like a control/data mismatch, even though the rank snapshot was made
	// before the generation changed.
	committed := smart.markSelectedWithSnapshot(second, networkKey, siteKey, siteDisplay, N.NetworkTCP,
		first.Tag(), time.Now().Add(-time.Second), true, ranks, 1, true)
	if !committed {
		t.Fatal("successful fallback selection was not committed")
	}
	smart.recordActualDialForAttempt(statusKey, secondID, 1, committed)
	if got := smart.selectionMismatchTotal.Load(); got != 0 {
		t.Fatalf("successful fallback produced selection mismatch=%d", got)
	}
	if got := smart.zigSelectedEndpoint[statusKey]; got != secondID {
		t.Fatalf("zig endpoint=%q, want %q", got, secondID)
	}
}

func TestSmartSwitchAuditIncludesEndpointIDs(t *testing.T) {
	first := newSmartFakeOutbound("airport/HK #1", nil)
	second := newSmartFakeOutbound("airport/HK #2", nil)
	smart := newTestSmart(first, second)
	setSmartCandidateIdentities(smart, map[string]string{
		first.Tag():  "trojan://edge-a.example:443",
		second.Tag(): "trojan://edge-b.example:443",
	})
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("search.example:443"))
	ranks := []smartRank{
		{outbound: first, identity: "trojan://edge-a.example:443", policyID: smartPolicyID("trojan://edge-a.example:443"), status: adapter.SmartCandidateStatus{Tag: first.Tag(), State: "open", Score: 2}},
		{outbound: second, identity: "trojan://edge-b.example:443", policyID: smartPolicyID("trojan://edge-b.example:443"), status: adapter.SmartCandidateStatus{Tag: second.Tag(), State: "healthy", Score: 1}},
	}
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, ranks, 0, false)
	smart.store.openEndpointCircuit(time.Now(), networkKey, smart.candidateProfileID(first.Tag()), N.NetworkTCP)
	smart.markSelected(second, networkKey, siteKey, siteDisplay, N.NetworkTCP, ranks, 1, true)
	status := smart.SmartStatus()
	if len(status.RecentSwitches) != 1 {
		t.Fatalf("expected one switch audit, got %d", len(status.RecentSwitches))
	}
	audit := status.RecentSwitches[0]
	if audit.PreviousEndpointID != smartEndpointID(ranks[0].identity, ranks[0].policyID) || audit.CurrentEndpointID != smartEndpointID(ranks[1].identity, ranks[1].policyID) {
		t.Fatalf("audit endpoint IDs = %q -> %q", audit.PreviousEndpointID, audit.CurrentEndpointID)
	}
	if strings.Contains(audit.PreviousEndpointID, "edge-a.example") || strings.Contains(audit.CurrentEndpointID, "edge-b.example") {
		t.Fatal("switch audit leaked provider endpoint details")
	}
}

func TestSmartRankIndexForPolicyPrefersCurrentAlias(t *testing.T) {
	primary := newSmartFakeOutbound("airport/HK #1", nil)
	duplicate := newSmartFakeOutbound("airport/HK #2", nil)
	policyID := smartPolicyID("trojan://edge.example:443")
	ranks := []smartRank{
		{outbound: primary, policyID: policyID, eligible: true},
		{outbound: duplicate, policyID: policyID, eligible: true},
	}
	if got := smartRankIndexForPolicy(ranks, policyID, duplicate.Tag()); got != 1 {
		t.Fatalf("current alias index = %d, want 1", got)
	}
	ranks[1].eligible = false
	if got := smartRankIndexForPolicy(ranks, policyID, duplicate.Tag()); got != 0 {
		t.Fatalf("ineligible alias prevented fallback to eligible endpoint: %d", got)
	}
}

func TestSmartRemapRemovedAliasKeepsEndpointAffinity(t *testing.T) {
	oldTag := "airport/HK #old"
	newTag := "airport/HK #new"
	oldMetadata := smartCandidateMetadata{identity: "trojan://edge.example:443", profileID: "endpoint:trojan://edge.example:443", policyID: smartPolicyID("trojan://edge.example:443")}
	newMetadata := smartCandidateMetadata{identity: oldMetadata.identity, profileID: oldMetadata.profileID, policyID: oldMetadata.policyID}
	newCandidate := newSmartFakeOutbound(newTag, nil)
	got := smartRemapCandidateAlias(oldTag,
		map[string]smartCandidateMetadata{oldTag: oldMetadata},
		map[string]smartCandidateMetadata{newTag: newMetadata},
		[]adapter.Outbound{newCandidate},
	)
	if got != newTag {
		t.Fatalf("removed alias was not remapped to the same endpoint: %q", got)
	}
}

func TestSmartLineFamilyOnlyStripsGeneratedDuplicateSuffixes(t *testing.T) {
	base := "airport/香港-广东专线 NeaRoute"
	for _, duplicate := range []string{base + " #deadbeef", base + " (2)"} {
		if !smartEquivalentLine(base, duplicate) {
			t.Fatalf("generated duplicate suffix was not grouped: %q", duplicate)
		}
	}
	if smartEquivalentLine("airport/香港-广东专线 BGP 1", "airport/香港-广东专线 BGP 2") {
		t.Fatal("real numbered lines were incorrectly grouped")
	}
}

func TestSmartFixedPrimaryDoesNotWaitForLatencyImprovement(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.switchConfirm = 20 * time.Millisecond
	smart.switchConfirmSamples = 3
	smart.switchMargin = 0
	// The production backend receives these values at construction time. Rebuild
	// the fixture after overriding them so the test models the same immutable
	// configuration boundary instead of accidentally retaining the defaults.
	smart.closePolicyBackend()
	smart.policyBackend = newSmartPolicyBackend(smartPolicyBackendConfig{
		Exploration:         smart.exploration,
		SwitchMargin:        smart.switchMargin,
		SwitchConfirm:       smart.switchConfirmSamples,
		SwitchConfirmWindow: smart.switchConfirm.Milliseconds(),
		SwitchCooldown:      smart.switchCooldown.Milliseconds(),
		MinSamples:          smart.minSamples,
	})
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("search.example:443")
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 200*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 20*time.Millisecond)
	}
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].outbound.Tag() != first.Tag() {
		t.Fatalf("fixed incumbent was replaced by latency improvement: %s", ranks[0].outbound.Tag())
	}
}

func TestSmartDialFailureBypassesLazySwitchConfirmation(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	destination := M.ParseSocksaddr("search.example:443")
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	smart.store.observeDial(time.Now(), networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)
	smart.store.observeDial(time.Now(), networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 100*time.Millisecond)
	first.dialError = errors.New("node unavailable")
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer (<-second.peers).Close()
	if first.dials.Load() != 1 || second.dials.Load() != 1 {
		t.Fatalf("failure did not fail over in the same request: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != second.Tag() {
		t.Fatalf("successful Surge fallback was not recorded: %s", smart.Now())
	}
}

func TestSmartDataPlaneFailureDemotesSiteCandidateForNextRequest(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("node unavailable"))
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.maxAttempts = 1
	// Keep the ordinary breaker at its production threshold. The test must
	// prove that the short data-plane quarantine, not three repeated failures,
	// removes the incumbent from the next ranking.
	smart.store.breakerFailures = 3
	destination := M.ParseSocksaddr("jp.example:443")
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	smart.store.observeDial(time.Now(), networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 10*time.Millisecond)
	smart.store.observeDial(time.Now(), networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 100*time.Millisecond)
	if _, err := smart.DialContext(context.Background(), N.NetworkTCP, destination); err == nil {
		t.Fatal("expected the dead incumbent dial to fail")
	}
	if first.dials.Load() != 1 || second.dials.Load() != 0 {
		t.Fatalf("unexpected first request dials: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	smart.maxAttempts = 2
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer (<-second.peers).Close()
	if second.dials.Load() != 1 {
		t.Fatalf("Surge tiered retry did not reach the backup: first=%d second=%d", first.dials.Load(), second.dials.Load())
	}
	if smart.Now() != second.Tag() {
		t.Fatalf("successful fallback was not recorded: %s", smart.Now())
	}
}

func TestSmartHedgeWinnerDoesNotMasqueradeAsFailureFailover(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	first.dialDelay = 400 * time.Millisecond
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.attemptTimeout = 900 * time.Millisecond
	destination := M.ParseSocksaddr("search.example:443")
	networkKey := smart.networkFingerprint()
	siteDisplay, siteKey := smartSiteIdentity(nil, destination)
	smart.markSelected(first, networkKey, siteKey, siteDisplay, N.NetworkTCP, nil, 0, false)
	conn, err := smart.DialContext(context.Background(), N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer (<-second.peers).Close()
	if smart.failureFailovers.Load() != 0 {
		t.Fatalf("hedged success was counted as failure failover: %d", smart.failureFailovers.Load())
	}
	if smart.Now() != second.Tag() {
		t.Fatalf("successful hedge winner was not recorded for Surge site history: %s", smart.Now())
	}
}

func TestSmartPerformanceSwitchKeepsEstablishedConnection(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.interruptMode = "selective"
	networkKey := "network"
	siteKey := "site"
	smart.markSelected(first, networkKey, siteKey, "example.com", N.NetworkTCP, nil, 0, false)
	left, right := net.Pipe()
	defer right.Close()
	wrapped := smart.interruptGroup.NewConnWithKey(left, true, false, smartConnectionKey(networkKey, siteKey, N.NetworkTCP, first.Tag()))
	defer wrapped.Close()
	smart.markSelected(second, networkKey, siteKey, "example.com", N.NetworkTCP, nil, 0, false)
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = right.Write([]byte{1}) }()
	buffer := make([]byte, 1)
	if _, err := wrapped.Read(buffer); err != nil {
		t.Fatalf("performance switch interrupted established connection: %v", err)
	}
	if smart.connectionsInterrupted.Load() != 0 {
		t.Fatalf("performance switch reported interrupted connections: %d", smart.connectionsInterrupted.Load())
	}
	if smart.switchesTotal.Load() != 0 || smart.performanceSwitches.Load() != 0 {
		t.Fatalf("Surge per-request rotation was counted as an operational switch: total=%d performance=%d", smart.switchesTotal.Load(), smart.performanceSwitches.Load())
	}
}

func TestSmartAdvisoryOpenRankDoesNotInterruptEstablishedConnection(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	second := newSmartFakeOutbound("second", nil)
	smart := newTestSmart(first, second)
	smart.interruptMode = "all"
	networkKey := "network"
	siteKey := "site"
	smart.markSelected(first, networkKey, siteKey, "example.com", N.NetworkTCP, nil, 0, false)
	left, right := net.Pipe()
	defer right.Close()
	wrapped := smart.interruptGroup.NewConnWithKey(left, true, false, smartConnectionKey(networkKey, siteKey, N.NetworkTCP, first.Tag()))
	defer wrapped.Close()
	ranks := []smartRank{
		{outbound: second, eligible: true, status: adapter.SmartCandidateStatus{Tag: second.Tag(), State: "healthy"}},
		// An advisory ranking state is not an authoritative endpoint circuit.
		{outbound: first, eligible: false, status: adapter.SmartCandidateStatus{Tag: first.Tag(), State: "open"}},
	}
	smart.markSelected(second, networkKey, siteKey, "example.com", N.NetworkTCP, ranks, 0, false)
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = right.Write([]byte{1}) }()
	buffer := make([]byte, 1)
	if _, err := wrapped.Read(buffer); err != nil {
		t.Fatalf("advisory open rank interrupted established connection: %v", err)
	}
	if got := smart.connectionsInterrupted.Load(); got != 0 {
		t.Fatalf("advisory open rank reported %d interrupted connections", got)
	}
	if got := smart.switchesTotal.Load(); got != 0 {
		t.Fatalf("advisory open rank counted %d operational switches", got)
	}
}

func TestSmartSiteIdentityUsesSniffHostForIPDestination(t *testing.T) {
	metadata := &adapter.InboundContext{SniffHost: "www.google.com"}
	display, key := smartSiteIdentity(metadata, M.ParseSocksaddr("142.251.156.119:443"))
	if display != "service:google" || key == "" {
		t.Fatalf("sniffed host was not inherited: display=%q key=%q", display, key)
	}
}

func TestSmartSiteIdentityNormalizesHostSpellings(t *testing.T) {
	variants := []string{"WWW.Example.COM.", "www.example.com:443", "www.example.com"}
	var expectedDisplay, expectedKey string
	for _, variant := range variants {
		metadata := &adapter.InboundContext{SniffHost: variant}
		display, key := smartSiteIdentity(metadata, M.ParseSocksaddr("192.0.2.1:443"))
		if expectedDisplay == "" {
			expectedDisplay, expectedKey = display, key
		}
		if display != expectedDisplay || key != expectedKey {
			t.Fatalf("host spelling %q split site identity: display=%q key=%q, want %q/%q", variant, display, key, expectedDisplay, expectedKey)
		}
	}
	if got := normalizeSmartHostname("Bücher.Example."); got != "xn--bcher-kva.example" {
		t.Fatalf("IDN host normalization = %q", got)
	}
}

func TestSmartGoogleServiceFamilySharesAffinityIdentity(t *testing.T) {
	hosts := []string{
		"www.google.com", "www.googleapis.com",
		"ssl.gstatic.com", "lh3.googleusercontent.com", "mtalk.google.com", "mail.google.com",
	}
	var expectedKey string
	for _, host := range hosts {
		display, key := smartSiteIdentity(nil, M.ParseSocksaddr(host+":443"))
		if display != "service:google" {
			t.Fatalf("Google host %s resolved to %q", host, display)
		}
		if expectedKey == "" {
			expectedKey = key
		} else if key != expectedKey {
			t.Fatalf("Google host %s split affinity: %s != %s", host, key, expectedKey)
		}
	}
}

func TestSmartAccountAndChallengeFamiliesStayStable(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	smart := newTestSmart(first)
	metadata := &adapter.InboundContext{Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.2:1000"), Domain: "chatgpt.com"}
	product, productKey := smart.resolveSmartSiteIdentity(metadata, M.ParseSocksaddr("198.18.0.1:443"))
	metadata.Domain = "challenges.cloudflare.com"
	challenge, challengeKey := smart.resolveSmartSiteIdentity(metadata, M.ParseSocksaddr("198.18.0.2:443"))
	if product != "service:chatgpt_web" || challenge != product || challengeKey != productKey {
		t.Fatalf("Smart challenge lost parent family: product=%q challenge=%q", product, challenge)
	}
	metadata.Domain = "accounts.google.com"
	account, _ := smart.resolveSmartSiteIdentity(metadata, M.ParseSocksaddr("198.18.0.3:443"))
	if account != "service:google_account" {
		t.Fatalf("Google account diagnostic family changed: %q", account)
	}
	_, genericKey := smart.resolveSmartSiteIdentity(nil, M.ParseSocksaddr("www.gstatic.com:443"))
	_, accountKey := smart.resolveSmartSiteIdentity(nil, M.ParseSocksaddr("accounts.google.com:443"))
	if genericKey != accountKey {
		t.Fatalf("Google OAuth and static origins split business health: %q != %q", genericKey, accountKey)
	}
}

func TestSmartChatGPTWebsocketSharesAffinityAcrossClients(t *testing.T) {
	// Source IP is part of the lineage resolver for challenge inheritance, not
	// the Smart selection key. Connections from two clients to the same
	// WebSocket service therefore share one service affinity; they do not get a
	// fresh rendezvous choice merely because their local ports differ.
	variants := []struct {
		source string
		host   string
	}{
		{source: "192.168.0.2:51001", host: "ws.chatgpt.com"},
		{source: "192.168.0.30:51002", host: "WS.CHATGPT.COM."},
	}
	var expectedDisplay, expectedKey string
	for _, variant := range variants {
		metadata := &adapter.InboundContext{
			Inbound: "JP-in",
			Source:  M.ParseSocksaddr(variant.source),
			Domain:  variant.host,
		}
		display, key := smartSiteIdentity(metadata, M.ParseSocksaddr("198.18.0.1:443"))
		if expectedDisplay == "" {
			expectedDisplay, expectedKey = display, key
		}
		if display != "service:chatgpt_web" || display != expectedDisplay || key != expectedKey {
			t.Fatalf("WebSocket service affinity split for source %s: display=%q key=%q, want %q/%q", variant.source, display, key, expectedDisplay, expectedKey)
		}
	}
}

func TestSmartOpenAISubservicesShareSelectionButIsolateHealth(t *testing.T) {
	webDisplay, webKey := smartSiteIdentity(nil, M.ParseSocksaddr("chatgpt.com:443"))
	apiDisplay, apiKey := smartSiteIdentity(nil, M.ParseSocksaddr("api.openai.com:443"))
	if webDisplay == apiDisplay || webKey == apiKey {
		t.Fatalf("subservice metric identities collapsed: web=%q/%q api=%q/%q", webDisplay, webKey, apiDisplay, apiKey)
	}
	webBusiness := smartBusinessSelectionKey("network", webKey, N.NetworkTCP)
	apiBusiness := smartBusinessSelectionKey("network", apiKey, N.NetworkTCP)
	if webBusiness != apiBusiness {
		t.Fatalf("OpenAI subservices did not share business primary: web=%q api=%q", webBusiness, apiBusiness)
	}
	if webBusiness != smartBusinessSelectionKey("network", apiKey, N.NetworkUDP) {
		t.Fatal("OpenAI business primary split by transport")
	}

	store := newSmartStore(time.Hour, 1, time.Minute)
	now := time.Now()
	store.quarantineDataPlaneFailure(now, "network", webKey, "candidate", N.NetworkTCP, time.Minute)
	if !store.candidateDead("network", webKey, "candidate", N.NetworkTCP, now) {
		t.Fatal("web subservice quarantine was not applied")
	}
	if store.candidateDead("network", apiKey, "candidate", N.NetworkTCP, now) {
		t.Fatal("web subservice quarantine contaminated API health")
	}
}

func TestSmartOpenAISubservicesUseOneBusinessPrimary(t *testing.T) {
	primary := newSmartFakeOutbound("primary", nil)
	alternate := newSmartFakeOutbound("alternate", nil)
	smart := newTestSmart(primary, alternate)
	networkKey := smart.networkFingerprint()
	webDestination := M.ParseSocksaddr("chatgpt.com:443")
	apiDestination := M.ParseSocksaddr("api.openai.com:443")
	webDisplay, webKey := smartSiteIdentity(nil, webDestination)
	_, apiKey := smartSiteIdentity(nil, apiDestination)
	now := time.Now()
	for range 10 {
		smart.store.observeDial(now, networkKey, webKey, primary.Tag(), N.NetworkTCP, true, 30*time.Millisecond)
		smart.store.observeDial(now, networkKey, webKey, alternate.Tag(), N.NetworkTCP, true, 80*time.Millisecond)
		// The API has a locally faster alternate. It must still inherit the
		// healthy business primary chosen by the web subservice.
		smart.store.observeDial(now, networkKey, apiKey, primary.Tag(), N.NetworkTCP, true, 80*time.Millisecond)
		smart.store.observeDial(now, networkKey, apiKey, alternate.Tag(), N.NetworkTCP, true, 30*time.Millisecond)
	}
	webRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, webDestination)
	smart.markSelected(primary, networkKey, webKey, webDisplay, N.NetworkTCP, webRanks, 0, false)
	apiRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, apiDestination)
	if got := apiRanks[0].outbound.Tag(); got != primary.Tag() {
		t.Fatalf("business primary was not retained across subservices: %s", got)
	}
}

func TestSmartTelegramIPUsesDomainBusinessPrimary(t *testing.T) {
	domainDisplay, domainKey := smartSiteIdentity(nil, M.ParseSocksaddr("telegram.org:443"))
	ipDisplay, ipKey := smartSiteIdentity(nil, M.ParseSocksaddr("149.154.167.43:443"))
	if domainDisplay != "service:telegram" || ipDisplay != domainDisplay || ipKey != domainKey {
		t.Fatalf("Telegram domain/IP were split: domain=%q/%q ip=%q/%q", domainDisplay, domainKey, ipDisplay, ipKey)
	}
}

func TestSmartApplicationFeatureFillsIPOnlyBusiness(t *testing.T) {
	smart := newTestSmart(newSmartFakeOutbound("node", nil))
	metadata := &adapter.InboundContext{
		Network:     N.NetworkUDP,
		Protocol:    "k3:telegram",
		Destination: M.ParseSocksaddr("1.1.1.1:443"),
	}
	display, featureKey := smart.resolveSmartSiteIdentity(metadata, metadata.Destination)
	_, domainKey := smart.resolveSmartSiteIdentity(nil, M.ParseSocksaddr("telegram.org:443"))
	if display != "service:telegram" || featureKey != domainKey {
		t.Fatalf("application feature did not join Telegram business: %q/%q want key %q", display, featureKey, domainKey)
	}
}

func TestSmartGoogleProductsKeepIndependentFamilies(t *testing.T) {
	tests := map[string]string{
		"www.youtube.com":                   "service:youtube",
		"r1.googlevideo.com":                "service:youtube",
		"gemini.google.com":                 "service:gemini",
		"generativelanguage.googleapis.com": "service:gemini",
	}
	keys := make(map[string]string)
	for host, expected := range tests {
		display, key := smartSiteIdentity(nil, M.ParseSocksaddr(host+":443"))
		if display != expected {
			t.Fatalf("host %s resolved to %q, want %q", host, display, expected)
		}
		keys[expected] = key
	}
	if keys["service:youtube"] == keys["service:gemini"] {
		t.Fatal("YouTube and Gemini unexpectedly share one affinity family")
	}
}

func TestSmartRanksTCPAndUDPIndependently(t *testing.T) {
	first := newSmartFakeOutboundNetworks("first", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	second := newSmartFakeOutboundNetworks("second", []string{N.NetworkTCP, N.NetworkUDP}, nil)
	smart := newTestSmart(first, second)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	_, siteKey := smartSiteIdentity(nil, M.ParseSocksaddr("game.example:443"))
	for range 10 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkTCP, true, 30*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkTCP, true, 100*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, "second", N.NetworkUDP, true, 35*time.Millisecond)
	}
	smart.store.breakerFailures = 3
	for range 3 {
		smart.store.observeDial(now, networkKey, siteKey, "first", N.NetworkUDP, false, time.Second)
	}
	tcpRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("game.example:443"))
	udpRanks, _, _, _ := smart.rank(context.Background(), N.NetworkUDP, M.ParseSocksaddr("game.example:443"))
	if tcpRanks[0].outbound.Tag() != "first" {
		t.Fatalf("expected first for TCP, got %s", tcpRanks[0].outbound.Tag())
	}
	if udpRanks[0].outbound.Tag() != "second" {
		t.Fatalf("expected second for UDP, got %s", udpRanks[0].outbound.Tag())
	}
}

func TestSmartBulkSitePrefersSustainedThroughput(t *testing.T) {
	lowLatency := newSmartFakeOutbound("low-latency", nil)
	highThroughput := newSmartFakeOutbound("high-throughput", nil)
	smart := newTestSmart(lowLatency, highThroughput)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("video.example:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 12 {
		smart.store.observeDial(now, networkKey, siteKey, lowLatency.Tag(), N.NetworkTCP, true, 25*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, highThroughput.Tag(), N.NetworkTCP, true, 130*time.Millisecond)
	}
	for range 3 {
		smart.store.observeThroughput(now, networkKey, siteKey, lowLatency.Tag(), N.NetworkTCP, 512*1024, 2*time.Second)
		smart.store.observeThroughput(now, networkKey, siteKey, highThroughput.Tag(), N.NetworkTCP, 64*1024*1024, 2*time.Second)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if ranks[0].profile != smartProfileBulk {
		t.Fatalf("expected bulk profile, got %s", ranks[0].profile)
	}
	if ranks[0].outbound.Tag() != lowLatency.Tag() {
		t.Fatalf("Surge delay/loss score should prefer low-latency candidate, got %s", ranks[0].outbound.Tag())
	}
	unrelatedRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("bank.example:443"))
	if unrelatedRanks[0].profile != smartProfileInteractive {
		t.Fatalf("bulk profile leaked to an unrelated site: %s", unrelatedRanks[0].profile)
	}
}

func TestSmartBulkLowThroughputDoesNotStrandGroup(t *testing.T) {
	first := newSmartFakeOutbound("bulk-low-first", nil)
	second := newSmartFakeOutbound("bulk-low-second", nil)
	smart := newTestSmart(first, second)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("video.example:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 8 {
		smart.store.observeDial(now, networkKey, siteKey, first.Tag(), N.NetworkTCP, true, 40*time.Millisecond)
		smart.store.observeDial(now, networkKey, siteKey, second.Tag(), N.NetworkTCP, true, 60*time.Millisecond)
	}
	for range 3 {
		smart.store.observeThroughput(now, networkKey, siteKey, first.Tag(), N.NetworkTCP, 64*1024, 2*time.Second)
		smart.store.observeThroughput(now, networkKey, siteKey, second.Tag(), N.NetworkTCP, 96*1024, 2*time.Second)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if len(ranks) != 2 || !hasEligibleSmartRank(ranks) {
		t.Fatalf("low bulk throughput stranded the group: %+v", ranks)
	}
	for _, rank := range ranks {
		if rank.status.State == "open" || !rank.eligible {
			t.Fatalf("advisory throughput signal became a hard gate: %+v", rank.status)
		}
	}
}

func TestSmartProbeSuppressesCommonFailure(t *testing.T) {
	first := newSmartFakeOutbound("first", errors.New("offline"))
	second := newSmartFakeOutbound("second", errors.New("offline"))
	smart := newTestSmart(first, second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := smart.probe(ctx); err == nil {
		t.Fatal("expected all-probe failure")
	}
	networkKey := smart.networkFingerprint()
	for _, candidate := range []string{"first", "second"} {
		estimate := smart.store.estimate(time.Now(), networkKey, "", candidate, N.NetworkTCP, smart.minSamples)
		if estimate.State != "unknown" {
			t.Fatalf("common failure penalized %s: %s", candidate, estimate.State)
		}
	}
}

func TestSmartHalfOpenAllowsOneRecoveryTrial(t *testing.T) {
	candidate := newSmartFakeOutbound("candidate", nil)
	smart := newTestSmart(candidate)
	rank := smartRank{
		outbound: candidate,
		status: adapter.SmartCandidateStatus{
			State: "half_open",
		},
	}
	if !smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("first half-open trial was not reserved")
	}
	if smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("second concurrent half-open trial was admitted")
	}
	smart.releaseHalfOpen(candidate.Tag(), "network", "site", N.NetworkTCP)
	if !smart.reserveHalfOpen(rank, "network", "site", N.NetworkTCP) {
		t.Fatal("half-open trial did not become available after release")
	}
}

func TestSmartObservedConnKeepsExtendedCounters(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var firstByte atomic.Int32
	var closedBytes atomic.Int64
	observed := newSmartObservedConn(local, time.Now(), func(time.Duration) {
		firstByte.Add(1)
	}, func(bytes int64, _ time.Duration) {
		closedBytes.Store(bytes)
	}, nil)
	if _, loaded := observed.(N.ExtendedConn); !loaded {
		t.Fatal("observed connection lost ExtendedConn support")
	}
	if _, loaded := observed.(N.ReadCounter); !loaded {
		t.Fatal("observed connection does not expose read counters")
	}
	if _, loaded := observed.(N.WriteCounter); !loaded {
		t.Fatal("observed connection does not expose write counters")
	}
	go func() {
		_, _ = peer.Write([]byte("reply"))
	}()
	buffer := make([]byte, 5)
	if _, err := observed.Read(buffer); err != nil {
		t.Fatal(err)
	}
	go func() {
		readBuffer := make([]byte, 7)
		_, _ = peer.Read(readBuffer)
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	if firstByte.Load() != 1 {
		t.Fatalf("first byte observed %d times", firstByte.Load())
	}
	if closedBytes.Load() != 12 {
		t.Fatalf("unexpected observed byte count: %d", closedBytes.Load())
	}
}

func TestSmartObservedConnWakesOnceOnEstablishedTimeout(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConn(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	})
	if err := observed.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	for range 2 {
		if _, err := observed.Read(buffer); err == nil {
			t.Fatal("expected read timeout")
		}
	}
	if failures.Load() != 1 {
		t.Fatalf("expected one coalesced recovery wake, got %d", failures.Load())
	}
}

func TestSmartObservedConnWakesOnFirstResponseStall(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConnWithStall(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	}, 20*time.Millisecond)
	go func() {
		// net.Pipe.Write blocks until the complete payload is consumed. Read the
		// full request here so the test exercises the stall timer instead of
		// deadlocking in the transport write.
		buffer := make([]byte, len("request"))
		_, _ = peer.Read(buffer)
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if failures.Load() != 1 {
		t.Fatalf("expected one first-response stall wake, got %d", failures.Load())
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSmartObservedConnCancelsStallAfterFirstByte(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConnWithStall(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	}, 30*time.Millisecond)
	go func() {
		buffer := make([]byte, 7)
		_, _ = peer.Read(buffer)
		_, _ = peer.Write([]byte("reply"))
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := observed.Read(buffer); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if failures.Load() != 0 {
		t.Fatalf("first byte should cancel stall wake, got %d", failures.Load())
	}
	_ = observed.Close()
}

func TestSmartObservedConnWakesOnEstablishedResponseStall(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConnWithStall(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	}, 30*time.Millisecond)
	go func() {
		request := make([]byte, len("request-1"))
		_, _ = peer.Read(request)
		_, _ = peer.Write([]byte("reply-1"))
		request = make([]byte, len("request-2"))
		_, _ = peer.Read(request)
	}()
	if _, err := observed.Write([]byte("request-1")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("reply-1"))
	if _, err := observed.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if _, err := observed.Write([]byte("request-2")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Millisecond)
	if failures.Load() != 1 {
		t.Fatalf("expected one established response stall wake, got %d", failures.Load())
	}
	_ = observed.Close()
}

func TestSmartObservedConnDoesNotWakeOnEstablishedIdle(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConnWithStall(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	}, 30*time.Millisecond)
	go func() {
		request := make([]byte, len("request"))
		_, _ = peer.Read(request)
		_, _ = peer.Write([]byte("reply"))
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("reply"))
	if _, err := observed.Read(buffer); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Millisecond)
	if failures.Load() != 0 {
		t.Fatalf("idle established connection incorrectly woke recovery, got %d", failures.Load())
	}
	_ = observed.Close()
}

func TestSmartObservedConnCancelsStallOnTerminalRead(t *testing.T) {
	local, peer := net.Pipe()
	var failures atomic.Int32
	observed := newSmartObservedConnWithStall(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	}, 30*time.Millisecond)
	go func() {
		request := make([]byte, len("request"))
		_, _ = peer.Read(request)
		_ = peer.Close()
	}()
	if _, err := observed.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := observed.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("expected terminal EOF, got %v", err)
	}
	time.Sleep(90 * time.Millisecond)
	if failures.Load() != 0 {
		t.Fatalf("terminal read incorrectly woke recovery, got %d", failures.Load())
	}
	_ = observed.Close()
}

func TestSmartStatusTracksIndependentContexts(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	smart := newTestSmart(first)
	ranks := []smartRank{{outbound: first, status: adapter.SmartCandidateStatus{Tag: "first", State: "healthy"}, profile: smartProfileInteractive}}
	smart.updateStatusSelected("network", "site-a", N.NetworkTCP, ranks, "first", "tcp ok")
	smart.updateStatusSelected("network", "site-b", N.NetworkUDP, ranks, "first", "udp ok")
	status := smart.SmartStatus()
	if len(status.Contexts) != 2 {
		t.Fatalf("expected two independent contexts, got %d", len(status.Contexts))
	}
	if status.Contexts[0].Transport != N.NetworkTCP || status.Contexts[1].Transport != N.NetworkUDP {
		t.Fatalf("unexpected context transports: %#v", status.Contexts)
	}
}

func TestSmartStatusKeepsPerBusinessEndpointSelection(t *testing.T) {
	// Both candidates belong to this one Smart group. Business contexts may
	// choose different leaves inside the group, but never draw from another
	// Smart group's catalog.
	first := newSmartFakeOutbound("group-a/node-1", nil)
	second := newSmartFakeOutbound("group-a/node-2", nil)
	smart := newTestSmart(first, second)
	setSmartCandidateIdentities(smart, map[string]string{
		first.Tag():  "trojan://node-1.example:443",
		second.Tag(): "trojan://node-2.example:443",
	})
	ranks := []smartRank{
		{outbound: first, identity: "trojan://node-1.example:443", policyID: smartPolicyID("trojan://node-1.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: first.Tag(), State: "healthy"}, profile: smartProfileInteractive},
		{outbound: second, identity: "trojan://node-2.example:443", policyID: smartPolicyID("trojan://node-2.example:443"), eligible: true, status: adapter.SmartCandidateStatus{Tag: second.Tag(), State: "healthy"}, profile: smartProfileInteractive},
	}
	smart.updateStatusSelected("network", "service:search", N.NetworkTCP, ranks, first.Tag(), "node 1 path")
	smart.updateStatusSelected("network", "service:chat", N.NetworkTCP, ranks, second.Tag(), "node 2 path")
	status := smart.SmartStatus()
	if len(status.Contexts) != 2 {
		t.Fatalf("expected two business contexts, got %d", len(status.Contexts))
	}
	seen := make(map[string]string, len(status.Contexts))
	for _, contextStatus := range status.Contexts {
		seen[contextStatus.Site] = contextStatus.SelectedEndpointID
	}
	if seen["service:search"] != smartEndpointID(ranks[0].identity, ranks[0].policyID) || seen["service:chat"] != smartEndpointID(ranks[1].identity, ranks[1].policyID) {
		t.Fatalf("business selections were not kept independently: %#v", seen)
	}
	if status.Selected != second.Tag() || status.SelectedEndpointID != smartEndpointID(ranks[1].identity, ranks[1].policyID) {
		t.Fatalf("latest group snapshot did not reflect last context: %q / %q", status.Selected, status.SelectedEndpointID)
	}
}

func TestSmartPreMatchUsesBusinessContextSelection(t *testing.T) {
	first := newSmartFakeOutbound("group-a/node-1", nil)
	second := newSmartFakeOutbound("group-a/node-2", nil)
	smart := newTestSmart(first, second)
	destination := M.ParseSocksaddr("search.example:443")
	metadata := &adapter.InboundContext{Network: N.NetworkTCP, Destination: destination}
	_, siteKey := resolveSmartSiteIdentity(nil, metadata, destination)
	contextKey := smartBusinessSelectionKey(smart.networkFingerprint(), siteKey, N.NetworkTCP)
	smart.access.Lock()
	smart.lastSelected[contextKey] = second.Tag()
	smart.latest.Store(first)
	smart.access.Unlock()
	if got := smart.preMatchLeaf(metadata); got == nil || got.Tag() != second.Tag() {
		t.Fatalf("pre-match ignored business context selection: %v", got)
	}
}

func TestSmartBusinessContextCannotSelectOutsideGroup(t *testing.T) {
	local := newSmartFakeOutbound("group-a/node-1", nil)
	foreign := newSmartFakeOutbound("group-b/node-1", nil)
	smart := newTestSmart(local)
	if smart.SelectOutbound(foreign.Tag()) {
		t.Fatalf("accepted candidate from another Smart group: %q", foreign.Tag())
	}
	destination := M.ParseSocksaddr("search.example:443")
	metadata := &adapter.InboundContext{Network: N.NetworkTCP, Destination: destination}
	_, siteKey := resolveSmartSiteIdentity(nil, metadata, destination)
	contextKey := smartBusinessSelectionKey(smart.networkFingerprint(), siteKey, N.NetworkTCP)
	smart.access.Lock()
	smart.lastSelected[contextKey] = foreign.Tag()
	smart.access.Unlock()
	if got := smart.preMatchLeaf(metadata); got == nil || got.Tag() != local.Tag() {
		t.Fatalf("pre-match escaped group boundary: %v", got)
	}
}

func TestSmartStatusExposesPrimaryBackupAndStandbyRoles(t *testing.T) {
	primary := newSmartFakeOutbound("primary", nil)
	backup := newSmartFakeOutbound("backup", nil)
	standby := newSmartFakeOutbound("standby", nil)
	smart := newTestSmart(primary, backup, standby)
	ranks := []smartRank{
		{outbound: primary, eligible: true, status: adapter.SmartCandidateStatus{Tag: primary.Tag(), State: "healthy"}, profile: smartProfileInteractive},
		{outbound: backup, eligible: true, status: adapter.SmartCandidateStatus{Tag: backup.Tag(), State: "suspect"}, profile: smartProfileInteractive},
		{outbound: standby, eligible: false, status: adapter.SmartCandidateStatus{Tag: standby.Tag(), State: "open"}, profile: smartProfileInteractive},
	}
	smart.updateStatusSelected("network", "site", N.NetworkTCP, ranks, primary.Tag(), "ranked")
	status := smart.SmartStatus()
	if len(status.Candidates) != 3 {
		t.Fatalf("unexpected status candidates: %+v", status.Candidates)
	}
	if status.Candidates[0].Role != "primary" || status.Candidates[1].Role != "backup" || status.Candidates[2].Role != "standby" {
		t.Fatalf("unexpected primary/backup roles: %+v", status.Candidates)
	}
}

func TestSmartStatusCoalescesIdenticalDecision(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	smart := newTestSmart(first)
	ranks := []smartRank{{outbound: first, status: adapter.SmartCandidateStatus{Tag: "first", State: "healthy"}, profile: smartProfileInteractive}}
	smart.updateStatusSelected("network", "site-a", N.NetworkTCP, ranks, "first", "tcp ok")
	initial := smart.SmartStatus().UpdatedAt
	smart.updateStatusSelected("network", "site-a", N.NetworkTCP, ranks, "first", "tcp ok")
	coalesced := smart.SmartStatus().UpdatedAt
	if !coalesced.Equal(initial) {
		t.Fatalf("identical status update was republished: initial=%v current=%v", initial, coalesced)
	}
	smart.updateStatusSelected("network", "site-a", N.NetworkTCP, ranks, "first", "tcp recovered")
	changed := smart.SmartStatus().UpdatedAt
	if !changed.After(initial) {
		t.Fatalf("changed status update was not published: initial=%v current=%v", initial, changed)
	}
}

func TestSmartStatusExposesPolicyBackendContract(t *testing.T) {
	smart := newTestSmart(newSmartFakeOutbound("first", nil))
	status := smart.SmartStatus()
	if status.PolicyBackend != smartPolicyBackendName() {
		t.Fatalf("status backend=%q, want %q", status.PolicyBackend, smartPolicyBackendName())
	}
	if status.PolicyBackendRequired != smartPolicyBackendRequired() {
		t.Fatalf("status backend required=%t, want %t", status.PolicyBackendRequired, smartPolicyBackendRequired())
	}
	if status.PolicyBackendAvailable != (smart.policyBackend != nil) {
		t.Fatalf("status backend available=%t, actual=%t", status.PolicyBackendAvailable, smart.policyBackend != nil)
	}
}

func TestSmartObservedConnIgnoresNormalEOF(t *testing.T) {
	local, peer := net.Pipe()
	var failures atomic.Int32
	observed := newSmartObservedConn(local, time.Now(), nil, nil, func() {
		failures.Add(1)
	})
	_ = peer.Close()
	buffer := make([]byte, 1)
	if _, err := observed.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	if failures.Load() != 0 {
		t.Fatalf("normal EOF woke recovery %d times", failures.Load())
	}
}

func TestSmartObservedConnClassifiesProtocolHandshakeFailures(t *testing.T) {
	positive := []string{
		// VLESS / VMess.
		"connection download closed: unknown version: 72",
		"bad response header",
		"vmess: invalid chunk checksum",
		"bad header type",
		"unknown protobuf message header: 9",
		"unknown UUID: deadbeef",
		"unknown flow: xtls-rprx-vision",
		"bad version",
		"replayed request",

		// Trojan / Shadowsocks / Shadowsocks 2022.
		"bad request size",
		"salt not unique",
		"server session changed more than once during the last minute",
		"shadowsocks: unsupported method chacha20",

		// TUIC / Hysteria / Hysteria2.
		"v2ray-http: unexpected status: 502 Bad Gateway",
		"v2ray-grpc: unexpected status: 403 Forbidden",
		"hysteria2: authentication failed, status code: 401",
		"authentication: token mismatch",
		"authentication failed, auth_str=deadbeef",
		"unsupported stream command 9",
		"invalid dissociate message",
		"unknown session ID: 7",
		"UDP disabled by server",

		// SOCKS / HTTP CONNECT.
		"unknown socks version: 4",
		"socks5: incorrect user name or password",
		"socks5: unsupported auth method: 2",
		"socks4: authentication failed, username=bad",
		"socks5: authentication failed, username=bad",
		"socks4: udp unsupported",
		"socks5: unsupported command 3",
		"authentication required",
		"http: authentication failed, no Proxy-Authorization header",

		// Snell / SSH / OpenVPN / OpenConnect.
		"snell: bad header version",
		"snell: unsupported command",
		"snell: invalid udp tunnel request",
		"snell: server error 2: bad key",
		"ssh: handshake failed: ssh: no common algorithm",
		"ssh: unable to authenticate, attempted methods none",
		"host key mismatch, server send ssh-ed25519",
		"no shared cipher",
		"cipher negotiation failed with peer",
		"invalid tls-crypt packet",
		"invalid tls-auth packet",
		"invalid tls-crypt-v2 packet",
		"invalid tls data packet hmac",
		"replayed tls stream data packet",
		"invalid gcm payload",
		"invalid static key payload hmac",
		"invalid OpenVPN push reply fields",
		"invalid openconnect authentication response",
		"invalid openconnect browser authentication result",
		"protocol behavior is not supported",
		"invalid CSTP packet header",
		"invalid CSTP HTTP headers",
		"invalid CSTP HTTP status line",
		"received unknown CSTP packet type",
		"authentication failed",
		"authorization failed",

		// AnyTLS and the QUIC protocol error envelope.
		"cipher: message authentication failed",
		"remote error: authentication failed",
		"anytls: remote: invalid session",
		"unknown user password",
		"invalid request",
	}
	for _, message := range positive {
		if !isSmartStreamFailure(errors.New(message), true) {
			t.Errorf("protocol handshake failure was not classified: %q", message)
		}
	}

	negative := []string{
		"403 Forbidden",
		"429 Too Many Requests",
		"unexpected status: 502 Bad Gateway",
		"method not allowed",
		"socks5: request rejected, code=5",
		"connection closed by peer",
		"remote EOF",
		"tls: bad certificate",
		"x509: certificate signed by unknown authority",
		"i/o timeout",
		"context deadline exceeded",
	}
	for _, message := range negative {
		if isSmartStreamFailure(errors.New(message), true) {
			t.Errorf("non-handshake error was classified: %q", message)
		}
	}
	for _, message := range positive {
		if !isSmartStreamFailure(errors.New(message), false) {
			t.Errorf("protocol failure was lost after invalid response bytes: %q", message)
		}
	}
}

type smartProtocolErrorConn struct {
	net.Conn
	err error
}

func (c *smartProtocolErrorConn) Read([]byte) (int, error) {
	// Return one byte together with the protocol error.  This models a proxy
	// reader consuming an invalid version byte before it can report the error.
	return 1, c.err
}

func TestSmartObservedConnClassifiesErrorsThroughUnwrappedCopy(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	var failures atomic.Int32
	observed := newSmartObservedConn(&smartProtocolErrorConn{
		Conn: local,
		err:  errors.New("connection download closed: unknown version: 72"),
	}, time.Now(), nil, nil, func() {
		failures.Add(1)
	})

	_, err := bufio.CopyWithIncreateBuffer(io.Discard, observed, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	if err == nil || !strings.Contains(err.Error(), "unknown version: 72") {
		t.Fatalf("copy returned %v, want protocol error", err)
	}
	if failures.Load() != 1 {
		t.Fatalf("unwrapped copy lost protocol failure, got %d callbacks", failures.Load())
	}
}

func TestSmartObservedConnReportsProtocolFailureType(t *testing.T) {
	var failureType string
	observed := newSmartObservedConnWithRetransmitReason(&smartProtocolErrorConn{err: errors.New("connection download closed: unknown version: 72")}, time.Now(), nil, nil, nil, nil, func(value string) {
		failureType = value
	}, 0)
	_, _ = observed.Read(make([]byte, 1))
	if failureType != "protocol" {
		t.Fatalf("failure type=%q, want protocol", failureType)
	}
}

func TestSmartObservedConnIgnoresExpiredRequestDeadline(t *testing.T) {
	requestCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var failures atomic.Int32
	observed := newSmartObservedConnWithRetransmit(&smartProtocolErrorConn{err: context.DeadlineExceeded}, time.Now(), nil, nil, nil, func() {
		failures.Add(1)
	}, 0, requestCtx)
	_, err := observed.Read(make([]byte, 1))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read error=%v, want request deadline", err)
	}
	if failures.Load() != 0 {
		t.Fatalf("expired request deadline was recorded as node failure: %d", failures.Load())
	}
}

func TestSmartObservedPacketConnIgnoresExpiredRequestDeadline(t *testing.T) {
	requestCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var failures atomic.Int32
	conn := newSmartObservedPacketConnWithWatchdogThreshold(&smartObservedTestPacketConn{}, time.Now(), true, 1, 20*time.Millisecond, func(time.Duration) {
		failures.Add(1)
	}, requestCtx)
	if _, err := conn.WriteTo([]byte("dns"), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if failures.Load() != 0 {
		t.Fatalf("expired request deadline was recorded as UDP node failure: %d", failures.Load())
	}
}

func TestSmartRanksLargeCandidatePool(t *testing.T) {
	const candidateCount = 1000
	candidates := make([]adapter.Outbound, 0, candidateCount)
	for index := range candidateCount {
		candidates = append(candidates, newSmartFakeOutbound("candidate-"+strconv.Itoa(index), nil))
	}
	smart := newTestSmart(candidates...)
	now := time.Now()
	networkKey := smart.networkFingerprint()
	destination := M.ParseSocksaddr("pool.example:443")
	_, siteKey := smartSiteIdentity(nil, destination)
	for range 20 {
		smart.store.observeDial(now, networkKey, siteKey, "candidate-999", N.NetworkTCP, true, 15*time.Millisecond)
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
	if len(ranks) != candidateCount {
		t.Fatalf("expected %d candidates, got %d", candidateCount, len(ranks))
	}
	if ranks[0].outbound.Tag() != "candidate-999" {
		t.Fatalf("known healthy candidate did not lead the pool: %s", ranks[0].outbound.Tag())
	}
	status := smart.SmartStatus()
	if status.CandidateCount != candidateCount {
		t.Fatalf("status candidate count mismatch: %d", status.CandidateCount)
	}
	if len(status.Candidates) != smartStatusCandidateLimit {
		t.Fatalf("status snapshot was not bounded: %d", len(status.Candidates))
	}
}

func TestSmartNestedGroupsExpandToUniqueLeaves(t *testing.T) {
	leafA := newSmartFakeOutbound("leaf-a", nil)
	leafB := newSmartFakeOutbound("leaf-b", nil)
	groupA := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("group-a", nil),
		children:          []string{"leaf-a", "group-b"},
	}
	groupB := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("group-b", nil),
		children:          []string{"leaf-b", "group-a", "leaf-a"},
	}
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{
		"leaf-a":  leafA,
		"leaf-b":  leafB,
		"group-a": groupA,
		"group-b": groupB,
	}}
	smart := newTestSmart()
	smart.outbound = manager
	var leaves []adapter.Outbound
	smart.flattenCandidate(groupA, make(map[string]bool), make(map[string]bool), &leaves)
	if len(leaves) != 2 {
		t.Fatalf("expected two unique leaves, got %d", len(leaves))
	}
	if leaves[0].Tag() != "leaf-a" || leaves[1].Tag() != "leaf-b" {
		t.Fatalf("unexpected leaf order: %s, %s", leaves[0].Tag(), leaves[1].Tag())
	}
}

func TestSmartManualNodeExclusionFiltersNestedLeaves(t *testing.T) {
	keep := newSmartFakeOutbound("airport/美国-普通节点", nil)
	excludedKeyword := newSmartFakeOutbound("airport/美国-Gcore-01", nil)
	excludedExact := newSmartFakeOutbound("airport/完整节点名", nil)
	group := &smartFakeGroup{
		smartFakeOutbound: newSmartFakeOutbound("provider/group", nil),
		children:          []string{keep.Tag(), excludedKeyword.Tag(), excludedExact.Tag()},
	}
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{
		keep.Tag(): keep, excludedKeyword.Tag(): excludedKeyword, excludedExact.Tag(): excludedExact, group.Tag(): group,
	}}
	matcher, err := nodefilter.New([]string{"Gcore", "=" + excludedExact.Tag()})
	if err != nil {
		t.Fatal(err)
	}
	smart := newTestSmart()
	smart.outbound = manager
	smart.manualExclude = matcher
	var leaves []adapter.Outbound
	smart.flattenCandidate(group, make(map[string]bool), make(map[string]bool), &leaves)
	if len(leaves) != 1 || leaves[0].Tag() != keep.Tag() {
		t.Fatalf("manual exclusion did not filter nested leaves: %+v", leaves)
	}
}

func TestSmartNetworkFingerprintUsesSubnetAndDNS(t *testing.T) {
	base := &adapter.NetworkInterface{
		Interface: control.Interface{
			Index:        2,
			MTU:          1500,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("2001:db8:1::1234/64"),
				netip.MustParsePrefix("192.0.2.20/24"),
			},
		},
		Type:       C.InterfaceTypeEthernet,
		DNSServers: []string{"1.1.1.1", "8.8.8.8"},
	}
	reordered := *base
	reordered.Addresses = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.99/24"),
		netip.MustParsePrefix("2001:db8:1::abcd/64"),
	}
	reordered.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	first := smartNetworkFingerprint(base, adapter.WIFIState{})
	second := smartNetworkFingerprint(&reordered, adapter.WIFIState{})
	if first != second {
		t.Fatal("address or DNS ordering changed the network fingerprint")
	}
	otherSubnet := reordered
	otherSubnet.Addresses = []netip.Prefix{netip.MustParsePrefix("198.51.100.20/24")}
	if first == smartNetworkFingerprint(&otherSubnet, adapter.WIFIState{}) {
		t.Fatal("different subnet reused the same network fingerprint")
	}
	if first == smartNetworkFingerprint(base, adapter.WIFIState{SSID: "other-network"}) {
		t.Fatal("different Wi-Fi identity reused the same network fingerprint")
	}
}

func BenchmarkSmartRankCandidatePools(b *testing.B) {
	for _, candidateCount := range []int{100, 500, 1000} {
		b.Run(strconv.Itoa(candidateCount), func(b *testing.B) {
			candidates := make([]adapter.Outbound, 0, candidateCount)
			for index := range candidateCount {
				candidates = append(candidates, newSmartFakeOutbound("candidate-"+strconv.Itoa(index), nil))
			}
			smart := newTestSmart(candidates...)
			destination := M.ParseSocksaddr("benchmark.example:443")
			b.ResetTimer()
			for b.Loop() {
				ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, destination)
				if len(ranks) != candidateCount {
					b.Fatal("candidate count changed")
				}
			}
		})
	}
}
