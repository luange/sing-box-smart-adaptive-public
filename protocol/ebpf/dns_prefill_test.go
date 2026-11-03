//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type blockingDNSPrefillRouter struct {
	adapter.Router
	gate  <-chan struct{}
	calls atomic.Int64
}

func (r *blockingDNSPrefillRouter) Rules() []adapter.Rule {
	r.calls.Add(1)
	<-r.gate
	return nil
}

type unusedDNSPrefillOutbounds struct{ adapter.OutboundManager }

func testDNSPrefillWork(key string, router adapter.Router) dnsPrefillWork {
	return dnsPrefillWork{
		key: key, tag: "test", domain: key,
		addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		ttl:   time.Minute, routeRouter: router,
		outbounds: &unusedDNSPrefillOutbounds{}, queuedAt: time.Now(),
	}
}

func waitDNSPrefillActive(t *testing.T, inbound *Inbound, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for inbound.dnsPrefillActive.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("active workers = %d, want %d", inbound.dnsPrefillActive.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDNSPrefillAdmissionIsBounded(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("a", router)) || !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("b", router)) {
		t.Fatal("first two prefill workers should be admitted")
	}
	waitDNSPrefillActive(t, inbound, dnsPrefillWorkerLimit)
	for n := range dnsPrefillQueueLimit {
		if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork(string(rune('c'+n)), router)) {
			t.Fatalf("pending task %d was not admitted", n)
		}
	}
	if inbound.scheduleDNSPrefillWork(testDNSPrefillWork("overflow", router)) {
		t.Fatal("prefill admission exceeded its pending queue bound")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 1 {
		t.Fatalf("unique queue-drop count = %d, want 1", got)
	}
	if got := inbound.dnsPrefillQueued.Load(); got != dnsPrefillQueueLimit {
		t.Fatalf("queued tasks = %d, want %d", got, dnsPrefillQueueLimit)
	}
	if got := inbound.dnsPrefillQueuePeak.Load(); got > dnsPrefillQueueLimit {
		t.Fatalf("queue peak %d exceeded %d", got, dnsPrefillQueueLimit)
	}
	closed := make(chan struct{})
	go func() { inbound.stopDNSPrefill(); close(closed) }()
	close(gate)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("bounded queue did not shut down")
	}
	if len(inbound.dnsPrefillInflight) != 0 || inbound.dnsPrefillActive.Load() != 0 || inbound.dnsPrefillPendingDepth() != 0 {
		t.Fatal("queued or active workers left state behind")
	}
}

func TestDNSPrefillAnswerCallbackDoesNotWaitForBusyWorkers(t *testing.T) {
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	inbound := &Inbound{
		ctx: context.Background(), dnsPrefill: dnsPrefillOptions{enabled: true},
		dnsPrefillRouter: router, dnsPrefillOutbounds: &unusedDNSPrefillOutbounds{},
	}
	t.Cleanup(func() { close(gate); inbound.stopDNSPrefill() })
	done := make(chan struct{})
	go func() {
		for n := range dnsPrefillWorkerLimit + dnsPrefillQueueLimit + 2 {
			inbound.OnDNSAnswer(string(rune('a'+n))+".example", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, false)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DNS answer callback waited for a busy prefill worker")
	}
	if got := inbound.dnsPrefillAdmitted.Load(); got != dnsPrefillWorkerLimit+dnsPrefillQueueLimit {
		t.Fatalf("admitted = %d, want %d", got, dnsPrefillWorkerLimit+dnsPrefillQueueLimit)
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 2 {
		t.Fatalf("full queue rejected %d unique tasks, want 2", got)
	}
}

func TestDNSPrefillQueuedTaskExpiresWithoutRuleEvaluation(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("a", router)) || !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("b", router)) {
		t.Fatal("failed to fill worker budget")
	}
	waitDNSPrefillActive(t, inbound, dnsPrefillWorkerLimit)
	stale := testDNSPrefillWork("stale", router)
	stale.queuedAt = time.Now().Add(-dnsPrefillQueueMaxAge - time.Second)
	if !inbound.scheduleDNSPrefillWork(stale) {
		t.Fatal("stale task was not admitted to the queue")
	}
	close(gate)
	deadline := time.Now().Add(time.Second)
	for inbound.dnsPrefillExpired.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("queued task did not expire")
		}
		time.Sleep(time.Millisecond)
	}
	inbound.stopDNSPrefill()
	if got := router.calls.Load(); got != 2 {
		t.Fatalf("expired task evaluated rules: calls=%d", got)
	}
	if inbound.dnsPrefillQueueDrops.Load() != 0 {
		t.Fatal("expired admitted task was counted as a capacity drop")
	}
}

func TestRemainingDNSPrefillTTLNeverExtendsOriginalAnswer(t *testing.T) {
	if got := remainingDNSPrefillTTL(10*time.Second, 3*time.Second); got != 7*time.Second {
		t.Fatalf("remaining TTL = %v, want 7s", got)
	}
	if got := remainingDNSPrefillTTL(time.Second, 2*time.Second); got != 0 {
		t.Fatalf("expired DNS TTL was extended: %v", got)
	}
}

func TestDNSPrefillCoalescesOnlySameDomainAddressesAndTTL(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	a := netip.MustParseAddr("8.8.8.8")
	b := netip.MustParseAddr("1.1.1.1")
	first := dnsPrefillTaskKey("Example.COM.", []netip.Addr{a, b}, time.Minute)
	if first != dnsPrefillTaskKey("example.com", []netip.Addr{b, a}, time.Minute) {
		t.Fatal("address order or domain spelling changed the task identity")
	}
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork(first, router)) {
		t.Fatal("initial task rejected")
	}
	if inbound.scheduleDNSPrefillWork(testDNSPrefillWork(first, router)) {
		t.Fatal("in-flight duplicate was admitted")
	}
	if got := inbound.dnsPrefillCoalesced.Load(); got != 1 {
		t.Fatalf("duplicate count = %d, want 1", got)
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 0 {
		t.Fatalf("duplicate incorrectly counted as capacity drop: %d", got)
	}
	// Another domain on the same shared IP must still run conflict isolation.
	otherDomain := dnsPrefillTaskKey("proxy.example", []netip.Addr{a, b}, time.Minute)
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork(otherDomain, router)) {
		t.Fatal("different domain sharing an IP was incorrectly coalesced")
	}
	shortTTL := dnsPrefillTaskKey("example.com", []netip.Addr{a, b}, time.Second)
	waitDNSPrefillActive(t, inbound, dnsPrefillWorkerLimit)
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork(shortTTL, router)) {
		t.Fatal("a different TTL must remain independently queued")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 0 {
		t.Fatalf("short TTL was incorrectly dropped: %d", got)
	}
	close(gate)
	inbound.stopDNSPrefill()
	if got := inbound.dnsPrefillPeak.Load(); got != dnsPrefillWorkerLimit {
		t.Fatalf("peak workers = %d, want %d", got, dnsPrefillWorkerLimit)
	}
}

func TestDNSPrefillEarlyFilterDoesNotConsumeWorkerBudget(t *testing.T) {
	inbound := &Inbound{ctx: context.Background(), dnsPrefill: dnsPrefillOptions{enabled: true}}
	inbound.OnDNSAnswer("local.example", []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	if inbound.dnsPrefillFiltered.Load() != 1 || inbound.dnsPrefillAdmitted.Load() != 0 || inbound.dnsPrefillQueueDrops.Load() != 0 {
		t.Fatal("filtered answer consumed capacity or was counted as a drop")
	}
	inbound.OnDNSAnswer("public.example", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, false)
	if inbound.dnsPrefillMissingDeps.Load() != 1 || inbound.dnsPrefillAdmitted.Load() != 0 {
		t.Fatal("missing dependencies consumed capacity")
	}
}

func TestDNSPrefillFakeIPKeepsLifecycleWithoutUsingAdvisorySlots(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("a", router)) || !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("b", router)) {
		t.Fatal("failed to fill advisory worker budget")
	}
	waitDNSPrefillActive(t, inbound, dnsPrefillWorkerLimit)
	inbound.OnDNSAnswer("example.com", []netip.Addr{netip.MustParseAddr("198.18.0.1")}, true)
	if inbound.dnsPrefillQueueDrops.Load() != 0 || inbound.dnsPrefillAdmitted.Load() != 2 {
		t.Fatal("FakeIP consumed or was rejected by the advisory worker budget")
	}
	close(gate)
	inbound.stopDNSPrefill()
}

func TestDNSPrefillConcurrentAdmissionAndClose(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	key := dnsPrefillTaskKey("example.com", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, time.Minute)
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork(key, router)) {
		t.Fatal("initial task rejected")
	}
	var callers sync.WaitGroup
	for range 64 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			inbound.scheduleDNSPrefillWork(testDNSPrefillWork(key, router))
		}()
	}
	callers.Wait()
	close(gate)
	inbound.stopDNSPrefill()
	if inbound.scheduleDNSPrefillWork(testDNSPrefillWork(key, router)) || len(inbound.dnsPrefillInflight) != 0 {
		t.Fatal("closed lifecycle accepted work or retained in-flight state")
	}
}

func TestDNSPrefillStopWaitsForAdmittedWork(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	gate := make(chan struct{})
	router := &blockingDNSPrefillRouter{gate: gate}
	if !inbound.scheduleDNSPrefillWork(testDNSPrefillWork("work", router)) || !inbound.acquireDNSPrefillLifecycle() {
		t.Fatal("failed to admit worker and synchronous callback")
	}
	waitDNSPrefillActive(t, inbound, 1)
	done := make(chan struct{})
	go func() {
		inbound.stopDNSPrefill()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Stop returned before admitted work completed")
	case <-time.After(10 * time.Millisecond):
	}
	close(gate)
	inbound.dnsPrefillWorkers.Done()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not release after work completed")
	}
	if inbound.acquireDNSPrefillLifecycle() || inbound.scheduleDNSPrefillWork(testDNSPrefillWork("new", router)) {
		t.Fatal("Stop left admission open")
	}
}

func TestDNSPrefillRejectsSourceSensitiveGlobalPromotion(t *testing.T) {
	inbound := &Inbound{
		sharedOptions: option.EBPFSharedNetworkOptions{
			PolicyOffload: option.EBPFPolicyOffloadOptions{MACSourcePolicy: true},
		},
	}
	if inbound.dnsPrefillIdentitySafe() {
		t.Fatal("source-sensitive policy must not publish global DNS/IP hints")
	}
	plain := &Inbound{}
	if !plain.dnsPrefillIdentitySafe() {
		t.Fatal("plain policy should allow DNS/IP hints")
	}
}

func TestV3DNSHintDoesNotImplicitlyFollowFakeIP(t *testing.T) {
	newInbound := func() *Inbound {
		return &Inbound{
			sharedNetwork: &sharedNetwork{engineV3: true},
			sharedOptions: option.EBPFSharedNetworkOptions{PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true}},
		}
	}
	base := newInbound()
	if base.v3DNSHintEnabled() {
		t.Fatal("dns_ip_hint=off must not enable real-DNS observation")
	}

	fakeOnly := newInbound()
	fakeOnly.sharedOptions.PolicyOffload.FakeIP = true
	if fakeOnly.v3DNSHintEnabled() {
		t.Fatal("FakeIP-only mode must not enable real-DNS observation")
	}
	if !fakeOnly.v3FakeIPEnabled() {
		t.Fatal("FakeIP-only mode should keep the authoritative FakeIP path enabled")
	}

	strong := newInbound()
	strong.sharedOptions.PolicyOffload.DNSIPHint = "strong"
	if !strong.v3DNSHintEnabled() {
		t.Fatal("dns_ip_hint=strong should enable real-DNS observation")
	}
}

func TestDNSObservationPromotionTTLIsCapped(t *testing.T) {
	if got := dnsObservationPromotionTTL(5*time.Minute, 10); got != 10*time.Second {
		t.Fatalf("short RR TTL=%v", got)
	}
	if got := dnsObservationPromotionTTL(5*time.Minute, 600); got != 5*time.Minute {
		t.Fatalf("configured cap=%v", got)
	}
	if got := dnsObservationPromotionTTL(0, 0); got != 0 {
		t.Fatalf("zero RR TTL must disable promotion, got %v", got)
	}
}
