//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestDNSPrefillAdmissionIsBounded(t *testing.T) {
	var inbound Inbound

	if !inbound.acquireDNSPrefillSlot("a") || !inbound.acquireDNSPrefillSlot("b") {
		t.Fatal("first two prefill workers should be admitted")
	}
	if inbound.acquireDNSPrefillSlot("c") {
		t.Fatal("prefill admission exceeded its worker bound")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 1 {
		t.Fatalf("unexpected queue-drop count: %d", got)
	}

	inbound.releaseDNSPrefillWorker("a")
	if !inbound.acquireDNSPrefillSlot("c") {
		t.Fatal("a worker slot should be reusable after release")
	}
	inbound.releaseDNSPrefillWorker("b")
	inbound.releaseDNSPrefillWorker("c")

	inbound.dnsPrefillClosed.Store(true)
	if inbound.acquireDNSPrefillSlot("a") {
		t.Fatal("closed prefill admission accepted new work")
	}
	if len(inbound.dnsPrefillInflight) != 0 || inbound.dnsPrefillActive.Load() != 0 {
		t.Fatal("workers left in-flight state behind")
	}
}

func TestDNSPrefillCoalescesOnlySameDomainAddressesAndTTL(t *testing.T) {
	var inbound Inbound
	a := netip.MustParseAddr("8.8.8.8")
	b := netip.MustParseAddr("1.1.1.1")
	first := dnsPrefillTaskKey("Example.COM.", []netip.Addr{a, b}, time.Minute)
	if first != dnsPrefillTaskKey("example.com", []netip.Addr{b, a}, time.Minute) {
		t.Fatal("address order or domain spelling changed the task identity")
	}
	if !inbound.acquireDNSPrefillSlot(first) {
		t.Fatal("initial task rejected")
	}
	if inbound.acquireDNSPrefillSlot(first) {
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
	if !inbound.acquireDNSPrefillSlot(otherDomain) {
		t.Fatal("different domain sharing an IP was incorrectly coalesced")
	}
	shortTTL := dnsPrefillTaskKey("example.com", []netip.Addr{a, b}, time.Second)
	if inbound.acquireDNSPrefillSlot(shortTTL) {
		t.Fatal("unique task exceeded the worker bound")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 1 {
		t.Fatalf("unique rejection count = %d, want 1", got)
	}
	inbound.releaseDNSPrefillWorker(first)
	if !inbound.acquireDNSPrefillSlot(shortTTL) {
		t.Fatal("a different TTL must remain independently admissible")
	}
	inbound.releaseDNSPrefillWorker(otherDomain)
	inbound.releaseDNSPrefillWorker(shortTTL)
	if got := inbound.dnsPrefillPeak.Load(); got != dnsPrefillWorkerLimit {
		t.Fatalf("peak workers = %d, want %d", got, dnsPrefillWorkerLimit)
	}
}

func TestDNSPrefillObservationSharesInflightIdentityWithoutWorkerSlot(t *testing.T) {
	var inbound Inbound
	key := dnsPrefillTaskKey("example.com", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, time.Minute)
	if !inbound.claimDNSPrefillObservation(key) {
		t.Fatal("TC observation was not admitted")
	}
	if inbound.acquireDNSPrefillSlot(key) {
		t.Fatal("DNS callback duplicated an in-flight TC observation")
	}
	if got := inbound.dnsPrefillActive.Load(); got != 0 {
		t.Fatalf("TC observation consumed a worker slot: %d", got)
	}
	inbound.releaseDNSPrefillObservation(key)
	if !inbound.acquireDNSPrefillSlot(key) {
		t.Fatal("completed observation left stale in-flight identity")
	}
	inbound.releaseDNSPrefillWorker(key)
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
	var inbound Inbound
	if !inbound.acquireDNSPrefillSlot("a") || !inbound.acquireDNSPrefillSlot("b") {
		t.Fatal("failed to fill advisory worker budget")
	}
	inbound.OnDNSAnswer("example.com", []netip.Addr{netip.MustParseAddr("198.18.0.1")}, true)
	if inbound.dnsPrefillQueueDrops.Load() != 0 || inbound.dnsPrefillAdmitted.Load() != 2 {
		t.Fatal("FakeIP consumed or was rejected by the advisory worker budget")
	}
	inbound.releaseDNSPrefillWorker("a")
	inbound.releaseDNSPrefillWorker("b")
	inbound.dnsPrefillWorkers.Wait()
}

func TestDNSPrefillConcurrentAdmissionAndClose(t *testing.T) {
	var inbound Inbound
	key := dnsPrefillTaskKey("example.com", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, time.Minute)
	if !inbound.acquireDNSPrefillSlot(key) {
		t.Fatal("initial task rejected")
	}
	var callers sync.WaitGroup
	for range 64 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if inbound.acquireDNSPrefillSlot(key) {
				inbound.releaseDNSPrefillWorker(key)
			}
		}()
	}
	callers.Wait()
	inbound.dnsPrefillAccess.Lock()
	inbound.dnsPrefillClosed.Store(true)
	inbound.dnsPrefillAccess.Unlock()
	inbound.releaseDNSPrefillWorker(key)
	inbound.dnsPrefillWorkers.Wait()
	if inbound.acquireDNSPrefillSlot(key) || len(inbound.dnsPrefillInflight) != 0 {
		t.Fatal("closed lifecycle accepted work or retained in-flight state")
	}
}

func TestDNSPrefillStopWaitsForAdmittedWork(t *testing.T) {
	inbound := &Inbound{ctx: context.Background()}
	if !inbound.acquireDNSPrefillSlot("work") || !inbound.acquireDNSPrefillLifecycle() {
		t.Fatal("failed to admit worker and synchronous callback")
	}
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
	inbound.releaseDNSPrefillWorker("work")
	inbound.dnsPrefillWorkers.Done()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not release after work completed")
	}
	if inbound.acquireDNSPrefillLifecycle() || inbound.acquireDNSPrefillSlot("new") {
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
