//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestDNSPrefillAdmissionIsBounded(t *testing.T) {
	var inbound Inbound

	if !inbound.acquireDNSPrefillSlot() || !inbound.acquireDNSPrefillSlot() {
		t.Fatal("first two prefill workers should be admitted")
	}
	if inbound.acquireDNSPrefillSlot() {
		t.Fatal("prefill admission exceeded its worker bound")
	}
	if got := inbound.dnsPrefillQueueDrops.Load(); got != 1 {
		t.Fatalf("unexpected queue-drop count: %d", got)
	}

	inbound.releaseDNSPrefillWorker()
	if !inbound.acquireDNSPrefillSlot() {
		t.Fatal("a worker slot should be reusable after release")
	}
	inbound.releaseDNSPrefillWorker()
	inbound.releaseDNSPrefillWorker()

	inbound.dnsPrefillClosed.Store(true)
	if inbound.acquireDNSPrefillSlot() {
		t.Fatal("closed prefill admission accepted new work")
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
