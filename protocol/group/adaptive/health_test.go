package adaptive

import (
	"sync"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type fakeClock struct {
	access sync.Mutex
	now    time.Time
}

func (c *fakeClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.access.Lock()
	c.now = c.now.Add(duration)
	c.access.Unlock()
}

func newBreakerTestStore() (*HealthStore, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return NewHealthStoreWithClock(time.Hour, 64, clock, BreakerConfig{FailureThreshold: 3, BaseCooldown: 10 * time.Second, MaxCooldown: 40 * time.Second, JitterFraction: 0}), clock
}

func TestHealthStoreIsBoundedAndDeferredIsIgnored(t *testing.T) {
	store := NewHealthStore(time.Hour, 3)
	now := time.Now()
	store.Observe(Observation{NodeID: NodeID{1}, Scope: ScopeEndpoint, Outcome: OutcomeDeferred, At: now})
	if entries, _ := store.Stats(); entries != 0 {
		t.Fatalf("deferred observation created state: %d", entries)
	}
	for index := 1; index <= 5; index++ {
		store.Observe(Observation{NodeID: NodeID{byte(index)}, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, At: now.Add(time.Duration(index) * time.Second)})
	}
	entries, evictions := store.Stats()
	if entries != 3 {
		t.Fatalf("health store exceeded bound: %d", entries)
	}
	if evictions != 2 {
		t.Fatalf("unexpected eviction count: %d", evictions)
	}
}

func TestHealthScopesDoNotContaminateEndpoint(t *testing.T) {
	store := NewHealthStore(time.Hour, 16)
	nodeID := NodeID{1}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: ScopeService, Service: "youtube", Outcome: OutcomeBlocked})
	}
	if status := store.Endpoint(nodeID); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("service failure contaminated endpoint health: %+v", status)
	}
	store.Observe(Observation{NodeID: nodeID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess})
	if status := store.Endpoint(nodeID); status.Health != HealthHealthy || status.Breaker != BreakerClosed {
		t.Fatalf("endpoint success was not recorded: %+v", status)
	}
}

func TestBreakerFailureDomainsAreIsolated(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{1}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainService, Service: "youtube", Outcome: OutcomeBlocked, At: clock.Now()})
	}
	if status := store.Status(nodeID, DomainService, "", "youtube"); status.Breaker != BreakerOpen || status.Health != HealthUnreachable || status.Failures != 3 {
		t.Fatalf("service breaker did not enter cooldown: %+v", status)
	}
	if status := store.Endpoint(nodeID); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("service 403/451 contaminated endpoint breaker: %+v", status)
	}
	if status := store.Status(nodeID, DomainTransport, N.NetworkTCP, ""); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("service failure contaminated transport breaker: %+v", status)
	}
	if status := store.Status(nodeID, DomainService, "", "google"); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("service failure contaminated another service: %+v", status)
	}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainTransport, Transport: N.NetworkTCP, Outcome: OutcomeFailure, At: clock.Now(), Reason: "timeout"})
	}
	if status := store.Status(nodeID, DomainTransport, N.NetworkTCP, ""); status.Breaker != BreakerOpen || status.Health != HealthUnreachable {
		t.Fatalf("transport timeout did not open transport breaker: %+v", status)
	}
	if status := store.Endpoint(nodeID); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("transport timeout contaminated endpoint breaker: %+v", status)
	}
}

func TestTransportPurposeAndIPFamilyBreakersAreIsolated(t *testing.T) {
	store, clock := newBreakerTestStore()
	handle := NodeHandle{NodeID: NodeID{91}, Slot: 1, Version: 1}
	tcp4 := ServiceContext{ID: "site:example.com", Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"}
	tcp6 := ServiceContext{ID: "site:example.com", Transport: N.NetworkTCP, HealthTransport: "tcp/ipv6"}
	udpDNS4 := ServiceContext{ID: "site:example.com", Transport: N.NetworkUDP, HealthTransport: "udp_dns/ipv4"}
	udpData4 := ServiceContext{ID: "site:example.com", Transport: N.NetworkUDP, HealthTransport: "udp_data/ipv4"}
	for range 3 {
		store.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainTransport, Transport: tcp4.HealthTransport, Outcome: OutcomeFailure, At: clock.Now()})
	}
	if store.CanAttemptHandle(handle, tcp4, clock.Now()) {
		t.Fatal("failed TCP/IPv4 path remained available")
	}
	if !store.CanAttemptHandle(handle, tcp6, clock.Now()) {
		t.Fatal("TCP/IPv4 failure contaminated TCP/IPv6")
	}
	for range 3 {
		store.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainTransport, Transport: udpDNS4.HealthTransport, Outcome: OutcomeFailure, At: clock.Now()})
	}
	if store.CanAttemptHandle(handle, udpDNS4, clock.Now()) {
		t.Fatal("failed UDP-DNS/IPv4 path remained available")
	}
	if !store.CanAttemptHandle(handle, udpData4, clock.Now()) {
		t.Fatal("UDP-DNS/IPv4 failure contaminated UDP-Data/IPv4")
	}
}

func TestBreakerHalfOpenRequiresTwoSuccessesAndKeepsSingleToken(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{2}
	service := ServiceContext{ID: "youtube", Transport: N.NetworkTCP}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainService, Service: service.ID, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	first, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
	if !allowed {
		t.Fatal("first recovery attempt was not admitted")
	}
	if _, allowed = store.TryAcquireAttemptPermit(nodeID, service, clock.Now()); allowed {
		t.Fatal("second concurrent recovery attempt bypassed half-open token")
	}
	first.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainService: OutcomeSuccess}, clock.Now(), 25*time.Millisecond, "")
	status := store.Status(nodeID, DomainService, "", service.ID)
	if status.Breaker != BreakerHalfOpen || status.Health != HealthDegraded || status.RecoverySuccesses != 1 || status.Successes != 1 || status.Failures != 3 || status.ConsecutiveFailures != 0 {
		t.Fatalf("first half-open success incorrectly restored the breaker: %+v", status)
	}
	second, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
	if !allowed {
		t.Fatal("second recovery confirmation was not admitted")
	}
	if _, allowed = store.TryAcquireAttemptPermit(nodeID, service, clock.Now()); allowed {
		t.Fatal("concurrent attempt bypassed second recovery token")
	}
	second.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainService: OutcomeSuccess}, clock.Now(), 20*time.Millisecond, "")
	status = store.Status(nodeID, DomainService, "", service.ID)
	if status.Breaker != BreakerClosed || status.Health != HealthHealthy || status.RecoverySuccesses != 0 || status.Successes != 2 || status.Failures != 3 {
		t.Fatalf("second recovery success did not close the breaker: %+v", status)
	}
}

func TestBreakerRecoveryConfirmationFailureReopens(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{22}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainService, Service: service.ID, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	first, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
	if !allowed {
		t.Fatal("first recovery attempt was not admitted")
	}
	first.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainService: OutcomeSuccess}, clock.Now(), 0, "")
	second, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
	if !allowed {
		t.Fatal("second recovery attempt was not admitted")
	}
	second.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainService: OutcomeFailure}, clock.Now(), 0, "still failing")
	status := store.Status(nodeID, DomainService, "", service.ID)
	if status.Breaker != BreakerOpen || status.Health != HealthUnreachable || status.RecoverySuccesses != 0 || status.Backoff != 20*time.Second {
		t.Fatalf("failed recovery confirmation did not reopen with backoff: %+v", status)
	}
}

func TestBreakerStatusIsPureObservation(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{4}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	store.access.RLock()
	record := store.entries[healthKey{nodeID: nodeID, domain: DomainEndpoint}]
	before := *record
	beforeStatus := record.status
	store.access.RUnlock()
	for range 10 {
		_ = store.Endpoint(nodeID)
	}
	store.access.RLock()
	after := *record
	afterStatus := record.status
	store.access.RUnlock()
	if beforeStatus != afterStatus || before.halfOpenToken != after.halfOpenToken || before.consecutiveFailure != after.consecutiveFailure || before.reopenCount != after.reopenCount {
		t.Fatalf("Status mutated breaker state: before=%+v after=%+v", beforeStatus, afterStatus)
	}
}

func TestBreakerLateSuccessCannotCloseNewVersion(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{5}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	old, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
	if !allowed {
		t.Fatal("old attempt was not admitted")
	}
	failures := make([]*AttemptPermit, 3)
	for index := range failures {
		failures[index], allowed = store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
		if !allowed {
			t.Fatal("failure attempt was not admitted")
		}
	}
	for _, permit := range failures {
		permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeFailure}, clock.Now(), 0, "dial failed")
	}
	old.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeSuccess}, clock.Now(), 0, "late success")
	status := store.Endpoint(nodeID)
	if status.Breaker != BreakerOpen || status.Health != HealthUnreachable || status.Successes != 0 || status.Failures != 3 {
		t.Fatalf("late v0 success closed v1 breaker: %+v", status)
	}
}

func TestBreakerHalfOpenFailureUsesBoundedBackoff(t *testing.T) {
	store, clock := newBreakerTestStore()
	nodeID := NodeID{3}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	for range 3 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	for _, expected := range []time.Duration{20 * time.Second, 40 * time.Second, 40 * time.Second} {
		status := store.Endpoint(nodeID)
		clock.Advance(status.Backoff)
		permit, allowed := store.TryAcquireAttemptPermit(nodeID, service, clock.Now())
		if !allowed {
			t.Fatalf("half-open attempt was not admitted after %s", status.Backoff)
		}
		permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeFailure}, clock.Now(), 0, "dial failed")
		status = store.Endpoint(nodeID)
		if status.Backoff != expected || status.Failures == 0 {
			t.Fatalf("unexpected bounded backoff: got=%s want=%s status=%+v", status.Backoff, expected, status)
		}
	}
}

func TestHealthStoreBoundsTenThousandObservations(t *testing.T) {
	store := NewHealthStore(time.Hour, 4096)
	for index := 0; index < 10000; index++ {
		store.Observe(Observation{
			NodeID:  NodeID{byte(index), byte(index >> 8)},
			Scope:   ScopeService,
			Service: "service",
			Outcome: OutcomeSuccess,
		})
	}
	entries, evictions := store.Stats()
	if entries != 4096 {
		t.Fatalf("10k observations exceeded state bound: %d", entries)
	}
	if evictions != 10000-4096 {
		t.Fatalf("unexpected 10k eviction count: %d", evictions)
	}
}

func TestAggregateTransportStatusUsesBreakerSeverity(t *testing.T) {
	store, clock := newBreakerTestStore()
	handle := NodeHandle{NodeID: NodeID{92}, Slot: 1, Version: 1}
	for _, family := range []string{"tcp/ipv4", "tcp/ipv6"} {
		for range 3 {
			store.Observe(Observation{
				NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
				Scope: DomainTransport, Transport: family, Outcome: OutcomeFailure, At: clock.Now(),
			})
		}
	}
	// Move only IPv6 into half-open. The aggregate "tcp" status must report
	// half-open because it is the most restrictive state, not whichever breaker
	// string happens to sort later lexically ("open" > "half_open").
	clock.Advance(11 * time.Second)
	permit, allowed := store.TryAcquireDomainPermitHandle(handle, DomainTransport, "tcp/ipv6", "", clock.Now())
	if !allowed {
		t.Fatal("IPv6 half-open recovery permit was not admitted")
	}
	defer permit.ReleaseDeferred()
	status := store.StatusHandle(handle, DomainTransport, "tcp", "")
	if status.Breaker != BreakerHalfOpen {
		t.Fatalf("aggregate transport status lost half-open severity: %+v", status)
	}
}

func TestHealthStoreNodeVersionDoesNotInheritRetiredBreaker(t *testing.T) {
	clock := &fakeClock{now: time.Unix(400, 0)}
	store := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	nodeID := NodeID{77}
	store.Observe(Observation{NodeID: nodeID, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	if status := store.EndpointVersion(nodeID, 1); status.Breaker != BreakerOpen {
		t.Fatalf("v1 breaker did not open: %+v", status)
	}
	if status := store.EndpointVersion(nodeID, 2); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("v2 inherited v1 health: %+v", status)
	}
	store.Observe(Observation{NodeID: nodeID, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, At: clock.Now().Add(time.Second)})
	if status := store.EndpointVersion(nodeID, 2); status.Health != HealthUnknown || status.Successes != 0 {
		t.Fatalf("retiring v1 evidence changed v2: %+v", status)
	}
	store.RetireNodeVersion(nodeID, 1)
	if status := store.EndpointVersion(nodeID, 1); status.Health != HealthUnknown {
		t.Fatalf("retired v1 health remains active: %+v", status)
	}
}

func TestHealthStoreThroughputUsesQualityEWMAWithoutBreakerMutation(t *testing.T) {
	store := NewHealthStore(time.Hour, 16)
	handle := NodeHandle{NodeID: NodeID{78}, Slot: 3, Version: 2}
	for _, throughput := range []float64{1 << 20, 4 << 20} {
		store.ObserveEvidence(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainService, Service: "bulk", Outcome: OutcomeSuccess, ThroughputBPS: throughput}, false, 0.6)
	}
	status := store.StatusHandle(handle, DomainService, "", "bulk")
	if status.ThroughputSamples != 2 || status.ThroughputBPS <= 1<<20 || status.ThroughputBPS >= 4<<20 {
		t.Fatalf("throughput EWMA is invalid: %+v", status)
	}
	if status.Breaker != BreakerClosed || status.Successes != 0 || status.Failures != 0 || status.NonBreakerSuccesses != 2 {
		t.Fatalf("throughput quality mutated breaker counters: %+v", status)
	}
	summary := store.ThroughputByHandle()[handle]
	if summary.Samples != 2 || summary.BPS != status.ThroughputBPS {
		t.Fatalf("throughput monitoring aggregate diverged: summary=%+v status=%+v", summary, status)
	}
}

func TestHealthDelayRingUsesMedianSmoothedDelay(t *testing.T) {
	store := NewHealthStore(time.Hour, 16)
	nodeID := NodeID{91}
	delays := []time.Duration{
		100 * time.Millisecond,
		110 * time.Millisecond,
		90 * time.Millisecond,
		105 * time.Millisecond,
		95 * time.Millisecond,
		1 * time.Second, // outlier must not dominate the median
	}
	for _, delay := range delays {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: delay, At: time.Now()})
	}
	status := store.Endpoint(nodeID)
	if status.LastDelay != time.Second {
		t.Fatalf("last delay should keep the newest sample: %+v", status)
	}
	if status.DelaySamples != len(delays) {
		t.Fatalf("delay sample count mismatch: %+v", status)
	}
	// Median of [90,95,100,105,110,1000] = (100+105)/2 = 102.5ms
	want := (100*time.Millisecond + 105*time.Millisecond) / 2
	if status.SmoothedDelay != want || status.RankingDelay() != want {
		t.Fatalf("smoothed median mismatch: got=%s want=%s status=%+v", status.SmoothedDelay, want, status)
	}
}

func TestBreakerBackoffJitterIsBounded(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	store := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{
		FailureThreshold: 1,
		BaseCooldown:     10 * time.Second,
		MaxCooldown:      40 * time.Second,
		JitterFraction:   0.2,
	})
	nodeID := NodeID{92}
	seen := map[time.Duration]bool{}
	for range 20 {
		store.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
		status := store.Endpoint(nodeID)
		if status.Backoff < 8*time.Second || status.Backoff > 12*time.Second {
			t.Fatalf("jittered backoff out of bounds: %s", status.Backoff)
		}
		seen[status.Backoff] = true
		// Recover so the next failure reopens from a closed breaker.
		clock.Advance(status.Backoff)
		permit, allowed := store.TryAcquireDomainPermit(nodeID, DomainEndpoint, "", "", clock.Now())
		if !allowed {
			t.Fatal("half-open recovery was not admitted")
		}
		permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeSuccess}, clock.Now(), 0, "")
		permit, allowed = store.TryAcquireDomainPermit(nodeID, DomainEndpoint, "", "", clock.Now())
		if !allowed {
			t.Fatal("confirmation recovery was not admitted")
		}
		permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeSuccess}, clock.Now(), 0, "")
	}
	if len(seen) < 2 {
		t.Fatalf("expected jitter to produce more than one backoff value, got %v", seen)
	}
}

func TestBreakerBackoffJitterUsesInjectedDeterministicSource(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	store := NewHealthStoreWithClock(time.Hour, 8, clock, BreakerConfig{
		FailureThreshold: 1, BaseCooldown: 10 * time.Second, MaxCooldown: time.Minute,
		JitterFraction: 0.2, JitterRandom: func() float64 { return 0.75 },
	})
	store.Observe(Observation{NodeID: NodeID{93}, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	if status := store.Endpoint(NodeID{93}); status.Backoff != 11*time.Second {
		t.Fatalf("injected jitter was not deterministic: %+v", status)
	}
}

func TestHealthReadOnlySnapshotDoesNotChangeWithLiveStore(t *testing.T) {
	store := NewHealthStore(time.Hour, 8)
	handle := NodeHandle{NodeID: NodeID{94}, Slot: 1, Version: 1}
	store.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 10 * time.Millisecond})
	snapshot := store.ReadOnlySnapshot()
	store.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 90 * time.Millisecond})
	if got := snapshot.EndpointHandle(handle); got.Successes != 1 || got.LastDelay != 10*time.Millisecond {
		t.Fatalf("read snapshot changed with live health: %+v", got)
	}
}
