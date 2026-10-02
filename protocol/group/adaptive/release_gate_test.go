package adaptive

import (
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// Release gates encode the expert rollout checklist as automated invariants.
// These are the minimum proofs required before an adaptive package ships.

func TestGateDualSessionStickyDoesNotCrossClients(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	nodeA := Candidate{ID: NodeID{0xa1}, Handle: NodeHandle{NodeID: NodeID{0xa1}, Slot: 1, Version: 1}, PrimaryTag: "node-a"}
	nodeB := Candidate{ID: NodeID{0xa2}, Handle: NodeHandle{NodeID: NodeID{0xa2}, Slot: 2, Version: 1}, PrimaryTag: "node-b"}
	// B is materially faster so pure rank would always prefer B.
	health.Observe(Observation{NodeID: nodeA.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 120 * time.Millisecond})
	health.Observe(Observation{NodeID: nodeB.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute)

	// Affinity is per product; session is per client. Cross-product sticky must not couple.
	clientAChat := ServiceContext{ID: "chatgpt_web", AffinityID: "chatgpt_web", Session: SessionKey{1}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	clientBClaude := ServiceContext{ID: "claude", AffinityID: "claude", Session: SessionKey{2}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	now := time.Now()
	engine.RememberSelection(engine.stickyKey(clientAChat), nodeA.Handle, now)
	engine.RememberSelection(engine.stickyKey(clientBClaude), nodeB.Handle, now)

	planA, err := engine.Plan(testExecutionSnapshot(nodeA, nodeB), clientAChat, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	planB, err := engine.Plan(testExecutionSnapshot(nodeA, nodeB), clientBClaude, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if planA.Candidates[0].ID != nodeA.ID {
		t.Fatalf("client A chatgpt sticky lost: %+v", planA)
	}
	if planB.Candidates[0].ID != nodeB.ID {
		t.Fatalf("client B claude sticky lost: %+v", planB)
	}
	// Same client, different product: claude must NOT inherit chatgpt sticky.
	clientAClaude := ServiceContext{ID: "claude", AffinityID: "claude", Session: SessionKey{1}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	planA2, err := engine.Plan(testExecutionSnapshot(nodeA, nodeB), clientAClaude, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if planA2.Candidates[0].ID != nodeB.ID {
		// Pure rank prefers B (40ms). No chatgpt sticky bleed.
		t.Fatalf("cross-product sticky bleed: expected rank leader B, got %+v", planA2)
	}
}

func TestGateLatencyModeIgnoresStickyCooldown(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	slow := Candidate{ID: NodeID{0xb1}, Handle: NodeHandle{NodeID: NodeID{0xb1}, Slot: 1, Version: 1}, PrimaryTag: "slow"}
	fast := Candidate{ID: NodeID{0xb2}, Handle: NodeHandle{NodeID: NodeID{0xb2}, Slot: 2, Version: 1}, PrimaryTag: "fast"}
	health.Observe(Observation{NodeID: slow.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 200 * time.Millisecond})
	health.Observe(Observation{NodeID: fast.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Hour)
	service := ServiceContext{ID: "lat", AffinityID: "lat", Session: SessionKey{9}, Mode: ModeLatency, Transport: N.NetworkTCP}
	engine.RememberSelection(engine.stickyKey(service), slow.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(slow, fast), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != fast.ID || plan.Reason == ReasonSwitchCooldown || plan.Reason == ReasonStickyMargin {
		t.Fatalf("latency mode must stay pure lowest smoothed delay: %+v", plan)
	}
}

func TestGateSixPathIsolationMatrix(t *testing.T) {
	store, clock := newBreakerTestStore()
	handle := NodeHandle{NodeID: NodeID{0xc1}, Slot: 1, Version: 1}
	paths := []string{
		"tcp/ipv4", "tcp/ipv6",
		"udp_dns/ipv4", "udp_dns/ipv6",
		"udp_data/ipv4", "udp_data/ipv6",
	}
	// Open only udp_dns/ipv4.
	for range 3 {
		store.Observe(Observation{
			NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
			Scope: DomainTransport, Transport: "udp_dns/ipv4", Outcome: OutcomeFailure, At: clock.Now(),
		})
	}
	for _, path := range paths {
		service := ServiceContext{ID: "svc", Transport: N.NetworkTCP, HealthTransport: path}
		if path[:3] == "udp" {
			service.Transport = N.NetworkUDP
		}
		blocked := !store.CanAttemptHandleReadOnly(handle, service, clock.Now())
		wantBlocked := path == "udp_dns/ipv4"
		if blocked != wantBlocked {
			t.Fatalf("path %s blocked=%v want=%v", path, blocked, wantBlocked)
		}
	}
	profile := store.BuildCapabilityProfile(handle, clock.Now())
	if profile.DNSUDPv4.Available || !profile.TCP4.Available || !profile.DataUDPv4.Available {
		t.Fatalf("capability portrait leaked path failure: %+v", profile)
	}
}

func TestGateStatusReadsDoNotMutateBreakers(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 64, realClock{}, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Minute, MaxCooldown: 5 * time.Minute, JitterFraction: 0})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{0xd1}, "gate-status", newTestOutbound("gate-status")))
	handle := snapshot.Candidates[0].Handle
	for range 3 {
		health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: time.Now()})
	}
	before := health.EndpointHandle(handle)
	if before.Breaker != BreakerOpen {
		t.Fatalf("setup open breaker failed: %+v", before)
	}
	for range 1000 {
		_ = pool.AdaptiveStatus()
		_ = health.PeekAvailable(handle, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"}, time.Now())
		engine := NewPolicyEngine(health, 2, "fallback")
		_, _ = engine.Plan(testExecutionSnapshot(snapshot.Candidates[0]), ServiceContext{ID: "s", Mode: ModeAdaptive, Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"}, nil, nil)
	}
	after := health.EndpointHandle(handle)
	if after.Breaker != before.Breaker || after.CooldownUntil != before.CooldownUntil || after.Failures != before.Failures {
		t.Fatalf("status/plan reads mutated breaker: before=%+v after=%+v", before, after)
	}
}

func TestGateRetireKeepsIngestorForLateObservations(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{0xe1}, "late-obs", newTestOutbound("late-obs")))
	handle := snapshot.Candidates[0].Handle
	ingestorBefore := pool.sharedObservationIngestor()
	if ingestorBefore == nil {
		t.Fatal("missing observation ingestor")
	}
	// Hold an epoch lease across retire, matching long-lived business connections.
	lease, err := pool.runtimeManager.AcquireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	guard := RuntimeEpochObservationGuard{Lease: lease}

	// Retire must not wipe the ingestor; late business failures still settle.
	pool.OnRuntimeEpochRetire()
	if pool.sharedObservationIngestor() != ingestorBefore {
		t.Fatal("retire replaced or cleared the observation ingestor")
	}
	evidence := ObservationEvidence{
		RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
		Handle: handle, AttemptID: 1, Source: SourceDial, Stage: StageDestinationTransport,
		Outcome: OutcomeFailure, Failure: FailureConnect, Confidence: ConfidenceHigh,
		Transport: N.NetworkTCP, NetworkPath: "tcp/ipv4", At: time.Now(), Reason: "late failure after retire",
	}
	reducer := &HealthObservationReducer{Store: health}
	disposition, err := PublishSettledObservationGuarded(ingestorBefore, guard, evidence, reducer)
	if err != nil {
		t.Fatalf("late observation after retire failed: %v", err)
	}
	if disposition != IngestAccepted {
		t.Fatalf("late observation disposition=%s", disposition)
	}
	status := health.StatusHandle(handle, DomainTransport, "tcp/ipv4", "")
	if status.Failures == 0 {
		t.Fatalf("late observation did not land in health store: %+v", status)
	}
}

func TestGateHardFailureBypassesStickyMargin(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Minute, MaxCooldown: time.Minute, JitterFraction: 0})
	incumbent := Candidate{ID: NodeID{0xf1}, Handle: NodeHandle{NodeID: NodeID{0xf1}, Slot: 1, Version: 1}, PrimaryTag: "incumbent"}
	backup := Candidate{ID: NodeID{0xf2}, Handle: NodeHandle{NodeID: NodeID{0xf2}, Slot: 2, Version: 1}, PrimaryTag: "backup"}
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 30 * time.Millisecond})
	health.Observe(Observation{NodeID: backup.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 80 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.5, time.Hour)
	service := ServiceContext{ID: "web", AffinityID: "web", Session: SessionKey{7}, Mode: ModeAdaptive, Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"}
	engine.RememberSelection(engine.stickyKey(service), incumbent.Handle, time.Now())
	// Open endpoint breaker on sticky incumbent.
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: time.Now()})
	plan, err := engine.Plan(testExecutionSnapshot(incumbent, backup), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) == 0 || plan.Candidates[0].ID != backup.ID {
		t.Fatalf("hard failure must bypass sticky and fail over: %+v", plan)
	}
}

func TestGateSmoothedDelayUsesSuccessOnly(t *testing.T) {
	store := NewHealthStore(time.Hour, 16)
	node := NodeID{0x11}
	store.Observe(Observation{NodeID: node, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	store.Observe(Observation{NodeID: node, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 60 * time.Millisecond})
	// Failure with huge delay must not enter the ranking ring.
	store.Observe(Observation{NodeID: node, Scope: DomainEndpoint, Outcome: OutcomeFailure, Delay: 5 * time.Second})
	status := store.Endpoint(node)
	if status.DelaySamples != 2 {
		t.Fatalf("failure delay polluted ring: %+v", status)
	}
	if status.SmoothedDelay != 55*time.Millisecond {
		t.Fatalf("smoothed delay want 55ms got %s", status.SmoothedDelay)
	}
}
