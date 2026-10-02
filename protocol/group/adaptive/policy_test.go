package adaptive

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodeweight"
	N "github.com/sagernet/sing/common/network"
)

func testExecutionSnapshot(candidates ...Candidate) *ExecutionSnapshot {
	snapshot := &ExecutionSnapshot{
		Generation: 1,
		Candidates: candidates,
		ByID:       make(map[NodeID]int, len(candidates)),
		AliasToID:  make(map[string]NodeID, len(candidates)),
	}
	for index, candidate := range candidates {
		if candidate.Handle.NodeID == (NodeID{}) {
			candidate.Handle.NodeID = candidate.ID
		}
		if len(candidate.Transport) == 0 {
			candidate.Transport = []string{N.NetworkTCP, N.NetworkUDP}
		}
		candidates[index] = candidate
		snapshot.ByID[candidate.ID] = index
		snapshot.AliasToID[candidate.PrimaryTag] = candidate.ID
	}
	return snapshot
}

func TestPolicyKeepsHealthySessionLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	first := Candidate{ID: NodeID{1}, PrimaryTag: "first"}
	second := Candidate{ID: NodeID{2}, PrimaryTag: "second"}
	health.Observe(Observation{NodeID: first.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, Delay: 20 * time.Millisecond})
	health.Observe(Observation{NodeID: second.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, Delay: 10 * time.Millisecond})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	lease := &SessionLease{NodeID: first.ID}
	plan, err := engine.Plan(testExecutionSnapshot(first, second), service, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonLease || plan.Candidates[0].ID != first.ID || len(plan.Candidates) != 1 {
		t.Fatalf("healthy lease was not retained: %+v", plan)
	}
}

func TestPolicyWeightBreaksTiesButNeverOverridesHealth(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	preferred := Candidate{ID: NodeID{41}, Handle: NodeHandle{NodeID: NodeID{41}, Slot: 1, Version: 1}, PrimaryTag: "preferred"}
	normal := Candidate{ID: NodeID{42}, Handle: NodeHandle{NodeID: NodeID{42}, Slot: 2, Version: 1}, PrimaryTag: "normal"}
	for _, candidate := range []Candidate{preferred, normal} {
		health.Observe(Observation{NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	}
	weights, err := nodeweight.New([]nodeweight.Rule{{Match: "preferred", Weight: 2}})
	if err != nil {
		t.Fatal(err)
	}
	engine := NewPolicyEngine(health, 2, "fallback").BindNodeWeights(weights)
	service := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(normal, preferred), service, nil, nil)
	if err != nil || plan.Candidates[0].ID != preferred.ID {
		t.Fatalf("weight did not break healthy tie: plan=%+v err=%v", plan, err)
	}
	for range 3 {
		health.Observe(Observation{NodeID: preferred.ID, NodeSlot: preferred.Handle.Slot, NodeVersion: preferred.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	plan, err = engine.Plan(testExecutionSnapshot(preferred, normal), service, nil, nil)
	if err != nil || plan.Candidates[0].ID != normal.ID {
		t.Fatalf("weight overrode health breaker: plan=%+v err=%v", plan, err)
	}
}

func TestStrictAffinityLeaseFailsOverOnlyAfterLeasedNodeIsUnavailable(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	leased := Candidate{ID: NodeID{11}, Handle: NodeHandle{NodeID: NodeID{11}, Slot: 1, Version: 1}, PrimaryTag: "leased"}
	alternative := Candidate{ID: NodeID{12}, Handle: NodeHandle{NodeID: NodeID{12}, Slot: 2, Version: 1}, PrimaryTag: "alternative"}
	for range 3 {
		health.Observe(Observation{NodeID: leased.ID, NodeSlot: leased.Handle.Slot, NodeVersion: leased.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	service := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	lease := &SessionLease{NodeID: leased.ID, NodeSlot: leased.Handle.Slot, NodeVersion: leased.Handle.Version, ServiceID: service.ID, Mode: service.Mode}
	plan, err := NewPolicyEngine(health, 3, "fallback").Plan(testExecutionSnapshot(leased, alternative), service, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonStrictNew || len(plan.Candidates) != 1 || plan.Candidates[0].ID != alternative.ID {
		t.Fatalf("strict affinity did not build a bounded replacement plan: %+v", plan)
	}
}

func TestStrictAffinityReplacementUsesCooldownNotPureRankThrash(t *testing.T) {
	// After the leased identity dies, the next plan must not hop to every
	// slightly-faster node. Cooldown keeps the remembered replacement stable.
	health := NewHealthStore(time.Hour, 32)
	dead := Candidate{ID: NodeID{0xd1}, Handle: NodeHandle{NodeID: NodeID{0xd1}, Slot: 1, Version: 1}, PrimaryTag: "dead"}
	stable := Candidate{ID: NodeID{0xd2}, Handle: NodeHandle{NodeID: NodeID{0xd2}, Slot: 2, Version: 1}, PrimaryTag: "stable"}
	faster := Candidate{ID: NodeID{0xd3}, Handle: NodeHandle{NodeID: NodeID{0xd3}, Slot: 3, Version: 1}, PrimaryTag: "faster"}
	for range 3 {
		health.Observe(Observation{NodeID: dead.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	health.Observe(Observation{NodeID: stable.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	health.Observe(Observation{NodeID: faster.ID, NodeSlot: 3, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	engine := NewPolicyEngine(health, 3, "fallback").BindSwitchStability(0.15, time.Minute)
	service := ServiceContext{ID: "chatgpt_web", AffinityID: "chatgpt_web", Session: SessionKey{7}, Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	// Prior successful replacement remembered as sticky.
	engine.RememberSelection(engine.stickyKey(service), stable.Handle, time.Now())
	lease := &SessionLease{NodeID: dead.ID, NodeSlot: 1, NodeVersion: 1, ServiceID: service.ID, Mode: service.Mode}
	plan, err := engine.Plan(testExecutionSnapshot(dead, faster, stable), service, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != stable.ID {
		t.Fatalf("strict replacement ignored cooldown sticky: reason=%s first=%+v", plan.Reason, plan.Candidates[0])
	}
	if plan.Reason != ReasonSwitchCooldown && plan.Reason != ReasonStickyMargin {
		t.Fatalf("expected sticky/cooldown reason after strict lease break, got %s", plan.Reason)
	}
}

func TestRealTransportFailureDownranksGenericProbeWinner(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	fastButBroken := Candidate{ID: NodeID{31}, Handle: NodeHandle{NodeID: NodeID{31}, Slot: 1, Version: 1}, PrimaryTag: "fast-but-broken"}
	working := Candidate{ID: NodeID{32}, Handle: NodeHandle{NodeID: NodeID{32}, Slot: 2, Version: 1}, PrimaryTag: "working"}
	health.Observe(Observation{NodeID: fastButBroken.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 5 * time.Millisecond})
	health.Observe(Observation{NodeID: working.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	health.Observe(Observation{NodeID: fastButBroken.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: N.NetworkTCP, Outcome: OutcomeFailure, Delay: 4 * time.Second})
	health.Observe(Observation{NodeID: working.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainTransport, Transport: N.NetworkTCP, Outcome: OutcomeSuccess, Delay: 60 * time.Millisecond})
	service := ServiceContext{ID: "telegram", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := NewPolicyEngine(health, 2, "fallback").Plan(testExecutionSnapshot(fastButBroken, working), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != working.ID || plan.Candidates[1].ID != fastButBroken.ID {
		t.Fatalf("real transport failure did not override generic probe latency: %+v", plan.Candidates)
	}
}

func TestAdaptiveKeepsFallbacksWhileBulkRotatesAndIgnoresLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	candidates := []Candidate{
		{ID: NodeID{21}, Handle: NodeHandle{NodeID: NodeID{21}, Slot: 1, Version: 1}, PrimaryTag: "a"},
		{ID: NodeID{22}, Handle: NodeHandle{NodeID: NodeID{22}, Slot: 2, Version: 1}, PrimaryTag: "b"},
		{ID: NodeID{23}, Handle: NodeHandle{NodeID: NodeID{23}, Slot: 3, Version: 1}, PrimaryTag: "c"},
	}
	engine := NewPolicyEngine(health, 3, "fallback")
	lease := &SessionLease{NodeID: candidates[2].ID, NodeSlot: candidates[2].Handle.Slot, NodeVersion: candidates[2].Handle.Version}
	adaptiveService := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	adaptivePlan, err := engine.Plan(testExecutionSnapshot(candidates...), adaptiveService, lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if adaptivePlan.Reason != ReasonLease || adaptivePlan.Candidates[0].ID != lease.NodeID || len(adaptivePlan.Candidates) != 3 {
		t.Fatalf("adaptive mode lost lease-first fallback behavior: %+v", adaptivePlan)
	}
	bulkService := ServiceContext{ID: "site:example.com", Mode: ModeBulk, Transport: N.NetworkTCP}
	want := []NodeID{candidates[0].ID, candidates[1].ID, candidates[2].ID, candidates[0].ID}
	for index, expected := range want {
		plan, planErr := engine.Plan(testExecutionSnapshot(candidates...), bulkService, lease, nil)
		if planErr != nil {
			t.Fatal(planErr)
		}
		if plan.Reason != ReasonBulkSpread || plan.Candidates[0].ID != expected {
			t.Fatalf("bulk connection %d did not rotate independently of lease: %+v", index, plan)
		}
	}
}

func TestPolicyManualPinFallbackIsExplicit(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pinned := Candidate{ID: NodeID{1}, PrimaryTag: "pinned"}
	fallback := Candidate{ID: NodeID{2}, PrimaryTag: "fallback"}
	for range 3 {
		health.Observe(Observation{NodeID: pinned.ID, Scope: ScopeEndpoint, Outcome: OutcomeFailure})
	}
	health.Observe(Observation{NodeID: fallback.ID, Scope: ScopeEndpoint, Outcome: OutcomeSuccess})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	pin := pinned.ID
	plan, err := engine.Plan(testExecutionSnapshot(pinned, fallback), service, nil, &pin)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonFallback || plan.Candidates[0].ID != fallback.ID {
		t.Fatalf("manual fallback was not explicit: %+v", plan)
	}
}

func TestPolicyUsesBoundedWarmingFallbackWhenEveryBreakerIsOpen(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	candidates := []Candidate{
		{ID: NodeID{71}, Handle: NodeHandle{NodeID: NodeID{71}, Slot: 1, Version: 1}, PrimaryTag: "first"},
		{ID: NodeID{72}, Handle: NodeHandle{NodeID: NodeID{72}, Slot: 2, Version: 1}, PrimaryTag: "second"},
	}
	for _, candidate := range candidates {
		for range 3 {
			health.Observe(Observation{NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure})
		}
	}
	service := ServiceContext{ID: "site:startup.example", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := NewPolicyEngine(health, 2, "fallback").Plan(testExecutionSnapshot(candidates...), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonWarmingFallback || len(plan.Candidates) != 1 || !plan.allowBlocked || !plan.disableHedge {
		t.Fatalf("all-open startup must be single-candidate no-hedge fallback: %+v", plan)
	}
	chosen := plan.Candidates[0]
	permit, allowed := plan.TryAcquireAttemptPermit(chosen.ID, time.Now())
	if !allowed || permit == nil {
		t.Fatal("last-resort candidate was not permitted")
	}
	permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainEndpoint: OutcomeSuccess, DomainTransport: OutcomeSuccess}, time.Now(), time.Millisecond, "recovered")
	if status := health.EndpointHandle(chosen.Handle); status.Health != HealthHealthy || status.Breaker != BreakerClosed {
		t.Fatalf("successful last-resort attempt did not recover breaker: %+v", status)
	}
}

func TestDualStackScorePrefersHealthyFamilyDelay(t *testing.T) {
	// v6 path is terrible; v4 is fine. tcp/any rank must not use the dead family delay.
	health := NewHealthStore(time.Hour, 32)
	node := Candidate{ID: NodeID{0xe1}, Handle: NodeHandle{NodeID: NodeID{0xe1}, Slot: 1, Version: 1}, PrimaryTag: "dual"}
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv6", Outcome: OutcomeSuccess, Delay: 800 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback")
	score := engine.candidateScore(node, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/any"})
	if score.ObservedDelay > 100*time.Millisecond {
		t.Fatalf("dual-stack score used dead/slow family delay: %+v", score)
	}
	if score.DominantEvidence != "tcp/ipv4" && score.SmoothedDelay > 100*time.Millisecond {
		t.Fatalf("expected v4-dominated score, got %+v", score)
	}
}

func TestLatencyModeRanksWithoutCreatingLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 16)
	fast := Candidate{ID: NodeID{1}, Handle: NodeHandle{NodeID: NodeID{1}, Slot: 1, Version: 1}, PrimaryTag: "fast"}
	slow := Candidate{ID: NodeID{2}, Handle: NodeHandle{NodeID: NodeID{2}, Slot: 2, Version: 1}, PrimaryTag: "slow"}
	health.Observe(Observation{NodeID: fast.ID, NodeSlot: fast.Handle.Slot, NodeVersion: fast.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 10 * time.Millisecond})
	health.Observe(Observation{NodeID: slow.ID, NodeSlot: slow.Handle.Slot, NodeVersion: slow.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	service := ServiceContext{ID: "site:example.com", Mode: ModeLatency, Transport: N.NetworkTCP}
	plan, err := NewPolicyEngine(health, 2, "fallback").Plan(testExecutionSnapshot(fast, slow), service, nil, nil)
	if err != nil || len(plan.Candidates) != 2 || plan.Candidates[0].ID != fast.ID || modeUsesLease(plan.Mode) {
		t.Fatalf("latency policy mismatch: plan=%+v err=%v", plan, err)
	}
}

func TestAdaptivePoolDisablesPreMatchLeafSelection(t *testing.T) {
	pool := new(AdaptivePool)
	if _, loaded := any(pool).(adapter.PreMatchOutboundGroup); loaded {
		t.Fatal("adaptive pool still implements pre-match leaf selection")
	}
	if _, loaded := any(pool).(adapter.PreMatchDisabledOutbound); !loaded {
		t.Fatal("adaptive pool does not disable pre-match")
	}
}

func TestServiceFailureDoesNotOpenEndpointBreaker(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	first := Candidate{ID: NodeID{1}, PrimaryTag: "first"}
	second := Candidate{ID: NodeID{2}, PrimaryTag: "second"}
	for range 3 {
		health.Observe(Observation{NodeID: first.ID, Scope: ScopeService, Service: "youtube", Outcome: OutcomeFailure})
	}
	engine := NewPolicyEngine(health, 3, "fallback")
	youtube := ServiceContext{ID: "youtube", Mode: ModeStrictAffinity, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(first, second), youtube, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != second.ID {
		t.Fatalf("service breaker did not exclude failed candidate: %+v", plan)
	}
	ordinary := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err = engine.Plan(testExecutionSnapshot(first, second), ordinary, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != first.ID {
		t.Fatalf("service failure contaminated unrelated endpoint ranking: %+v", plan)
	}
}

func TestPolicyClosedUnknownIsNotHealthyAndDegradedDoesNotBeatSuccess(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	degraded := Candidate{ID: NodeID{1}, PrimaryTag: "degraded"}
	healthy := Candidate{ID: NodeID{2}, PrimaryTag: "healthy"}
	unknown := Candidate{ID: NodeID{3}, PrimaryTag: "unknown"}
	health.Observe(Observation{NodeID: degraded.ID, Scope: DomainEndpoint, Outcome: OutcomeFailure, Delay: time.Millisecond})
	health.Observe(Observation{NodeID: healthy.ID, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 50 * time.Millisecond})
	engine := NewPolicyEngine(health, 3, "fallback")
	service := ServiceContext{ID: "service", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(degraded, unknown, healthy), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != healthy.ID || plan.Candidates[1].ID != unknown.ID || plan.Candidates[2].ID != degraded.ID {
		t.Fatalf("health evidence ordering is wrong: %v", []string{plan.Candidates[0].PrimaryTag, plan.Candidates[1].PrimaryTag, plan.Candidates[2].PrimaryTag})
	}
	if status := health.Endpoint(unknown.ID); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("closed unknown was presented as healthy: %+v", status)
	}
}

func TestCandidateScoreExplainsWeightAndHealthPenalty(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	handle := NodeHandle{NodeID: NodeID{61}, Slot: 1, Version: 1}
	candidate := Candidate{ID: handle.NodeID, Handle: handle, PrimaryTag: "Gcore weighted"}
	matcher, err := nodeweight.New([]nodeweight.Rule{{Match: "Gcore", Weight: 0.25}})
	if err != nil {
		t.Fatal(err)
	}
	engine := NewPolicyEngine(health, 3, "fallback").BindNodeWeights(matcher)
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	score := engine.candidateScore(candidate, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"})
	if score.HealthPriority != 1 || score.ObservedDelay != 100*time.Millisecond || score.WeightedDelay != 400*time.Millisecond || score.SelectionScore == 0 || score.DominantEvidence != "tcp/ipv4" {
		t.Fatalf("score explanation mismatch: %+v", score)
	}
}

func TestPolicyReaddedVersionDoesNotInheritBreakerOrLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	nodeID := NodeID{44}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure})
	}
	candidate := Candidate{ID: nodeID, Handle: NodeHandle{NodeID: nodeID, Slot: 1, Version: 2, BornRevision: 2}, PrimaryTag: "readded"}
	service := ServiceContext{ID: "service", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	oldLease := &SessionLease{NodeID: nodeID, NodeSlot: 1, NodeVersion: 1, ServiceID: service.ID, Mode: ModeAdaptive}
	plan, err := NewPolicyEngine(health, 1, "fallback").Plan(testExecutionSnapshot(candidate), service, oldLease, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason == ReasonLease || len(plan.Candidates) != 1 || plan.Candidates[0].Handle.Version != 2 {
		t.Fatalf("v1 lease/breaker contaminated v2 plan: %+v", plan)
	}
	if status := health.EndpointHandle(candidate.Handle); status.Health != HealthUnknown || status.Breaker != BreakerClosed {
		t.Fatalf("v2 did not start with isolated health: %+v", status)
	}
}

func TestBulkPolicyExploitsThroughputAndPeriodicallyExplores(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	fast := Candidate{ID: NodeID{51}, Handle: NodeHandle{NodeID: NodeID{51}, Slot: 1, Version: 1}, PrimaryTag: "fast"}
	slow := Candidate{ID: NodeID{52}, Handle: NodeHandle{NodeID: NodeID{52}, Slot: 2, Version: 1}, PrimaryTag: "slow"}
	unknown := Candidate{ID: NodeID{53}, Handle: NodeHandle{NodeID: NodeID{53}, Slot: 3, Version: 1}, PrimaryTag: "unknown"}
	service := ServiceContext{ID: "bulk-service", Mode: ModeBulk, Transport: N.NetworkTCP}
	for range 2 {
		health.ObserveEvidence(Observation{NodeID: fast.ID, NodeSlot: fast.Handle.Slot, NodeVersion: fast.Handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeSuccess, ThroughputBPS: 8 << 20}, false, 0.6)
		health.ObserveEvidence(Observation{NodeID: slow.ID, NodeSlot: slow.Handle.Slot, NodeVersion: slow.Handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeSuccess, ThroughputBPS: 1 << 20}, false, 0.6)
	}
	sequence := new(atomic.Uint64)
	engine := NewPolicyEngine(health, 3, "fallback").BindBulkSequence(sequence)
	plan, err := engine.Plan(testExecutionSnapshot(slow, unknown, fast), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonBulkThroughput || plan.Candidates[0].ID != fast.ID {
		t.Fatalf("bulk policy did not exploit trusted throughput: %+v", plan)
	}
	sequence.Store(9)
	plan, err = engine.Plan(testExecutionSnapshot(slow, unknown, fast), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonBulkSpread || plan.Candidates[0].ID != unknown.ID {
		t.Fatalf("bulk policy starved unknown candidate instead of exploring: %+v", plan)
	}
}

func TestPolicySwitchMarginKeepsIncumbentOnSmallLatencyGain(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	incumbent := Candidate{ID: NodeID{71}, Handle: NodeHandle{NodeID: NodeID{71}, Slot: 1, Version: 1}, PrimaryTag: "incumbent"}
	challenger := Candidate{ID: NodeID{72}, Handle: NodeHandle{NodeID: NodeID{72}, Slot: 2, Version: 1}, PrimaryTag: "challenger"}
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	health.Observe(Observation{NodeID: challenger.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 90 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, 0)
	service := ServiceContext{ID: "chatgpt_web", AffinityID: "browser-family", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	engine.RememberSelection(service.AffinityID, incumbent.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(challenger, incumbent), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonStickyMargin || plan.Candidates[0].ID != incumbent.ID {
		t.Fatalf("15%% margin did not keep incumbent: %+v", plan)
	}

	// Challenger is 20% faster: must replace.
	health.Observe(Observation{NodeID: challenger.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 80 * time.Millisecond})
	plan, err = engine.Plan(testExecutionSnapshot(challenger, incumbent), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != challenger.ID {
		t.Fatalf("materially faster challenger was blocked: %+v", plan)
	}
}

func TestPolicySwitchCooldownPrefersIncumbentInsideWindow(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	incumbent := Candidate{ID: NodeID{81}, Handle: NodeHandle{NodeID: NodeID{81}, Slot: 1, Version: 1}, PrimaryTag: "incumbent"}
	challenger := Candidate{ID: NodeID{82}, Handle: NodeHandle{NodeID: NodeID{82}, Slot: 2, Version: 1}, PrimaryTag: "challenger"}
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 120 * time.Millisecond})
	health.Observe(Observation{NodeID: challenger.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute)
	service := ServiceContext{ID: "claude", AffinityID: "ai-session", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	now := time.Now()
	engine.RememberSelection(service.AffinityID, incumbent.Handle, now)
	plan, err := engine.Plan(testExecutionSnapshot(challenger, incumbent), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reason != ReasonSwitchCooldown || plan.Candidates[0].ID != incumbent.ID {
		t.Fatalf("cooldown window did not retain incumbent: %+v", plan)
	}
}

func TestPolicySmoothedDelayPreventsSingleSpikeReordering(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	stable := Candidate{ID: NodeID{91}, Handle: NodeHandle{NodeID: NodeID{91}, Slot: 1, Version: 1}, PrimaryTag: "stable"}
	spiky := Candidate{ID: NodeID{92}, Handle: NodeHandle{NodeID: NodeID{92}, Slot: 2, Version: 1}, PrimaryTag: "spiky"}
	for _, delay := range []time.Duration{50, 52, 48, 51, 49} {
		health.Observe(Observation{NodeID: stable.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: delay * time.Millisecond})
	}
	for _, delay := range []time.Duration{40, 42, 41, 43, 39} {
		health.Observe(Observation{NodeID: spiky.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: delay * time.Millisecond})
	}
	// One bad sample on the normally faster node.
	health.Observe(Observation{NodeID: spiky.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 500 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0, 0)
	service := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	plan, err := engine.Plan(testExecutionSnapshot(stable, spiky), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != spiky.ID {
		t.Fatalf("median delay still preferred the spiked last sample incorrectly: %+v", plan.Candidates)
	}
	// Spiky median stays ~41ms, stable ~50ms, so spiky remains first despite last=500ms.
	if health.EndpointHandle(spiky.Handle).LastDelay != 500*time.Millisecond {
		t.Fatal("expected last delay to retain the spike")
	}
	if health.EndpointHandle(spiky.Handle).SmoothedDelay >= health.EndpointHandle(stable.Handle).SmoothedDelay {
		t.Fatalf("smoothed delay failed to suppress spike: spiky=%s stable=%s", health.EndpointHandle(spiky.Handle).SmoothedDelay, health.EndpointHandle(stable.Handle).SmoothedDelay)
	}
}

func TestPolicyStickyPreferenceIsSessionScoped(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	incumbent := Candidate{ID: NodeID{101}, Handle: NodeHandle{NodeID: NodeID{101}, Slot: 1, Version: 1}, PrimaryTag: "incumbent"}
	challenger := Candidate{ID: NodeID{102}, Handle: NodeHandle{NodeID: NodeID{102}, Slot: 2, Version: 1}, PrimaryTag: "challenger"}
	health.Observe(Observation{NodeID: incumbent.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	health.Observe(Observation{NodeID: challenger.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 40 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute)
	first := ServiceContext{ID: "chatgpt_web", AffinityID: "browser", Session: SessionKey{1}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	second := ServiceContext{ID: "chatgpt_web", AffinityID: "browser", Session: SessionKey{2}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	engine.RememberSelection(engine.stickyKey(first), incumbent.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(challenger, incumbent), second, nil, nil)
	if err != nil || plan.Candidates[0].ID != challenger.ID {
		t.Fatalf("one session contaminated another sticky preference: plan=%+v err=%v", plan, err)
	}
}

func TestLatencyModeIgnoresAdaptiveStickyCooldown(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	slow := Candidate{ID: NodeID{103}, Handle: NodeHandle{NodeID: NodeID{103}, Slot: 1, Version: 1}, PrimaryTag: "slow"}
	fast := Candidate{ID: NodeID{104}, Handle: NodeHandle{NodeID: NodeID{104}, Slot: 2, Version: 1}, PrimaryTag: "fast"}
	health.Observe(Observation{NodeID: slow.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 120 * time.Millisecond})
	health.Observe(Observation{NodeID: fast.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 30 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute)
	service := ServiceContext{ID: "latency", AffinityID: "latency", Session: SessionKey{3}, Mode: ModeLatency, Transport: N.NetworkTCP}
	engine.RememberSelection(engine.stickyKey(service), slow.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(fast, slow), service, nil, nil)
	if err != nil || plan.Candidates[0].ID != fast.ID || plan.Reason != ReasonRanked {
		t.Fatalf("latency mode was changed by adaptive stickiness: plan=%+v err=%v", plan, err)
	}
}

func TestEarlyFailureRemovesOnlyMatchingRecentStickySelection(t *testing.T) {
	engine := NewPolicyEngine(NewHealthStore(time.Hour, 8), 2, "fallback")
	service := ServiceContext{ID: "service", AffinityID: "family", Session: SessionKey{4}, Mode: ModeAdaptive, Transport: N.NetworkTCP}
	handle := NodeHandle{NodeID: NodeID{105}, Slot: 1, Version: 1}
	now := time.Now()
	engine.RememberSelection(engine.stickyKey(service), handle, now)
	if !engine.ForgetSelectionAfterEarlyFailure(service, handle, now.Add(5*time.Second)) {
		t.Fatal("recent matching failure did not remove sticky selection")
	}
	if _, loaded := engine.stickyPreferred(engine.stickyKey(service), now.Add(6*time.Second)); loaded {
		t.Fatal("early-failed sticky selection remained active")
	}
	engine.RememberSelection(engine.stickyKey(service), handle, now)
	if engine.ForgetSelectionAfterEarlyFailure(service, handle, now.Add(earlySwitchWindow+time.Second)) {
		t.Fatal("old failure incorrectly removed stable sticky selection")
	}
}

func TestPlanFilteringDoesNotMutateBreakerState(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_100_000, 0)}
	health := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Minute, MaxCooldown: time.Minute, JitterFraction: 0})
	node := Candidate{ID: NodeID{3, 0, 1}, Handle: NodeHandle{NodeID: NodeID{3, 0, 1}, Slot: 1, Version: 1}, PrimaryTag: "n1"}
	// Open breaker with cooldown still active.
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	before := health.EndpointHandle(node.Handle)
	if before.Breaker != BreakerOpen {
		t.Fatalf("setup expected open breaker: %+v", before)
	}
	engine := NewPolicyEngine(health, 2, "fallback")
	service := ServiceContext{ID: "site", Mode: ModeAdaptive, Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"}
	// Multiple plans must not advance open -> cooldown purely by filtering.
	for range 5 {
		_, err := engine.Plan(testExecutionSnapshot(node), service, nil, nil)
		if err != ErrNoEligibleCandidates && err != nil {
			// warming fallback may succeed with allowBlocked
		}
		_ = err
	}
	after := health.EndpointHandle(node.Handle)
	if after.Breaker != before.Breaker || after.CooldownUntil != before.CooldownUntil {
		t.Fatalf("plan filtering mutated breaker: before=%+v after=%+v", before, after)
	}
}

func TestExclusionReasonsSummarizeAllBrokenPaths(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Minute, MaxCooldown: time.Minute, JitterFraction: 0})
	node := Candidate{ID: NodeID{3, 0, 2}, Handle: NodeHandle{NodeID: NodeID{3, 0, 2}, Slot: 1, Version: 1}, PrimaryTag: "n2"}
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "udp_dns/ipv4", Outcome: OutcomeFailure, Reason: "dns fail"})
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv6", Outcome: OutcomeFailure, Reason: "tcp6 fail"})
	engine := NewPolicyEngine(health, 2, "fallback")
	reasons := engine.ExclusionReasons(node, ServiceContext{})
	if len(reasons) < 2 {
		t.Fatalf("expected multiple path exclusions, got %v", reasons)
	}
	joined := strings.Join(reasons, ",")
	if !strings.Contains(joined, "udp_dns/ipv4") || !strings.Contains(joined, "tcp/ipv6") {
		t.Fatalf("path labels missing from exclusions: %v", reasons)
	}
}

func TestAffinityModeDisabledSkipsSticky(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	fast := Candidate{ID: NodeID{1, 1, 1}, Handle: NodeHandle{NodeID: NodeID{1, 1, 1}, Slot: 1, Version: 1}, PrimaryTag: "fast"}
	slow := Candidate{ID: NodeID{2, 2, 2}, Handle: NodeHandle{NodeID: NodeID{2, 2, 2}, Slot: 2, Version: 1}, PrimaryTag: "slow"}
	health.Observe(Observation{NodeID: fast.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeSuccess, Delay: 20 * time.Millisecond})
	health.Observe(Observation{NodeID: slow.ID, NodeSlot: 2, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeSuccess, Delay: 200 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback").BindSwitchStability(0.15, time.Minute).BindAffinityMode("disabled")
	service := ServiceContext{ID: "svc", AffinityID: "svc", Mode: ModeAdaptive, Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4", Session: SessionKey{9}}
	engine.RememberSelection(engine.stickyKey(service), slow.Handle, time.Now())
	plan, err := engine.Plan(testExecutionSnapshot(fast, slow), service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].ID != fast.ID {
		t.Fatalf("disabled affinity still preferred sticky slow node: %+v", plan)
	}
}

func TestRankUsesConcreteDialFamilyNotPeer(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	node := Candidate{ID: NodeID{3, 3, 3}, Handle: NodeHandle{NodeID: NodeID{3, 3, 3}, Slot: 1, Version: 1}, PrimaryTag: "n"}
	// v4 is fast; v6 is terrible — dial family ipv4 must rank on v4 only.
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeSuccess, Delay: 15 * time.Millisecond})
	health.Observe(Observation{NodeID: node.ID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv6", Outcome: OutcomeSuccess, Delay: 800 * time.Millisecond})
	engine := NewPolicyEngine(health, 2, "fallback")
	score := engine.candidateScore(node, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"})
	// Ranking delay must come from the dial family ledger (v4), not the slower v6 peer.
	if score.ObservedDelay != 15*time.Millisecond {
		t.Fatalf("concrete dial family rank delay mismatch: %+v", score)
	}
	// Dual-stack aggregate would pick min(15,800)=15 too; pin path label when transport dominates.
	name, status := engine.transportScoreStatus(node.Handle, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4"})
	if name != "tcp/ipv4" || status.RankingDelay() != 15*time.Millisecond {
		t.Fatalf("transportScoreStatus did not pin dial family: name=%s status=%+v", name, status)
	}
}

func TestServiceAndTransportRecoveryIndependent(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_100_000, 0)}
	health := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Millisecond, MaxCooldown: time.Second, JitterFraction: 0})
	handle := NodeHandle{NodeID: NodeID{4, 4, 4}, Slot: 1, Version: 1}
	// Open both domains.
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeFailure, At: clock.Now()})
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainService, Service: "svc", Outcome: OutcomeFailure, At: clock.Now()})
	clock.Advance(2 * time.Millisecond)
	// Recover transport only via half-open settlement (two independent successes).
	for i := 0; i < 2; i++ {
		permit, ok := health.TryAcquireDomainPermitHandle(handle, DomainTransport, "tcp/ipv4", "", clock.Now())
		if !ok {
			t.Fatalf("transport permit %d", i)
		}
		permit.CompleteDomains(map[FailureDomain]ObservationOutcome{DomainTransport: OutcomeSuccess}, clock.Now(), time.Millisecond, "")
		clock.Advance(time.Millisecond)
	}
	transport := health.StatusHandle(handle, DomainTransport, "tcp/ipv4", "")
	service := health.StatusHandle(handle, DomainService, "", "svc")
	if transport.Breaker != BreakerClosed || transport.Health != HealthHealthy {
		t.Fatalf("transport did not recover independently: %+v", transport)
	}
	if service.Breaker == BreakerClosed && service.Health == HealthHealthy {
		t.Fatalf("service recovered from transport success: %+v", service)
	}
}

func TestCandidateScoreDeprioritizesProviderReplica(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	primary := Candidate{ID: NodeID{1}, Handle: NodeHandle{NodeID: NodeID{1}, Slot: 1, Version: 1}, PrimaryTag: "airport/hk-1", EndpointConflictCount: 2}
	replica := Candidate{ID: NodeID{2}, Handle: NodeHandle{NodeID: NodeID{2}, Slot: 2, Version: 1}, PrimaryTag: "airport/hk-1 (2)", EndpointConflictCount: 2}
	for _, c := range []Candidate{primary, replica} {
		health.Observe(Observation{NodeID: c.ID, NodeSlot: c.Handle.Slot, NodeVersion: c.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, Delay: 100 * time.Millisecond})
	}
	engine := NewPolicyEngine(health, 2, "fallback")
	service := ServiceContext{ID: "site:example.com", Mode: ModeAdaptive, Transport: N.NetworkTCP}
	primaryScore := engine.candidateScore(primary, service)
	replicaScore := engine.candidateScore(replica, service)
	if replicaScore.SelectionScore <= primaryScore.SelectionScore {
		t.Fatalf("replica was not deprioritized: primary=%d replica=%d", primaryScore.SelectionScore, replicaScore.SelectionScore)
	}
	// Primary with endpoint conflict gets +2s; replica tag gets +8s → gap ≥ 5s.
	if replicaScore.WeightedDelay < primaryScore.WeightedDelay+5*time.Second {
		t.Fatalf("replica delay bias missing: primary=%s replica=%s", primaryScore.WeightedDelay, replicaScore.WeightedDelay)
	}
}
