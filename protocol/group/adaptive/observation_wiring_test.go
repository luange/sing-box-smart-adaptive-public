package adaptive

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type wiredCandidate struct {
	Candidate Candidate
	Execution ExecutionPort
}

func wired(id NodeID, tag string, execution ExecutionPort) wiredCandidate {
	return wiredCandidate{Candidate: Candidate{ID: id, PrimaryTag: tag, Transport: []string{N.NetworkTCP, N.NetworkUDP}}, Execution: execution}
}

func newWiredObservationPool(t *testing.T, health *HealthStore, candidates ...wiredCandidate) (*AdaptivePool, *ExecutionSnapshot) {
	t.Helper()
	manager := NewRuntimeManager()
	groupID := "wired-group"
	nodes := make([]IdentityNode, len(candidates))
	for index := range candidates {
		nodes[index] = IdentityNode{NodeID: candidates[index].Candidate.ID, IdentityStable: true}
	}
	prepared, err := manager.PrepareEpoch(groupID, health, NewSessionLeaseManager(64), new(ControlState), identitySnapshot(1, nodes...))
	if err != nil {
		t.Fatal(err)
	}
	shared, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	catalog := NewCatalogPort()
	source := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: identity.SourceGeneration, Nodes: make([]CanonicalNode, len(candidates))}, Bindings: make(map[NodeID]ExecutionPort, len(candidates))}
	for index := range candidates {
		candidate := candidates[index].Candidate
		source.Nodes[index] = CanonicalNode{NodeID: candidate.ID, SourceKey: candidate.PrimaryTag, Aliases: []string{candidate.PrimaryTag}, Transport: candidate.Transport, IdentityStable: true}
		source.Bindings[candidate.ID] = candidates[index].Execution
	}
	preparedExecution, err := catalog.PrepareCommitted(source, identity)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := catalog.CommitPrepared(preparedExecution)
	pool := &AdaptivePool{
		ctx: context.Background(), groupID: groupID, runtimeManager: manager,
		health: health, leases: shared.leases, control: shared.control,
		resolver: NewServiceResolver(testIdentityHasher(t), ModeAdaptive),
		policy:   NewPolicyEngine(health, len(candidates), "fallback"), runner: NewAttemptRunner(200*time.Millisecond, 10*time.Millisecond, catalog),
		strictLeaseTTL: time.Minute, adaptiveLeaseTTL: time.Minute, defaultMode: ModeAdaptive,
		catalog: catalog, observationIngestor: NewObservationIngestor(nil, nil, time.Minute, 16384),
	}
	pool.runtimeIdentity = identity
	return pool, snapshot
}

type udpFailureOutbound struct {
	outbound.Adapter
	err error
}

func newUDPFailureOutbound(tag string, err error) *udpFailureOutbound {
	return &udpFailureOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkUDP}, nil), err: err}
}
func (o *udpFailureOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, o.err
}
func (o *udpFailureOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("tcp unsupported")
}

func TestDestinationFailuresOpenTransportButNotEndpoint(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 64, realClock{}, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	tcp := newDialTestOutbound("tcp-refused", 0, errors.New("connection refused"))
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{71}, "tcp-refused", tcp))
	for index := 0; index < 3; index++ {
		_, _ = pool.DialContext(udpFlowContext(uint16(2000+index)), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	}
	handle := snapshot.Candidates[0].Handle
	if endpoint := health.EndpointHandle(handle); endpoint.Breaker != BreakerClosed || endpoint.Failures != 0 {
		t.Fatalf("destination failure polluted endpoint: %+v", endpoint)
	}
	if transport := health.StatusHandle(handle, DomainTransport, "tcp/any", ""); transport.Breaker != BreakerOpen || transport.Failures != 3 {
		t.Fatalf("transport breaker did not open: %+v", transport)
	}

	udpHealth := NewHealthStoreWithClock(time.Hour, 64, realClock{}, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	udpPool, udpSnapshot := newWiredObservationPool(t, udpHealth, wired(NodeID{72}, "udp-refused", newUDPFailureOutbound("udp-refused", errors.New("udp destination refused"))))
	for index := 0; index < 3; index++ {
		_, _ = udpPool.ListenPacket(udpFlowContext(uint16(2100+index)), M.ParseSocksaddr("example.com:443"))
	}
	udpHandle := udpSnapshot.Candidates[0].Handle
	if endpoint := udpHealth.EndpointHandle(udpHandle); endpoint.Breaker != BreakerClosed || endpoint.Failures != 0 {
		t.Fatalf("UDP destination failure polluted endpoint: %+v", endpoint)
	}
	if transport := udpHealth.StatusHandle(udpHandle, DomainTransport, "udp_data/any", ""); transport.Breaker != BreakerOpen || transport.Failures != 3 {
		t.Fatalf("UDP transport breaker did not open: %+v", transport)
	}
}

func TestAdaptiveStatusExposesAllNetworkHealthPaths(t *testing.T) {
	health := NewHealthStore(time.Hour, 64)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{93}, "path-status", newTestOutbound("path-status")))
	handle := snapshot.Candidates[0].Handle
	for range 3 {
		health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainTransport, Transport: "udp_dns/ipv6", Outcome: OutcomeFailure, At: time.Now(), Reason: "dns timeout"})
	}
	status := pool.AdaptiveStatus()
	if len(status.Candidates) != 1 || len(status.Candidates[0].Paths) != len(observableHealthPaths) {
		t.Fatalf("network paths missing from status: %+v", status.Candidates)
	}
	candidate := status.Candidates[0]
	if candidate.Capabilities == nil || !candidate.Capabilities.Known {
		t.Fatalf("capability portrait missing from status: %+v", candidate.Capabilities)
	}
	if candidate.Capabilities.DNSUDPv6.Available || !candidate.Capabilities.DNSUDPv6.Known ||
		(candidate.Capabilities.DNSUDPv6.State != PathStateOpen && candidate.Capabilities.DNSUDPv6.State != PathStateUnreachable && candidate.Capabilities.DNSUDPv6.State != PathStateCooldown) {
		t.Fatalf("DNS UDP/IPv6 should be unavailable in capability portrait: %+v", candidate.Capabilities)
	}
	if len(candidate.FilterReasons) == 0 {
		t.Fatalf("expected multi-path filter reasons for broken DNS path: %+v", candidate)
	}
	if !candidate.Capabilities.TCP4.Available || candidate.Capabilities.TCP4.Known || candidate.Capabilities.TCP4.State != "unknown" {
		t.Fatalf("unknown TCP4 path should remain explicitly fail-open: %+v", candidate.Capabilities.TCP4)
	}
	for _, path := range candidate.Paths {
		if path.Path == "udp_dns/ipv6" {
			if path.Failures != 3 || path.Health != string(HealthUnreachable) || path.Reason != "dns timeout" {
				t.Fatalf("DNS/IPv6 path status mismatch: %+v", path)
			}
			return
		}
	}
	t.Fatal("DNS/IPv6 path was not exposed")
}

func TestOldProbeTaskDefersUntilCurrentRevisionTaskRuns(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, oldSnapshot := newWiredObservationPool(t, health, wired(NodeID{73}, "probe-v1", newTestOutbound("probe-v1")))
	oldCandidate := oldSnapshot.Candidates[0]
	task := pool.probeTask(oldSnapshot, oldCandidate, time.Time{}, 0)
	newOutbound := newTestOutbound("probe-v2")
	source := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 2, Nodes: []CanonicalNode{{NodeID: oldCandidate.ID, SourceKey: "probe-v2", Aliases: []string{"probe-v2"}, Transport: []string{"tcp"}, IdentityStable: true}}}, Bindings: map[NodeID]ExecutionPort{oldCandidate.ID: newOutbound}}
	identitySource, _ := IdentityFromSource(source.SourceSnapshot)
	prepared, err := pool.runtimeManager.PrepareRevision(pool.groupID, oldSnapshot.RuntimeEpochID, identitySource)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := pool.catalog.PrepareCommitted(source, prepared.Identity())
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	current := pool.catalog.CommitPrepared(execution)
	pool.runtimeIdentity = identity
	captured := make(chan ObservationEvidence, 1)
	pool.observationReducerHook = func(e ObservationEvidence, _ []DomainEvidence) error { captured <- e; return nil }
	var runs atomic.Int32
	pool.probeRunner = func(_ context.Context, _ string, dialer N.Dialer) (uint16, error) {
		runs.Add(1)
		if dialer != newOutbound {
			t.Error("current task did not execute current outbound")
		}
		return 5, nil
	}
	if result := task.Run(context.Background()); result.Outcome != OutcomeDeferred || runs.Load() != 0 {
		t.Fatalf("old revision task was not retired: result=%+v runs=%d", result, runs.Load())
	}
	currentCandidate, loaded := current.Candidate(oldCandidate.ID)
	if !loaded {
		t.Fatal("current candidate missing")
	}
	if result := pool.probeTask(current, currentCandidate, time.Time{}, 0).Run(context.Background()); result.Outcome != OutcomeSuccess || runs.Load() != 1 {
		t.Fatalf("current revision task failed: result=%+v runs=%d", result, runs.Load())
	}
	evidence := <-captured
	if evidence.CatalogRevision != current.CatalogRevision || evidence.SourceGeneration != current.Generation || evidence.CatalogRevision == oldSnapshot.CatalogRevision {
		t.Fatalf("current outbound was attributed to old revision: evidence=%+v old=%+v current=%+v", evidence, oldSnapshot, current)
	}
}

func TestSingleTargetGenericProbeCannotOpenOrCloseEndpointBreaker(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{78}, "probe", newTestOutbound("probe")))
	handle := snapshot.Candidates[0].Handle
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		return 0, errors.New("probe target unavailable")
	}
	for index := 0; index < 3; index++ {
		result, _ := pool.runGenericProbe(context.Background(), snapshot, snapshot.Candidates[0])
		if result.Outcome != OutcomeFailure {
			t.Fatalf("probe failure was not reported: %+v", result)
		}
	}
	status := health.EndpointHandle(handle)
	if status.Breaker != BreakerClosed || status.Failures != 0 || status.NonBreakerFailures != 3 {
		t.Fatalf("single target failure changed endpoint breaker: %+v", status)
	}

	recoveryHealth := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	recoveryPool, recoverySnapshot := newWiredObservationPool(t, recoveryHealth, wired(NodeID{80}, "recovery-probe", newTestOutbound("recovery-probe")))
	recoveryHandle := recoverySnapshot.Candidates[0].Handle
	recoveryHealth.Observe(Observation{NodeID: recoveryHandle.NodeID, NodeSlot: recoveryHandle.Slot, NodeVersion: recoveryHandle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: time.Now().Add(-time.Second)})
	recoveryPool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) { return 4, nil }
	result, _ := recoveryPool.runGenericProbe(context.Background(), recoverySnapshot, recoverySnapshot.Candidates[0])
	if result.Outcome != OutcomeSuccess {
		t.Fatalf("probe quality success was not reported: %+v", result)
	}
	status = recoveryHealth.EndpointHandle(recoveryHandle)
	if status.Breaker == BreakerClosed || status.Successes != 0 || status.NonBreakerSuccesses != 1 {
		t.Fatalf("single target success recovered endpoint breaker: %+v", status)
	}
}

func TestPoolSharedIngestorDeduplicatesIndependentCallbacks(t *testing.T) {
	clock := &fakeClock{now: time.Unix(5000, 0)}
	health := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{74}, "probe", newTestOutbound("probe")))
	handle := snapshot.Candidates[0].Handle
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	clock.Advance(time.Second)
	permit, allowed := health.TryAcquireDomainPermitHandle(handle, DomainEndpoint, "", "", clock.Now())
	if !allowed {
		t.Fatal("half-open permit unavailable")
	}
	lease, err := pool.runtimeManager.AcquireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	evidence := ObservationEvidence{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation, Handle: handle, AttemptID: 99, Source: SourceProbe, Stage: StageProxyTunnel, Confidence: ConfidenceHigh, Outcome: OutcomeSuccess, Transport: N.NetworkTCP, At: clock.Now()}
	guard := RuntimeEpochObservationGuard{Lease: lease}
	reducer := &HealthObservationReducer{Store: health, Settlement: AttemptPermitSettlement{Permit: permit}}
	if disposition, err := PublishSettledObservationGuarded(pool.sharedObservationIngestor(), guard, evidence, reducer); err != nil || disposition != IngestAccepted {
		t.Fatalf("first callback failed: %s %v", disposition, err)
	}
	if disposition, err := PublishSettledObservationGuarded(pool.sharedObservationIngestor(), guard, evidence, reducer); err != nil || disposition != IngestDuplicate {
		t.Fatalf("independent replay was not deduplicated: %s %v", disposition, err)
	}
	if status := health.EndpointHandle(handle); status.Successes != 1 || status.Breaker != BreakerHalfOpen || status.RecoverySuccesses != 1 {
		t.Fatalf("duplicate settled health more than once: %+v", status)
	}
}

func TestPoolSharedIngestorEnforcesGlobalPendingCapacity(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{79}, "probe", newTestOutbound("probe")))
	pool.observationIngestor = NewObservationIngestor(nil, nil, time.Minute, 1)
	lease, err := pool.runtimeManager.AcquireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	guard := RuntimeEpochObservationGuard{Lease: lease}
	handle := snapshot.Candidates[0].Handle
	evidence := ObservationEvidence{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation, Handle: handle, AttemptID: 700, Source: SourceProbe, Stage: StageProxyTunnel, Confidence: ConfidenceMedium, Outcome: OutcomeSuccess, Transport: N.NetworkTCP, At: time.Now()}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, publishErr := pool.sharedObservationIngestor().PublishGuarded(evidence, guard, ObservationReducerFunc(func(ObservationEvidence, []DomainEvidence) error {
			close(entered)
			<-release
			return nil
		}))
		firstDone <- publishErr
	}()
	<-entered
	second := evidence
	second.AttemptID++
	disposition, err := pool.sharedObservationIngestor().PublishGuarded(second, guard, ObservationReducerFunc(func(ObservationEvidence, []DomainEvidence) error {
		t.Fatal("backpressured evidence reached reducer")
		return nil
	}))
	if err != nil || disposition != IngestBackpressure {
		t.Fatalf("global pending capacity not enforced: disposition=%s err=%v", disposition, err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialReducerFailureReleasesHalfOpenToken(t *testing.T) {
	clock := &fakeClock{now: time.Unix(6000, 0)}
	health := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	dialer := newDialTestOutbound("success", 0, nil)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{75}, "success", dialer))
	handle := snapshot.Candidates[0].Handle
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainTransport, Transport: N.NetworkTCP, Outcome: OutcomeFailure, At: clock.Now()})
	clock.Advance(time.Second)
	pool.observationReducerHook = func(ObservationEvidence, []DomainEvidence) error { return errors.New("injected reducer failure") }
	conn, err := pool.DialContext(udpFlowContext(2200), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-dialer.peers).Close()
	permit, allowed := health.TryAcquireDomainPermitHandle(handle, DomainTransport, N.NetworkTCP, "", clock.Now())
	if !allowed {
		t.Fatal("reducer failure leaked half-open token")
	}
	permit.ReleaseDeferred()
	if status := health.StatusHandle(handle, DomainTransport, N.NetworkTCP, ""); status.Successes != 0 || status.Failures != 1 {
		t.Fatalf("reducer failure settled transport: %+v", status)
	}
}

func TestHedgeLoserCancellationDoesNotPolluteTransport(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	slow := newDialTestOutbound("slow", 500*time.Millisecond, nil)
	fast := newDialTestOutbound("fast", 5*time.Millisecond, nil)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{76}, "slow", slow), wired(NodeID{77}, "fast", fast))
	conn, err := pool.DialContext(udpFlowContext(2300), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-fast.peers).Close()
	time.Sleep(20 * time.Millisecond)
	if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "tcp/any", ""); status.Failures != 0 {
		t.Fatalf("hedge loser polluted transport: %+v", status)
	}
	if status := health.StatusHandle(snapshot.Candidates[1].Handle, DomainTransport, "tcp/any", ""); status.Successes != 1 {
		t.Fatalf("hedge winner was not observed once: %+v", status)
	}
}
