package adaptive

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type dialTestOutbound struct {
	outbound.Adapter
	delay time.Duration
	err   error
	peers chan net.Conn
	dials atomic.Int64
}

type udpRecoveryOutbound struct {
	outbound.Adapter
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

type memoryPacketConn struct{}

type retryBindingBridge struct{ ports map[NodeHandle]ExecutionPort }

func (b retryBindingBridge) AcquireExecution(token ExecutionToken) (*ExecutionLease, bool) {
	port, loaded := b.ports[token.Handle]
	if !loaded {
		return nil, false
	}
	return &ExecutionLease{Port: port}, true
}

func retryCandidate(id byte, tag string) Candidate {
	return Candidate{ID: NodeID{id}, Handle: NodeHandle{NodeID: NodeID{id}, Slot: uint64(id), Version: 1}, PrimaryTag: tag, Transport: []string{N.NetworkTCP, N.NetworkUDP}}
}

func retryRunner(timeout, hedge time.Duration, candidates []Candidate, executions ...ExecutionPort) *AttemptRunner {
	ports := make(map[NodeHandle]ExecutionPort)
	for index, candidate := range candidates {
		ports[candidate.Handle] = executions[index]
	}
	return NewAttemptRunner(timeout, hedge, retryBindingBridge{ports: ports})
}

func installTestCatalog(catalog *CatalogPort, candidates []Candidate, executions ...ExecutionPort) *ExecutionSnapshot {
	view := testExecutionSnapshot(candidates...)
	if view.RuntimeEpochID == 0 {
		view.RuntimeEpochID = 1
	}
	if view.CatalogRevision == 0 {
		view.CatalogRevision = 1
	}
	if view.Generation == 0 {
		view.Generation = 1
	}
	ports := make(map[NodeHandle]ExecutionPort, len(candidates))
	for index, candidate := range candidates {
		ports[candidate.Handle] = executions[index]
	}
	catalog.current = &committedCatalog{view: view, bindings: &EpochBindingSet{epochID: view.RuntimeEpochID, revision: view.CatalogRevision, ports: ports}}
	return view
}

func (*memoryPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*memoryPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (*memoryPacketConn) Close() error                     { return nil }
func (*memoryPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*memoryPacketConn) SetDeadline(time.Time) error      { return nil }
func (*memoryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }

func newUDPRecoveryOutbound(tag string) *udpRecoveryOutbound {
	return &udpRecoveryOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkUDP}, nil),
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func (o *udpRecoveryOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	o.calls.Add(1)
	o.started <- struct{}{}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-o.release:
	}
	return new(memoryPacketConn), nil
}

func (*udpRecoveryOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("tcp not implemented")
}

func newUDPRecoveryPool(t *testing.T, health *HealthStore, candidate Candidate, execution ExecutionPort) *AdaptivePool {
	t.Helper()
	pool := &AdaptivePool{
		resolver:         NewServiceResolver(testIdentityHasher(t), ModeAdaptive),
		leases:           NewSessionLeaseManager(32),
		health:           health,
		policy:           NewPolicyEngine(health, 1, "fallback"),
		runner:           nil,
		strictLeaseTTL:   time.Minute,
		adaptiveLeaseTTL: time.Minute,
		defaultMode:      ModeAdaptive,
	}
	pool.catalog = NewCatalogPort()
	installTestCatalog(pool.catalog, []Candidate{candidate}, execution)
	pool.runner = NewAttemptRunner(time.Second, time.Second, pool.catalog)
	return pool
}

func udpFlowContext(port uint16) context.Context {
	return adapter.WithContext(context.Background(), &adapter.InboundContext{Inbound: "mixed-in", Source: M.Socksaddr{Addr: M.ParseSocksaddr("192.0.2.1:1").Addr, Port: port}})
}

func newDialTestOutbound(tag string, delay time.Duration, err error) *dialTestOutbound {
	return &dialTestOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil),
		delay:   delay,
		err:     err,
		peers:   make(chan net.Conn, 1),
	}
}

func (o *dialTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	if o.delay > 0 {
		timer := time.NewTimer(o.delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if o.err != nil {
		return nil, o.err
	}
	local, peer := net.Pipe()
	o.peers <- peer
	return local, nil
}

func TestAdaptivePoolReusesNodeAcrossYouTubeDomains(t *testing.T) {
	hasher := testIdentityHasher(t)
	firstOutbound := newDialTestOutbound("first", 0, nil)
	secondOutbound := newDialTestOutbound("second", 0, nil)
	first := retryCandidate(1, "first")
	second := retryCandidate(2, "second")
	health := NewHealthStore(time.Hour, 32)
	pool := &AdaptivePool{
		resolver:         NewServiceResolver(hasher, ModeAdaptive),
		leases:           NewSessionLeaseManager(32),
		health:           health,
		policy:           NewPolicyEngine(health, 2, "fallback"),
		runner:           nil,
		strictLeaseTTL:   time.Minute,
		adaptiveLeaseTTL: time.Minute,
		defaultMode:      ModeAdaptive,
	}
	pool.catalog = NewCatalogPort()
	installTestCatalog(pool.catalog, []Candidate{first, second}, firstOutbound, secondOutbound)
	pool.runner = NewAttemptRunner(time.Second, 100*time.Millisecond, pool.catalog)
	metadata := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	ctx := adapter.WithContext(context.Background(), metadata)
	controlConn, err := pool.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("youtube.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	controlConn.Close()
	(<-firstOutbound.peers).Close()
	mediaConn, err := pool.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("r1.googlevideo.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	mediaConn.Close()
	(<-firstOutbound.peers).Close()
	if firstOutbound.dials.Load() != 2 || secondOutbound.dials.Load() != 0 {
		t.Fatalf("YouTube lease split exits: first=%d second=%d", firstOutbound.dials.Load(), secondOutbound.dials.Load())
	}
}

func TestStrictAffinityFailureRetainsIdentityUntilBreakerOpens(t *testing.T) {
	hasher := testIdentityHasher(t)
	failedOutbound := newDialTestOutbound("failed", 0, errors.New("failed"))
	workingOutbound := newDialTestOutbound("working", 0, nil)
	failed := retryCandidate(11, "failed")
	working := retryCandidate(12, "working")
	health := NewHealthStore(time.Hour, 32)
	resolver := NewServiceResolver(hasher, ModeAdaptive)
	leases := NewSessionLeaseManager(32)
	pool := &AdaptivePool{
		resolver: resolver, leases: leases, health: health,
		policy:         NewPolicyEngine(health, 2, "fallback"),
		strictLeaseTTL: time.Minute, adaptiveLeaseTTL: time.Minute,
	}
	pool.catalog = NewCatalogPort()
	installTestCatalog(pool.catalog, []Candidate{failed, working}, failedOutbound, workingOutbound)
	pool.runner = NewAttemptRunner(time.Second, time.Second, pool.catalog)
	metadata := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.20:2000")}
	destination := M.ParseSocksaddr("youtube.com:443")
	service := resolver.Resolve(metadata, destination, N.NetworkTCP)
	_, reservation, err := leases.Reserve(context.Background(), service.Session, time.Now())
	if err != nil || reservation == nil {
		t.Fatalf("reserve strict lease: reservation=%v err=%v", reservation, err)
	}
	reservation.CommitHandle(failed.Handle, service.ID, service.Mode, time.Minute, time.Now())
	ctx := adapter.WithContext(context.Background(), metadata)
	if _, err = pool.DialContext(ctx, N.NetworkTCP, destination); err == nil {
		t.Fatal("single leased-node failure unexpectedly fell through to a new identity")
	}
	lease, loaded := leases.Peek(service.Session, time.Now())
	if !loaded || lease.NodeID != failed.ID {
		t.Fatalf("transient failure changed strict identity: loaded=%v lease=%+v", loaded, lease)
	}
	if failedOutbound.dials.Load() != 1 || workingOutbound.dials.Load() != 0 {
		t.Fatalf("transient strict failure attempted another identity: failed=%d working=%d", failedOutbound.dials.Load(), workingOutbound.dials.Load())
	}
	for range 3 {
		health.Observe(Observation{NodeID: failed.ID, NodeSlot: failed.Handle.Slot, NodeVersion: failed.Handle.Version, Scope: DomainTransport, Transport: N.NetworkTCP, Outcome: OutcomeFailure})
	}
	conn, err := pool.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	(<-workingOutbound.peers).Close()
	lease, loaded = leases.Peek(service.Session, time.Now())
	if !loaded || lease.NodeID != working.ID || lease.NodeSlot != working.Handle.Slot || lease.NodeVersion != working.Handle.Version {
		t.Fatalf("breaker failover did not replace strict lease: loaded=%v lease=%+v", loaded, lease)
	}
}

func (*dialTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestAttemptRunnerFailsOverBeforeReturningToApp(t *testing.T) {
	firstOutbound := newDialTestOutbound("first", 0, errors.New("failed"))
	secondOutbound := newDialTestOutbound("second", 0, nil)
	first := retryCandidate(1, "first")
	second := retryCandidate(2, "second")
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Candidates: []Candidate{first, second}}
	runner := retryRunner(time.Second, 50*time.Millisecond, plan.Candidates, firstOutbound, secondOutbound)
	var observations []DialAttemptResult
	var access sync.Mutex
	begin := func(_ Candidate, permit *AttemptPermit) (AttemptComplete, error) {
		return func(observation DialAttemptResult) {
			permit.ReleaseDeferred()
			access.Lock()
			observations = append(observations, observation)
			access.Unlock()
		}, nil
	}
	conn, selected, err := runner.Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, begin)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-secondOutbound.peers).Close()
	if selected.ID != (NodeID{2}) {
		t.Fatalf("fallback selected wrong node: %s", selected.PrimaryTag)
	}
	if len(observations) != 2 || observations[0].Err == nil || observations[1].Err != nil {
		t.Fatalf("unexpected failover observations: %+v", observations)
	}
}

func TestAttemptRunnerHedgeDoesNotPenalizeCanceledLoser(t *testing.T) {
	firstOutbound := newDialTestOutbound("slow", 500*time.Millisecond, nil)
	secondOutbound := newDialTestOutbound("fast", 5*time.Millisecond, nil)
	first := retryCandidate(1, "slow")
	second := retryCandidate(2, "fast")
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Candidates: []Candidate{first, second}}
	runner := retryRunner(time.Second, 20*time.Millisecond, plan.Candidates, firstOutbound, secondOutbound)
	var observations []DialAttemptResult
	var access sync.Mutex
	startedAt := time.Now()
	begin := func(_ Candidate, permit *AttemptPermit) (AttemptComplete, error) {
		return func(observation DialAttemptResult) {
			permit.ReleaseDeferred()
			access.Lock()
			observations = append(observations, observation)
			access.Unlock()
		}, nil
	}
	conn, selected, err := runner.Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, begin)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-secondOutbound.peers).Close()
	if selected.ID != (NodeID{2}) || time.Since(startedAt) >= 200*time.Millisecond {
		t.Fatalf("hedge did not win promptly: selected=%s elapsed=%s", selected.PrimaryTag, time.Since(startedAt))
	}
	time.Sleep(30 * time.Millisecond)
	access.Lock()
	defer access.Unlock()
	var successful, deferred int
	for _, observation := range observations {
		if observation.Err == nil {
			successful++
		}
		if observation.Deferred {
			deferred++
		}
	}
	if successful != 1 || deferred > 1 {
		t.Fatalf("canceled loser contaminated health: %+v", observations)
	}
}

func TestBreakerAllDeferredNeverReturnsNilConnectionAndNilError(t *testing.T) {
	health, clock := newBreakerTestStore()
	nodeID := NodeID{9}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	handle := NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	held, allowed := health.TryAcquireAttemptPermitHandle(handle, service, clock.Now())
	if !allowed {
		t.Fatal("failed to establish held half-open token")
	}
	defer held.ReleaseDeferred()
	outbound := newDialTestOutbound("deferred", 0, nil)
	candidate := Candidate{ID: nodeID, Handle: NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}, PrimaryTag: "deferred"}
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Candidates: []Candidate{candidate}, health: health, service: service}
	conn, _, err := retryRunner(time.Second, time.Second, plan.Candidates, outbound).Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, nil)
	if conn != nil || err == nil || !errors.Is(err, ErrBreakerAttemptDeferred) {
		t.Fatalf("all-deferred result was not explicit: conn=%v err=%v", conn, err)
	}
}

func TestDialWaitsForRuntimeEpochPublication(t *testing.T) {
	pool := &AdaptivePool{publishPhase: publishPhasePrepared}
	done := make(chan error, 1)
	go func() { done <- pool.waitUntilPublished(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("startup gate returned before publication: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	pool.lifecycleAccess.Lock()
	pool.publishPhase = publishPhaseActive
	pool.published = true
	pool.lifecycleAccess.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup gate did not release after publication")
	}
}

func TestDialPublicationGateHonorsCancellation(t *testing.T) {
	pool := &AdaptivePool{publishPhase: publishPhasePrepared}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pool.waitUntilPublished(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("startup gate ignored cancellation: %v", err)
	}
}

func TestBulkRunnerDoesNotSpeculateButFailsOverImmediately(t *testing.T) {
	first := newDialTestOutbound("bulk-slow", 120*time.Millisecond, nil)
	second := newDialTestOutbound("bulk-unused", 0, nil)
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Mode: ModeBulk, Candidates: []Candidate{
		{ID: NodeID{31}, Handle: NodeHandle{NodeID: NodeID{31}, Slot: 1, Version: 1}, PrimaryTag: "bulk-slow"},
		{ID: NodeID{32}, Handle: NodeHandle{NodeID: NodeID{32}, Slot: 2, Version: 1}, PrimaryTag: "bulk-unused"},
	}}
	runner := retryRunner(time.Second, 10*time.Millisecond, plan.Candidates, first, second)
	done := make(chan error, 1)
	go func() {
		conn, _, err := runner.Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, nil)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	time.Sleep(40 * time.Millisecond)
	if second.dials.Load() != 0 {
		t.Fatalf("bulk mode speculatively duplicated a connection: dials=%d", second.dials.Load())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	(<-first.peers).Close()

	failing := newDialTestOutbound("bulk-failure", 20*time.Millisecond, errors.New("failed"))
	fallback := newDialTestOutbound("bulk-fallback", 0, nil)
	plan.Candidates[0] = Candidate{ID: NodeID{33}, Handle: NodeHandle{NodeID: NodeID{33}, Slot: 3, Version: 1}, PrimaryTag: "bulk-failure"}
	plan.Candidates[1] = Candidate{ID: NodeID{34}, Handle: NodeHandle{NodeID: NodeID{34}, Slot: 4, Version: 1}, PrimaryTag: "bulk-fallback"}
	runner = retryRunner(time.Second, time.Second, plan.Candidates, failing, fallback)
	startedAt := time.Now()
	conn, selected, err := runner.Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	(<-fallback.peers).Close()
	if selected.ID != (NodeID{34}) || time.Since(startedAt) >= 300*time.Millisecond {
		t.Fatalf("bulk failure did not trigger immediate fallback: selected=%+v elapsed=%s", selected.ID, time.Since(startedAt))
	}
}

func TestAdaptivePoolBulkConnectionsRotateWithoutSessionLease(t *testing.T) {
	firstOutbound := newDialTestOutbound("bulk-a", 0, nil)
	secondOutbound := newDialTestOutbound("bulk-b", 0, nil)
	first := Candidate{ID: NodeID{41}, Handle: NodeHandle{NodeID: NodeID{41}, Slot: 1, Version: 1}, PrimaryTag: "bulk-a"}
	second := Candidate{ID: NodeID{42}, Handle: NodeHandle{NodeID: NodeID{42}, Slot: 2, Version: 1}, PrimaryTag: "bulk-b"}
	health := NewHealthStore(time.Hour, 16)
	pool := &AdaptivePool{
		resolver: NewServiceResolver(testIdentityHasher(t), ModeBulk), leases: NewSessionLeaseManager(16), health: health,
		policy:  NewPolicyEngine(health, 2, "fallback"),
		catalog: NewCatalogPort(), control: new(ControlState),
	}
	installTestCatalog(pool.catalog, []Candidate{first, second}, firstOutbound, secondOutbound)
	pool.runner = NewAttemptRunner(time.Second, 10*time.Millisecond, pool.catalog)
	for range 2 {
		conn, err := pool.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("downloads.example.com:443"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		select {
		case peer := <-firstOutbound.peers:
			_ = peer.Close()
		case peer := <-secondOutbound.peers:
			_ = peer.Close()
		case <-time.After(time.Second):
			t.Fatal("bulk dial did not return a peer")
		}
	}
	if firstOutbound.dials.Load() != 1 || secondOutbound.dials.Load() != 1 {
		t.Fatalf("bulk connections did not rotate: first=%d second=%d", firstOutbound.dials.Load(), secondOutbound.dials.Load())
	}
	if active, _ := pool.leases.Stats(); active != 0 {
		t.Fatalf("bulk mode created session leases: %d", active)
	}
}

func TestBreakerUnstartedHedgeDoesNotLeakHalfOpenToken(t *testing.T) {
	health, clock := newBreakerTestStore()
	firstID, secondID := NodeID{10}, NodeID{11}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	for range 3 {
		health.Observe(Observation{NodeID: secondID, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	first := newDialTestOutbound("first", 0, nil)
	second := newDialTestOutbound("second", 0, nil)
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Candidates: []Candidate{{ID: firstID, Handle: NodeHandle{NodeID: firstID, Slot: 1, Version: 1}, PrimaryTag: "first"}, {ID: secondID, Handle: NodeHandle{NodeID: secondID, Slot: 2, Version: 1}, PrimaryTag: "second"}}, health: health, service: service}
	conn, _, err := retryRunner(time.Second, 200*time.Millisecond, plan.Candidates, first, second).Dial(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	(<-first.peers).Close()
	if second.dials.Load() != 0 {
		t.Fatalf("later hedge unexpectedly started: dials=%d", second.dials.Load())
	}
	permit, allowed := health.TryAcquireAttemptPermit(secondID, service, clock.Now())
	if !allowed {
		t.Fatal("unstarted hedge leaked the half-open token")
	}
	permit.ReleaseDeferred()
}

func TestBreakerCanceledAttemptReleasesTokenWithoutFailure(t *testing.T) {
	health, clock := newBreakerTestStore()
	nodeID := NodeID{12}
	handle := NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}
	service := ServiceContext{ID: "service", Transport: N.NetworkTCP}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	outbound := newDialTestOutbound("slow", time.Second, nil)
	plan := DecisionPlan{RuntimeEpochID: 1, CatalogRevision: 1, Candidates: []Candidate{{ID: nodeID, Handle: handle, PrimaryTag: "slow"}}, health: health, service: service}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, _, err := retryRunner(time.Second, time.Second, plan.Candidates, outbound).Dial(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"), plan, nil)
	if conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected canceled result: conn=%v err=%v", conn, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		permit, allowed := health.TryAcquireAttemptPermitHandle(handle, service, clock.Now())
		if allowed {
			permit.ReleaseDeferred()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled attempt did not release half-open token")
		}
		time.Sleep(time.Millisecond)
	}
	if status := health.EndpointHandle(handle); status.Failures != 3 {
		t.Fatalf("cancellation was counted as failure: %+v", status)
	}
}

func TestBreakerUDPRecoveryAllowsOnlyOneListenPacket(t *testing.T) {
	health, clock := newBreakerTestStore()
	nodeID := NodeID{13}
	handle := NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	outbound := newUDPRecoveryOutbound("udp")
	candidate := Candidate{ID: nodeID, Handle: NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}, PrimaryTag: "udp", Transport: []string{N.NetworkUDP}}
	pool := newUDPRecoveryPool(t, health, candidate, outbound)
	type result struct {
		conn net.PacketConn
		err  error
	}
	firstDone := make(chan result, 1)
	go func() {
		conn, err := pool.ListenPacket(udpFlowContext(1001), M.ParseSocksaddr("example.com:443"))
		firstDone <- result{conn: conn, err: err}
	}()
	select {
	case <-outbound.started:
	case <-time.After(time.Second):
		t.Fatal("first UDP recovery did not start")
	}
	secondConn, secondErr := pool.ListenPacket(udpFlowContext(1002), M.ParseSocksaddr("other.example.net:443"))
	if secondConn != nil || secondErr == nil {
		t.Fatalf("second UDP recovery bypassed half-open token: conn=%v err=%v", secondConn, secondErr)
	}
	close(outbound.release)
	first := <-firstDone
	if first.err != nil || first.conn == nil {
		t.Fatalf("first UDP recovery failed: conn=%v err=%v", first.conn, first.err)
	}
	first.conn.Close()
	if outbound.calls.Load() != 1 {
		t.Fatalf("half-open performed %d ListenPacket calls", outbound.calls.Load())
	}
}

func TestBreakerUDPCancelReleasesTokenWithoutFailure(t *testing.T) {
	health, clock := newBreakerTestStore()
	nodeID := NodeID{14}
	handle := NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}
	service := ServiceContext{ID: "site:example.com", Transport: N.NetworkUDP}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(10 * time.Second)
	outbound := newUDPRecoveryOutbound("udp-cancel")
	candidate := Candidate{ID: nodeID, Handle: NodeHandle{NodeID: nodeID, Slot: 1, Version: 1}, PrimaryTag: "udp-cancel", Transport: []string{N.NetworkUDP}}
	pool := newUDPRecoveryPool(t, health, candidate, outbound)
	ctx, cancel := context.WithCancel(udpFlowContext(1003))
	done := make(chan error, 1)
	go func() {
		_, err := pool.ListenPacket(ctx, M.ParseSocksaddr("example.com:443"))
		done <- err
	}()
	<-outbound.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected UDP cancel result: %v", err)
	}
	permit, allowed := health.TryAcquireAttemptPermitHandle(handle, service, clock.Now())
	if !allowed {
		t.Fatal("UDP cancellation leaked half-open token")
	}
	permit.ReleaseDeferred()
	if status := health.EndpointHandle(handle); status.Failures != 3 {
		t.Fatalf("UDP cancellation counted as failure: %+v", status)
	}
}
