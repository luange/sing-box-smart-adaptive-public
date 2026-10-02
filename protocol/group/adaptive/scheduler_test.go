package adaptive

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func newProbeTestPool(t *testing.T, ctx context.Context, health *HealthStore) (*AdaptivePool, Candidate) {
	t.Helper()
	manager := NewRuntimeManager()
	identity := prepareEpochForTest(t, manager, "probe-group", identitySnapshot(1, IdentityNode{NodeID: NodeID{21}, IdentityStable: true}))
	execution := newTestOutbound("probe")
	candidate := Candidate{ID: NodeID{21}, Handle: identity.Handles[NodeID{21}], PrimaryTag: "probe", Transport: []string{N.NetworkTCP}}
	p := &AdaptivePool{
		ctx:                 ctx,
		groupID:             "probe-group",
		runtimeManager:      manager,
		health:              health,
		probeURL:            "test://probe",
		probeTimeout:        time.Second,
		observationIngestor: NewObservationIngestor(nil, nil, time.Minute, 128),
		probeRunner:         func(context.Context, string, N.Dialer) (uint16, error) { return 0, context.DeadlineExceeded },
	}
	p.catalog = NewCatalogPort()
	view := installTestCatalog(p.catalog, []Candidate{candidate}, execution)
	view.RuntimeEpochID = identity.EpochID
	view.CatalogRevision = identity.Revision
	view.Generation = identity.SourceGeneration
	p.catalog.current.bindings.epochID = identity.EpochID
	p.catalog.current.bindings.revision = identity.Revision
	return p, candidate
}

func TestProbeTimeoutIsFailureButRuntimeRetireIsDeferred(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	runtimeCtx, cancel := context.WithCancel(context.Background())
	p, candidate := newProbeTestPool(t, runtimeCtx, health)
	task := p.probeTask(p.catalog.load(), candidate, time.Time{}, 0)
	result := task.Run(context.Background())
	if result.Outcome != OutcomeFailure || !result.Settled {
		t.Fatalf("active probe timeout was deferred: %+v", result)
	}
	if status := health.EndpointHandle(candidate.Handle); status.Failures != 0 || status.NonBreakerFailures != 1 || status.Health != HealthDegraded || status.Breaker != BreakerClosed {
		t.Fatalf("single-target probe timeout changed breaker state: %+v", status)
	}
	cancel()
	result = task.Run(context.Background())
	if result.Outcome != OutcomeDeferred || !result.Settled {
		t.Fatalf("retired runtime probe was not deferred: %+v", result)
	}
	if status := health.EndpointHandle(candidate.Handle); status.Failures != 0 || status.NonBreakerFailures != 1 {
		t.Fatalf("runtime retirement changed health: %+v", status)
	}
}

func TestRetiredProbeHandleCannotRunAgainstReaddedOutbound(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, v1 := newProbeTestPool(t, context.Background(), health)
	var runs atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		runs.Add(1)
		close(started)
		<-release
		return 1, nil
	}
	task := pool.probeTask(pool.catalog.load(), v1, time.Time{}, 0)
	resultCh := make(chan ProbeResult, 1)
	go func() { resultCh <- task.Run(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("v1 probe did not enter runner")
	}
	v2 := v1
	v2.Handle.Version = 2
	v2.Handle.BornRevision = 2
	v2Execution := newTestOutbound("probe-v2")
	pool.catalog.access.Lock()
	installTestCatalog(pool.catalog, []Candidate{v2}, v2Execution)
	pool.catalog.access.Unlock()
	close(release)
	result := <-resultCh
	if result.Outcome != OutcomeDeferred || runs.Load() != 1 {
		t.Fatalf("retired v1 task ran against v2: result=%+v runs=%d", result, runs.Load())
	}
	if old := health.EndpointHandle(v1.Handle); old.Health != HealthUnknown || old.Successes != 0 || old.Failures != 0 {
		t.Fatalf("retired v1 task wrote v1 health: %+v", old)
	}
	if current := health.EndpointHandle(v2.Handle); current.Health != HealthUnknown || current.Successes != 0 || current.Failures != 0 {
		t.Fatalf("retired v1 task wrote v2 health: %+v", current)
	}
}

func TestPassiveProbeSuccessCannotCloseOpenBreaker(t *testing.T) {
	health, clock := newBreakerTestStore()
	nodeID := NodeID{22}
	for range 3 {
		health.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	health.Observe(Observation{NodeID: nodeID, Scope: DomainEndpoint, Outcome: OutcomeSuccess, At: clock.Now()})
	status := health.Endpoint(nodeID)
	if status.Breaker != BreakerOpen || status.Successes != 0 {
		t.Fatalf("passive success bypassed open breaker: %+v", status)
	}
}

var _ adapter.Outbound = (*testOutbound)(nil)

func TestProbeSchedulerCompletesFairBoundedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scheduler := NewProbeScheduler(ctx, 4, 128)
	defer scheduler.Close()

	var active atomic.Int64
	var maximum atomic.Int64
	completed := make(chan string, 40)
	for index := 0; index < 40; index++ {
		source := "a"
		if index%2 == 1 {
			source = "b"
		}
		task := ProbeTask{
			Key:     ProbeKey{NodeID: NodeID{byte(index + 1)}, Suite: "test"},
			Source:  source,
			Timeout: time.Second,
			Run: func(context.Context) ProbeResult {
				current := active.Add(1)
				for {
					observed := maximum.Load()
					if current <= observed || maximum.CompareAndSwap(observed, current) {
						break
					}
				}
				time.Sleep(2 * time.Millisecond)
				active.Add(-1)
				return ProbeResult{Outcome: OutcomeSuccess}
			},
			Observe: func(task ProbeTask, _ ProbeResult) { completed <- task.Source },
		}
		if err := scheduler.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	counts := map[string]int{}
	deadline := time.After(3 * time.Second)
	for range 40 {
		select {
		case source := <-completed:
			counts[source]++
		case <-deadline:
			t.Fatalf("scheduler starved work: %v", counts)
		}
	}
	if counts["a"] != 20 || counts["b"] != 20 {
		t.Fatalf("sources were not fairly completed: %v", counts)
	}
	if maximum.Load() > 4 {
		t.Fatalf("worker limit exceeded: %d", maximum.Load())
	}
}

func TestProbeSchedulerCoalescesDuplicateKey(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 4)
	defer scheduler.Close()
	release := make(chan struct{})
	var observations atomic.Int64
	var once sync.Once
	task := ProbeTask{
		Key:     ProbeKey{NodeID: NodeID{1}, Suite: "test"},
		DueAt:   time.Now().Add(20 * time.Millisecond),
		Timeout: time.Second,
		Run: func(context.Context) ProbeResult {
			once.Do(func() { close(release) })
			return ProbeResult{Outcome: OutcomeSuccess}
		},
		Observe: func(ProbeTask, ProbeResult) { observations.Add(1) },
	}
	for range 3 {
		if err := scheduler.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-release:
	case <-time.After(time.Second):
		t.Fatal("coalesced task did not run")
	}
	time.Sleep(20 * time.Millisecond)
	if observations.Load() != 1 {
		t.Fatalf("duplicate task ran more than once: %d", observations.Load())
	}
}

func TestProbeSchedulerCoalescesDuplicateKeyWhileInFlight(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 128)
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int64
	var once sync.Once
	task := ProbeTask{
		Key:               ProbeKey{NodeID: NodeID{9}, Suite: "in-flight"},
		Timeout:           time.Second,
		FreshAfterCurrent: true,
		Run: func(context.Context) ProbeResult {
			runs.Add(1)
			once.Do(func() { close(started) })
			<-release
			return ProbeResult{Outcome: OutcomeSuccess}
		},
	}
	if err := scheduler.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first probe did not start")
	}
	for range 100 {
		if err := scheduler.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := scheduler.Close(); err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 2 {
		t.Fatalf("in-flight duplicate probes were not coalesced to one rerun: %d", runs.Load())
	}
}

func TestProbeSchedulerCloseIsIdempotent(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 4)
	if err := scheduler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProbeSchedulerManualTriggerKeepsRecurringSchedule(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 16)
	defer scheduler.Close()
	var runs atomic.Int64
	task := ProbeTask{
		Key:      ProbeKey{NodeID: NodeID{10}, Suite: "recurring"},
		Interval: 5 * time.Millisecond,
		Timeout:  time.Second,
		Run: func(context.Context) ProbeResult {
			runs.Add(1)
			// Deferred keeps the explicit short interval. Successful production
			// coverage probes intentionally enter the 5m/15m/30m stable backoff.
			return ProbeResult{Outcome: OutcomeDeferred}
		},
	}
	if err := scheduler.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	manual := task
	manual.Interval = 0
	for range 20 {
		if err := scheduler.Enqueue(manual); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for runs.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runs.Load() < 5 {
		t.Fatalf("manual trigger canceled recurring schedule: runs=%d", runs.Load())
	}
}

func TestProbeSchedulerCoversOneHundredTwentyFiveCandidates(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 5, 256)
	defer scheduler.Close()
	completed := make(chan NodeID, 125)
	for index := 0; index < 125; index++ {
		nodeID := NodeID{byte(index), byte(index >> 8)}
		if err := scheduler.Enqueue(ProbeTask{
			Key:     ProbeKey{NodeID: nodeID, Suite: "coverage"},
			Source:  "provider-" + string(rune('a'+index%5)),
			Timeout: time.Second,
			Run:     func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} },
			Observe: func(task ProbeTask, _ ProbeResult) { completed <- task.Key.NodeID },
		}); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[NodeID]bool, 125)
	deadline := time.After(3 * time.Second)
	for len(seen) < 125 {
		select {
		case nodeID := <-completed:
			seen[nodeID] = true
		case <-deadline:
			t.Fatalf("coverage stopped at %d/125", len(seen))
		}
	}
}
