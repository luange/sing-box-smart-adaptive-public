package adaptive

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

func probeTestTask(id byte, priority ProbePriority, run func(context.Context) ProbeResult) ProbeTask {
	return ProbeTask{Key: ProbeKey{NodeID: NodeID{id}, Suite: "test", Target: "test://target"}, Source: "source", Priority: priority, Timeout: time.Second, Run: run}
}

func TestSchedulerCoordinatorHandoffHasSingleOwnerAndOldReleaseCannotRevokeNew(t *testing.T) {
	coordinator := new(SchedulerCoordinator)
	firstToken, err := coordinator.Claim(1)
	if err != nil {
		t.Fatal(err)
	}
	first := newOwnedProbeScheduler(context.Background(), coordinator, firstToken, 1, 8)
	started := make(chan struct{})
	releaseFirst := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	firstSubmission := first.Submit(probeTestTask(1, ProbePriorityCoverage, func(context.Context) ProbeResult {
		current := active.Add(1)
		maximum.Store(max(maximum.Load(), current))
		close(started)
		<-releaseFirst
		active.Add(-1)
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	<-started
	secondToken, err := coordinator.Claim(2)
	if err != nil {
		t.Fatal(err)
	}
	second := newOwnedProbeScheduler(context.Background(), coordinator, secondToken, 1, 8)
	secondRan := make(chan struct{})
	secondSubmission := second.Submit(probeTestTask(3, ProbePriorityCoverage, func(context.Context) ProbeResult {
		current := active.Add(1)
		maximum.Store(max(maximum.Load(), current))
		active.Add(-1)
		close(secondRan)
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	select {
	case <-secondRan:
		t.Fatal("new owner dispatched before old worker drained")
	default:
	}
	close(releaseFirst)
	if result, err := firstSubmission.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeDeferred {
		t.Fatalf("old owner task was not canceled: result=%+v err=%v", result, err)
	}
	if submission := first.Submit(probeTestTask(2, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })); submission.Status != ProbeRejected || !errors.Is(submission.Err, ErrProbeSchedulerOwner) {
		t.Fatalf("old owner still accepted work: %+v", submission)
	}
	if result, err := secondSubmission.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("new owner task failed: result=%+v err=%v", result, err)
	}
	coordinator.Release(1, firstToken.Generation)
	if submission := second.Submit(probeTestTask(4, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })); submission.Status == ProbeRejected {
		t.Fatal("old runtime release revoked new owner")
	}
	if maximum.Load() > 1 {
		t.Fatalf("epoch handoff overlapped probes: max=%d", maximum.Load())
	}
	_ = first.Close()
	_ = second.Close()
	coordinator.Release(2, secondToken.Generation)
}

func TestRuntimePublishCommitHandsProbeOwnershipToNewEpoch(t *testing.T) {
	manager := NewRuntimeManager()
	var active atomic.Int32
	var maximum atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	first := preparedLifecyclePool(t, manager, "runtime-handoff")
	first.postStarted = true
	first.probeCoverage = time.Hour
	first.probeTimeout = time.Second
	first.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		current := active.Add(1)
		maximum.Store(max(maximum.Load(), current))
		close(firstStarted)
		<-releaseFirst
		active.Add(-1)
		return 1, nil
	}
	if err := first.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	first.OnRuntimeEpochPublishCommit()
	<-firstStarted

	secondRuns := make(chan struct{}, 2)
	second := preparedLifecyclePool(t, manager, "runtime-handoff")
	second.postStarted = true
	second.probeCoverage = time.Hour
	second.probeTimeout = time.Second
	second.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		current := active.Add(1)
		maximum.Store(max(maximum.Load(), current))
		active.Add(-1)
		secondRuns <- struct{}{}
		return 1, nil
	}
	if err := second.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	second.OnRuntimeEpochPublishCommit()
	select {
	case <-secondRuns:
		t.Fatal("new runtime probed before old worker drained")
	default:
	}
	close(releaseFirst)
	select {
	case <-secondRuns:
	case <-time.After(time.Second):
		t.Fatal("new epoch scheduler did not take ownership")
	}
	secondSnapshot := second.catalog.load()
	deadline := time.Now().Add(time.Second)
	var status HealthStatus
	for {
		status = second.health.EndpointHandle(secondSnapshot.Candidates[0].Handle)
		// Scheduler completion is published before Observe runs. Wait for the
		// health reducer's settled evidence instead of racing that handoff.
		if status.NonBreakerSuccesses > 0 || status.NonBreakerFailures > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new epoch probe did not publish evidence: %+v", status)
		}
		time.Sleep(time.Millisecond)
	}
	if status.NonBreakerSuccesses != 1 || status.NonBreakerFailures != 0 {
		t.Fatalf("revoked old epoch wrote probe evidence: %+v", status)
	}
	// Capture scheduler stats before retire/trigger so coalesce does not flake the
	// "did it still accept work" check (submit may merge with an in-flight key).
	if second.scheduler == nil || !second.scheduler.ActiveOwner() {
		t.Fatal("new epoch lost scheduler ownership before old retire")
	}
	_, _, completedBefore := second.scheduler.Stats()
	acceptedBefore, _, _, _ := second.scheduler.SubmissionStats()
	first.OnRuntimeEpochRetire()
	if second.scheduler == nil || !second.scheduler.ActiveOwner() {
		t.Fatal("old runtime retire revoked new scheduler ownership")
	}
	if err := second.TriggerAdaptiveProbe(context.Background()); err != nil {
		t.Fatalf("old runtime retire revoked new scheduler: %v", err)
	}
	// Prefer stats over channel: coalesced submits may not re-enter probeRunner.
	deadline = time.Now().Add(2 * time.Second)
	for {
		acceptedAfter, _, _, _ := second.scheduler.SubmissionStats()
		_, _, completedAfter := second.scheduler.Stats()
		if acceptedAfter > acceptedBefore || completedAfter > completedBefore {
			break
		}
		select {
		case <-secondRuns:
			// runner fired — also success
			goto handoffOK
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("new scheduler stopped accepting work after old runtime retire")
		}
		time.Sleep(time.Millisecond)
	}
handoffOK:
	if maximum.Load() > 1 {
		t.Fatalf("runtime publish overlapped epoch probes: max=%d", maximum.Load())
	}
	second.OnRuntimeEpochRetire()
}

func TestSchedulerCoordinatorRapidHandoffPreservesOldestDrainBarrier(t *testing.T) {
	coordinator := new(SchedulerCoordinator)
	firstToken, _ := coordinator.Claim(11)
	first := newOwnedProbeScheduler(context.Background(), coordinator, firstToken, 1, 4)
	started := make(chan struct{})
	release := make(chan struct{})
	_ = first.Submit(probeTestTask(5, ProbePriorityCoverage, func(context.Context) ProbeResult {
		close(started)
		<-release
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	<-started
	secondToken, _ := coordinator.Claim(12)
	second := newOwnedProbeScheduler(context.Background(), coordinator, secondToken, 1, 4)
	coordinator.Release(12, secondToken.Generation)
	thirdToken, _ := coordinator.Claim(13)
	third := newOwnedProbeScheduler(context.Background(), coordinator, thirdToken, 1, 4)
	thirdRan := make(chan struct{})
	thirdSubmission := third.Submit(probeTestTask(6, ProbePriorityCoverage, func(context.Context) ProbeResult {
		close(thirdRan)
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	select {
	case <-thirdRan:
		t.Fatal("rapid handoff bypassed oldest running owner")
	default:
	}
	close(release)
	if result, err := thirdSubmission.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("third owner did not start after drain chain: result=%+v err=%v", result, err)
	}
	_ = first.Close()
	_ = second.Close()
	_ = third.Close()
	coordinator.Release(13, thirdToken.Generation)
}

func TestProbeSchedulerQueueCapReturnsSynchronousDeferred(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 1)
	defer scheduler.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	first := scheduler.Submit(probeTestTask(10, ProbePriorityCoverage, func(context.Context) ProbeResult {
		close(started)
		<-release
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	<-started
	second := scheduler.Submit(probeTestTask(11, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} }))
	third := scheduler.Submit(probeTestTask(12, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} }))
	if first.Status != ProbeAccepted || second.Status != ProbeAccepted || third.Status != ProbeDeferred || !errors.Is(third.Err, ErrProbeQueueFull) {
		t.Fatalf("queue cap acknowledgement mismatch: first=%+v second=%+v third=%+v", first, second, third)
	}
	if result, err := third.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeDeferred {
		t.Fatalf("deferred future mismatch: result=%+v err=%v", result, err)
	}
	close(release)
	_, _ = first.Future.Await(context.Background())
	_, _ = second.Future.Await(context.Background())
}

func TestProbeSchedulerCoalescedFuturesBroadcastAndSingleCancelDoesNotCancelShared(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 8)
	defer scheduler.Close()
	var runs atomic.Int32
	task := probeTestTask(20, ProbePriorityCoverage, func(context.Context) ProbeResult {
		runs.Add(1)
		return ProbeResult{Outcome: OutcomeSuccess}
	})
	task.DueAt = time.Now().Add(20 * time.Millisecond)
	first := scheduler.Submit(task)
	second := scheduler.Submit(task)
	third := scheduler.Submit(task)
	if first.Status != ProbeAccepted || second.Status != ProbeCoalesced || third.Status != ProbeCoalesced {
		t.Fatalf("coalesce status mismatch: %s %s %s", first.Status, second.Status, third.Status)
	}
	second.Future.Cancel()
	if result, err := second.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeDeferred {
		t.Fatalf("canceled waiter mismatch: result=%+v err=%v", result, err)
	}
	for _, future := range []*ProbeFuture{first.Future, third.Future} {
		if result, err := future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
			t.Fatalf("shared future lost result: result=%+v err=%v", result, err)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("coalesced task ran %d times", runs.Load())
	}
}

func TestProbeSchedulerActiveFuturesAttachWithoutImplicitRerun(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 8)
	defer scheduler.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32
	task := probeTestTask(21, ProbePriorityCoverage, func(context.Context) ProbeResult {
		runs.Add(1)
		close(started)
		<-release
		return ProbeResult{Outcome: OutcomeSuccess}
	})
	first := scheduler.Submit(task)
	<-started
	second := scheduler.Submit(task)
	third := scheduler.Submit(task)
	second.Future.Cancel()
	close(release)
	for _, future := range []*ProbeFuture{first.Future, third.Future} {
		if result, err := future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
			t.Fatalf("active coalesced future lost result: result=%+v err=%v", result, err)
		}
	}
	if runs.Load() != 1 || second.Status != ProbeCoalesced || third.Status != ProbeCoalesced {
		t.Fatalf("active coalesce created rerun: runs=%d second=%s third=%s", runs.Load(), second.Status, third.Status)
	}
}

func TestProbeSchedulerPriorityIncludesCoverageQuota(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 64)
	defer scheduler.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	blocker := scheduler.Submit(probeTestTask(30, ProbePriorityRecovery, func(context.Context) ProbeResult {
		close(started)
		<-release
		return ProbeResult{Outcome: OutcomeSuccess}
	}))
	<-started
	order := make(chan string, 32)
	coverage := probeTestTask(31, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })
	coverage.Observe = func(ProbeTask, ProbeResult) { order <- "coverage" }
	_ = scheduler.Submit(coverage)
	service := probeTestTask(32, ProbePriorityService, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })
	service.Observe = func(ProbeTask, ProbeResult) { order <- "service" }
	_ = scheduler.Submit(service)
	for index := 0; index < 16; index++ {
		task := probeTestTask(byte(40+index), ProbePriorityRecovery, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })
		task.Observe = func(ProbeTask, ProbeResult) { order <- "recovery" }
		_ = scheduler.Submit(task)
	}
	close(release)
	_, _ = blocker.Future.Await(context.Background())
	coverageIndex, serviceIndex := -1, -1
	for index := 0; index < 18; index++ {
		select {
		case kind := <-order:
			if kind == "coverage" {
				coverageIndex = index
			} else if kind == "service" {
				serviceIndex = index
			}
		case <-time.After(time.Second):
			t.Fatal("priority queue did not drain")
		}
	}
	if coverageIndex < 0 || coverageIndex > maxHighPriorityBurst {
		t.Fatalf("coverage starved behind high priority work: index=%d", coverageIndex)
	}
	if serviceIndex < 0 || serviceIndex > 2*maxHighPriorityBurst+1 {
		t.Fatalf("service starved behind high priority work: index=%d", serviceIndex)
	}
}

func TestProbeSchedulerContainsRunAndObservePanics(t *testing.T) {
	scheduler := NewProbeScheduler(context.Background(), 1, 8)
	defer scheduler.Close()
	runPanic := scheduler.Submit(probeTestTask(60, ProbePriorityCoverage, func(context.Context) ProbeResult {
		panic("runner panic")
	}))
	result, err := runPanic.Future.Await(context.Background())
	if err != nil || result.Outcome != OutcomeDeferred || result.Reason != "probe runner panic" {
		t.Fatalf("run panic escaped scheduler: result=%+v err=%v", result, err)
	}
	observePanicTask := probeTestTask(61, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} })
	observePanicTask.Observe = func(ProbeTask, ProbeResult) { panic("observe panic") }
	observePanic := scheduler.Submit(observePanicTask)
	if result, err = observePanic.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("observe panic lost future: result=%+v err=%v", result, err)
	}
	next := scheduler.Submit(probeTestTask(62, ProbePriorityCoverage, func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} }))
	if result, err = next.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeSuccess {
		t.Fatalf("scheduler stopped after panic: result=%+v err=%v", result, err)
	}
	_, _, _, rejected := scheduler.SubmissionStats()
	if rejected < 2 {
		t.Fatalf("scheduler panics were not counted: rejected=%d", rejected)
	}
}

func TestURLTestTriggerAndPeriodicShareOneScheduler(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, candidate := newProbeTestPool(t, context.Background(), health)
	pool.probeURL = "test://single"
	pool.probeConcurrency = 1
	pool.probeQueueSize = 16
	pool.scheduler = NewProbeScheduler(context.Background(), 1, 16)
	defer pool.scheduler.Close()
	runs := make(chan struct{}, 4)
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		runs <- struct{}{}
		return 3, nil
	}
	result, err := pool.URLTest(context.Background())
	if err != nil || result[candidate.PrimaryTag] != 3 {
		t.Fatalf("URLTest did not use scheduler result: result=%v err=%v", result, err)
	}
	if err = pool.TriggerAdaptiveProbe(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runs:
	case <-time.After(time.Second):
		t.Fatal("trigger task did not run")
	}
	snapshot := pool.catalog.load()
	periodic := pool.scheduler.Submit(pool.probeTask(snapshot, candidate, time.Now(), time.Hour))
	if _, err = periodic.Future.Await(context.Background()); err != nil {
		t.Fatal(err)
	}
	accepted, coalesced, _, rejected := pool.scheduler.SubmissionStats()
	// URLTest + trigger(HTTP+DNS/v4) + periodic >= 4 (DNS/v6 no longer auto-fired).
	if accepted+coalesced < 4 {
		t.Fatalf("probe entrances did not share scheduler stats: accepted=%d coalesced=%d rejected=%d", accepted, coalesced, rejected)
	}
}

func TestRealFailureProbeUsesExistingScheduler(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, candidate := newProbeTestPool(t, context.Background(), health)
	pool.probeURL = "test://failure-feedback"
	pool.scheduler = NewProbeScheduler(context.Background(), 1, 16)
	defer pool.scheduler.Close()
	runs := make(chan struct{}, 1)
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) {
		runs <- struct{}{}
		return 4, nil
	}
	pool.scheduleFailureProbe(candidate.Handle)
	select {
	case <-runs:
	case <-time.After(time.Second):
		t.Fatal("real failure did not submit an immediate probe")
	}
	accepted, _, _, rejected := pool.scheduler.SubmissionStats()
	if accepted != 1 || rejected != 0 {
		t.Fatalf("failure feedback bypassed scheduler accounting: accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestProviderRevisionReplacesPendingProbeWithCurrentExecutionView(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, oldSnapshot := newWiredObservationPool(t, health, wired(NodeID{63}, "old", newTestOutbound("old")))
	pool.scheduler = NewProbeScheduler(context.Background(), 1, 16)
	defer pool.scheduler.Close()
	oldCandidate := oldSnapshot.Candidates[0]
	oldTask := pool.probeTask(oldSnapshot, oldCandidate, time.Now().Add(time.Hour), time.Hour)
	oldSubmission := pool.scheduler.Submit(oldTask)
	newOutbound := newTestOutbound("new")
	source := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 2, Nodes: []CanonicalNode{{NodeID: oldCandidate.ID, SourceKey: "new", Aliases: []string{"new"}, Transport: []string{N.NetworkTCP}, IdentityStable: true}}}, Bindings: map[NodeID]ExecutionPort{oldCandidate.ID: newOutbound}}
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		t.Fatal(err)
	}
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
	run := make(chan struct{}, 1)
	pool.probeRunner = func(_ context.Context, _ string, dialer N.Dialer) (uint16, error) {
		if dialer != newOutbound {
			t.Error("revision task executed stale outbound")
		}
		run <- struct{}{}
		return 2, nil
	}
	pool.reconcileScheduler(oldSnapshot, current)
	if result, err := oldSubmission.Future.Await(context.Background()); err != nil || result.Outcome != OutcomeDeferred {
		t.Fatalf("old revision future was not retired: result=%+v err=%v", result, err)
	}
	select {
	case <-run:
	case <-time.After(time.Second):
		t.Fatal("current revision probe did not run")
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, _, completed := pool.scheduler.Stats()
		if completed > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("current revision probe did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	status := health.EndpointHandle(current.Candidates[0].Handle)
	if status.NonBreakerSuccesses != 1 || status.Failures != 0 {
		t.Fatalf("current revision evidence missing or polluted: %+v", status)
	}
}

func TestURLTestContextCancelDoesNotWriteProbeHealth(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, candidate := newProbeTestPool(t, context.Background(), health)
	pool.scheduler = NewProbeScheduler(context.Background(), 1, 8)
	defer pool.scheduler.Close()
	started := make(chan struct{})
	var once sync.Once
	pool.probeRunner = func(ctx context.Context, _ string, _ N.Dialer) (uint16, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return 0, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := pool.URLTest(ctx); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("URLTest cancellation mismatch: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, _, completed := pool.scheduler.Stats()
		if completed > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled task did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	status := health.EndpointHandle(candidate.Handle)
	if status.Successes != 0 || status.Failures != 0 || status.NonBreakerSuccesses != 0 || status.NonBreakerFailures != 0 {
		t.Fatalf("canceled URLTest polluted health: %+v", status)
	}
}
