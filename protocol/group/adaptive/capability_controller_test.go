package adaptive

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type controllerTargetProvider struct {
	access  sync.Mutex
	err     error
	calls   int
	started chan struct{}
	release chan struct{}
}

func (p *controllerTargetProvider) Refresh(ctx context.Context) error {
	p.access.Lock()
	p.calls++
	started, release, refreshErr := p.started, p.release, p.err
	p.access.Unlock()
	if started != nil {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return refreshErr
}

func (*controllerTargetProvider) Snapshot(context.Context, string) (*ProbeTargetSnapshot, error) {
	return nil, ErrProbeRunUnknown
}

type controllerSuiteRunner struct {
	access  sync.Mutex
	calls   int
	request CapabilitySuiteRequest
	started chan struct{}
	block   bool
	err     error
}

func (s *controllerSuiteRunner) Run(ctx context.Context, request CapabilitySuiteRequest) (ProbeRunResult, error) {
	s.access.Lock()
	s.calls++
	s.request = request
	started, block, runErr := s.started, s.block, s.err
	s.access.Unlock()
	if started != nil {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	if block {
		<-ctx.Done()
		return ProbeRunResult{}, ctx.Err()
	}
	return ProbeRunResult{RunID: request.RunID}, runErr
}

func controllerExecutionSnapshot() *ExecutionSnapshot {
	handle := NodeHandle{NodeID: NodeID{81}, Slot: 2, Version: 3, BornRevision: 1}
	return &ExecutionSnapshot{
		RuntimeEpochID: 11, CatalogRevision: 12, Generation: 13,
		Candidates: []Candidate{{ID: handle.NodeID, Handle: handle, PrimaryTag: "node"}},
		ByID:       map[NodeID]int{handle.NodeID: 0}, AliasToID: map[string]NodeID{"node": handle.NodeID},
	}
}

func controllerBridge() ExecutionBridge {
	return retryBindingBridge{ports: map[NodeHandle]ExecutionPort{controllerExecutionSnapshot().Candidates[0].Handle: newTestOutbound("controller")}}
}

func TestCapabilityProbeControllerRefreshesThenRunsEpochLocalSuite(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	provider := new(controllerTargetProvider)
	suite := new(controllerSuiteRunner)
	view := controllerExecutionSnapshot()
	controller, err := NewCapabilityProbeController(&fakeClock{now: now}, provider, suite, func() *ExecutionSnapshot {
		return cloneExecutionSnapshot(view)
	}, 11, time.Minute, 10*time.Second, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	result, err := controller.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	suite.access.Lock()
	request, calls := suite.request, suite.calls
	suite.access.Unlock()
	if calls != 1 || result.RunID == 0 || request.RunID != result.RunID {
		t.Fatalf("controller did not submit one unique suite run: calls=%d request=%+v result=%+v", calls, request, result)
	}
	if request.RuntimeEpochID != view.RuntimeEpochID || request.CatalogRevision != view.CatalogRevision || request.SourceGeneration != view.Generation || len(request.Nodes) != 1 || request.Nodes[0].Handle != view.Candidates[0].Handle || request.Nodes[0].Dialer == nil {
		t.Fatalf("controller mixed execution identities: %+v", request)
	}
	status := controller.Status()
	if status.Running || status.CyclesStarted != 1 || status.CyclesCompleted != 1 || status.LastFailureStage != "" {
		t.Fatalf("unexpected successful controller status: %+v", status)
	}
}

func TestCapabilityProbeControllerRefreshFailureDoesNotReadViewOrRunSuite(t *testing.T) {
	provider := &controllerTargetProvider{err: ErrProbeTargetFetch}
	suite := new(controllerSuiteRunner)
	viewCalls := 0
	controller, err := NewCapabilityProbeController(nil, provider, suite, func() *ExecutionSnapshot {
		viewCalls++
		return controllerExecutionSnapshot()
	}, 11, time.Minute, time.Second, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if _, err = controller.RunOnce(context.Background()); !errors.Is(err, ErrProbeTargetFetch) {
		t.Fatalf("refresh failure was hidden: %v", err)
	}
	if viewCalls != 0 || suite.calls != 0 {
		t.Fatalf("refresh failure reached execution view or suite: view=%d suite=%d", viewCalls, suite.calls)
	}
	status := controller.Status()
	if status.RefreshFailures != 1 || status.ViewFailures != 0 || status.SuiteFailures != 0 || status.LastFailureStage != "refresh" {
		t.Fatalf("refresh failure status was not structured: %+v", status)
	}
}

func TestCapabilityProbeControllerRejectsViewFromSuccessorEpoch(t *testing.T) {
	provider := new(controllerTargetProvider)
	suite := new(controllerSuiteRunner)
	view := controllerExecutionSnapshot()
	view.RuntimeEpochID++
	controller, err := NewCapabilityProbeController(nil, provider, suite, func() *ExecutionSnapshot { return view }, 11, time.Minute, time.Second, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if _, err = controller.RunOnce(context.Background()); !errors.Is(err, ErrCapabilityView) {
		t.Fatalf("successor epoch view crossed controller boundary: %v", err)
	}
	if suite.calls != 0 {
		t.Fatalf("stale controller invoked suite with successor view: %d", suite.calls)
	}
	status := controller.Status()
	if status.ViewFailures != 1 || status.LastFailureStage != "view" {
		t.Fatalf("successor view failure was not structured: %+v", status)
	}
}

func TestCapabilityProbeControllerRejectsConcurrentCycle(t *testing.T) {
	provider := &controllerTargetProvider{started: make(chan struct{}), release: make(chan struct{})}
	controller, err := NewCapabilityProbeController(nil, provider, new(controllerSuiteRunner), controllerExecutionSnapshot, 11, time.Minute, time.Second, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	firstDone := make(chan error, 1)
	go func() {
		_, runErr := controller.RunOnce(context.Background())
		firstDone <- runErr
	}()
	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("first controller cycle did not enter refresh")
	}
	if _, err = controller.RunOnce(context.Background()); !errors.Is(err, ErrCapabilityCycleBusy) {
		t.Fatalf("concurrent cycle was not rejected: %v", err)
	}
	close(provider.release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityProbeControllerCloseCancelsBlockingSuite(t *testing.T) {
	started := make(chan struct{})
	suite := &controllerSuiteRunner{started: started, block: true}
	controller, err := NewCapabilityProbeController(nil, new(controllerTargetProvider), suite, controllerExecutionSnapshot, 11, time.Hour, time.Minute, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("periodic controller did not start suite")
	}
	closed := make(chan struct{})
	go func() {
		controller.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("controller close did not cancel and join suite")
	}
	status := controller.Status()
	if status.Running || status.SuiteFailures != 1 || status.LastFailureStage != "suite" {
		t.Fatalf("canceled controller status was not settled: %+v", status)
	}
}

func TestCapabilityProbeControllerRetriesInitialViewFailureBeforeInterval(t *testing.T) {
	provider := new(controllerTargetProvider)
	suite := new(controllerSuiteRunner)
	var viewCalls int
	controller, err := NewCapabilityProbeController(nil, provider, suite, func() *ExecutionSnapshot {
		viewCalls++
		if viewCalls == 1 {
			return nil
		}
		return controllerExecutionSnapshot()
	}, 11, time.Hour, time.Second, 2, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := controller.Status()
		if status.CyclesCompleted == 1 {
			if status.CyclesStarted != 2 || status.ViewFailures != 1 || suite.calls != 1 {
				t.Fatalf("unexpected startup retry status: status=%+v suite_calls=%d", status, suite.calls)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("controller waited for full interval after startup view failure: %+v", controller.Status())
}

func TestCapabilityProbeControllerDoesNotTightRetrySuiteFailure(t *testing.T) {
	provider := new(controllerTargetProvider)
	suite := &controllerSuiteRunner{err: errors.New("deterministic probe failure")}
	controller, err := NewCapabilityProbeController(nil, provider, suite, controllerExecutionSnapshot, 11, time.Hour, time.Second, 1, 2, controllerBridge())
	if err != nil {
		t.Fatal(err)
	}
	if err = controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	time.Sleep(600 * time.Millisecond)
	status := controller.Status()
	if status.CyclesStarted != 1 || status.SuiteFailures != 1 || suite.calls != 1 {
		t.Fatalf("suite failure entered startup retry loop: status=%+v suite_calls=%d", status, suite.calls)
	}
}
