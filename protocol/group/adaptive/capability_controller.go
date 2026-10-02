package adaptive

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrCapabilityCycleBusy = errors.New("adaptive capability cycle is already running")
	ErrCapabilityView      = errors.New("adaptive capability execution view is unavailable")
	capabilityRunSequence  atomic.Uint64
)

const capabilityStartupRetry = 250 * time.Millisecond

type RefreshableProbeTargetProvider interface {
	ProbeTargetProvider
	Refresh(context.Context) error
}

type CapabilitySuiteRunner interface {
	Run(context.Context, CapabilitySuiteRequest) (ProbeRunResult, error)
}

type CapabilityExecutionView func() *ExecutionSnapshot

type CapabilityControllerStatus struct {
	Running          bool
	CyclesStarted    uint64
	CyclesCompleted  uint64
	RefreshFailures  uint64
	ViewFailures     uint64
	SuiteFailures    uint64
	LastFailureStage string
	LastStartedAt    time.Time
	LastCompletedAt  time.Time
}

// CapabilityProbeController is epoch-local orchestration only. It never runs
// node probes itself; the injected suite submits every node x target task to
// the epoch's single ProbeScheduler.
type CapabilityProbeController struct {
	clock         Clock
	provider      RefreshableProbeTargetProvider
	suite         CapabilitySuiteRunner
	view          CapabilityExecutionView
	bridge        ExecutionBridge
	epochID       RuntimeEpochID
	serviceID     string
	interval      time.Duration
	timeout       time.Duration
	quorum        int
	commonModeMin int
	onComplete    func()

	running atomic.Bool
	status  sync.Mutex
	state   CapabilityControllerStatus

	lifecycle        sync.Mutex
	closed           bool
	controllerCtx    context.Context
	controllerCancel context.CancelFunc
	loopCancel       context.CancelFunc
	loopDone         chan struct{}
	cycles           sync.WaitGroup
}

func NewCapabilityProbeController(clock Clock, provider RefreshableProbeTargetProvider, suite CapabilitySuiteRunner, view CapabilityExecutionView, epochID RuntimeEpochID, interval, timeout time.Duration, quorum, commonModeMin int, bridges ...ExecutionBridge) (*CapabilityProbeController, error) {
	if clock == nil {
		clock = realClock{}
	}
	var bridge ExecutionBridge
	if len(bridges) > 0 {
		bridge = bridges[0]
	}
	if provider == nil || suite == nil || view == nil || bridge == nil || epochID == 0 {
		return nil, errors.New("adaptive capability controller dependency is nil")
	}
	if interval <= 0 || timeout <= 0 || quorum <= 0 || commonModeMin <= 0 {
		return nil, errors.New("adaptive capability controller policy is invalid")
	}
	controllerContext, controllerCancel := context.WithCancel(context.Background())
	return &CapabilityProbeController{
		clock: clock, provider: provider, suite: suite, view: view, bridge: bridge, epochID: epochID, serviceID: youtubeProbeServiceID,
		interval: interval, timeout: timeout, quorum: quorum, commonModeMin: commonModeMin,
		controllerCtx: controllerContext, controllerCancel: controllerCancel,
	}, nil
}

func (c *CapabilityProbeController) WithServiceID(serviceID string) *CapabilityProbeController {
	if c != nil && serviceID != "" {
		c.serviceID = serviceID
	}
	return c
}

func (c *CapabilityProbeController) RunOnce(ctx context.Context) (ProbeRunResult, error) {
	c.lifecycle.Lock()
	if c.closed {
		c.lifecycle.Unlock()
		return ProbeRunResult{}, context.Canceled
	}
	if !c.running.CompareAndSwap(false, true) {
		c.lifecycle.Unlock()
		return ProbeRunResult{}, ErrCapabilityCycleBusy
	}
	c.cycles.Add(1)
	controllerContext := c.controllerCtx
	c.lifecycle.Unlock()
	startedAt := c.clock.Now()
	c.status.Lock()
	c.state.Running = true
	c.state.CyclesStarted++
	c.state.LastStartedAt = startedAt
	c.status.Unlock()
	defer func() {
		c.status.Lock()
		c.state.Running = false
		c.status.Unlock()
		c.running.Store(false)
		c.cycles.Done()
	}()

	cycleContext, cancel := context.WithTimeout(ctx, c.timeout)
	stopControllerCancel := context.AfterFunc(controllerContext, cancel)
	defer func() {
		stopControllerCancel()
		cancel()
	}()

	if err := c.provider.Refresh(cycleContext); err != nil {
		c.recordFailure("refresh")
		return ProbeRunResult{}, err
	}
	view := c.view()
	if !validCapabilityExecutionView(view, c.epochID) {
		c.recordFailure("view")
		return ProbeRunResult{}, ErrCapabilityView
	}
	nodes := make([]CapabilitySuiteNode, len(view.Candidates))
	bindings := make([]*ExecutionLease, 0, len(view.Candidates))
	defer func() {
		for _, binding := range bindings {
			binding.Release()
		}
	}()
	for index, candidate := range view.Candidates {
		binding, loaded := c.bridge.AcquireExecution(ExecutionToken{RuntimeEpochID: view.RuntimeEpochID, CatalogRevision: view.CatalogRevision, Handle: candidate.Handle})
		if !loaded {
			c.recordFailure("view")
			return ProbeRunResult{}, ErrCapabilityView
		}
		bindings = append(bindings, binding)
		nodes[index] = CapabilitySuiteNode{Handle: candidate.Handle, Dialer: binding.Port}
	}
	runID := ProbeSuiteRunID(capabilityRunSequence.Add(1))
	result, err := c.suite.Run(cycleContext, CapabilitySuiteRequest{
		RunID: runID, RuntimeEpochID: view.RuntimeEpochID, CatalogRevision: view.CatalogRevision, SourceGeneration: view.Generation,
		ServiceID: c.serviceID, Nodes: nodes, Quorum: c.quorum, CommonModeMinNodes: c.commonModeMin,
		Deadline: c.clock.Now().Add(c.timeout), Priority: ProbePriorityService,
	})
	if err != nil {
		c.recordFailure("suite")
		return ProbeRunResult{}, err
	}
	c.status.Lock()
	c.state.CyclesCompleted++
	c.state.LastFailureStage = ""
	c.state.LastCompletedAt = c.clock.Now()
	c.status.Unlock()
	if c.onComplete != nil {
		c.onComplete()
	}
	return result, nil
}

func (c *CapabilityProbeController) Start(parent context.Context) error {
	c.lifecycle.Lock()
	defer c.lifecycle.Unlock()
	if c.closed {
		return context.Canceled
	}
	if c.loopDone != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	stopControllerCancel := context.AfterFunc(c.controllerCtx, cancel)
	c.loopCancel = cancel
	c.loopDone = make(chan struct{})
	done := c.loopDone
	go func() {
		defer func() {
			stopControllerCancel()
			close(done)
		}()
		retryDelay := min(c.interval, capabilityStartupRetry)
		for {
			if _, runErr := c.RunOnce(ctx); runErr == nil || !errors.Is(runErr, ErrCapabilityView) {
				break
			}
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			retryDelay = min(c.interval, retryDelay*2)
		}
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = c.RunOnce(ctx)
			}
		}
	}()
	return nil
}

func (c *CapabilityProbeController) Close() {
	c.lifecycle.Lock()
	if c.closed {
		c.lifecycle.Unlock()
		return
	}
	c.closed = true
	c.controllerCancel()
	cancel, done := c.loopCancel, c.loopDone
	c.lifecycle.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	c.cycles.Wait()
}

func (c *CapabilityProbeController) Status() CapabilityControllerStatus {
	c.status.Lock()
	status := c.state
	c.status.Unlock()
	return status
}

func (c *CapabilityProbeController) recordFailure(stage string) {
	c.status.Lock()
	switch stage {
	case "refresh":
		c.state.RefreshFailures++
	case "view":
		c.state.ViewFailures++
	case "suite":
		c.state.SuiteFailures++
	}
	c.state.LastFailureStage = stage
	c.state.LastCompletedAt = c.clock.Now()
	c.status.Unlock()
}

func validCapabilityExecutionView(view *ExecutionSnapshot, epochID RuntimeEpochID) bool {
	if view == nil || view.RuntimeEpochID != epochID || view.CatalogRevision == 0 || view.Generation == 0 || len(view.Candidates) == 0 {
		return false
	}
	seen := make(map[NodeHandle]struct{}, len(view.Candidates))
	for _, candidate := range view.Candidates {
		if candidate.ID == (NodeID{}) || candidate.Handle.NodeID != candidate.ID || candidate.Handle.Slot == 0 || candidate.Handle.Version == 0 {
			return false
		}
		if _, loaded := seen[candidate.Handle]; loaded {
			return false
		}
		seen[candidate.Handle] = struct{}{}
	}
	return true
}
