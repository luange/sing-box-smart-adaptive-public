package adaptive

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrProbeQueueFull      = errors.New("adaptive probe queue is full")
	ErrProbeSchedulerOwner = errors.New("adaptive probe scheduler is not active owner")
)

type ProbePriority uint8

const (
	ProbePriorityCoverage ProbePriority = iota + 1
	ProbePriorityService
	ProbePriorityOnDemand
	ProbePriorityRecovery
)

const maxHighPriorityBurst = 8
const schedulerReadyTimeout = 30 * time.Second

type ProbeKey struct {
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
	NodeID           NodeID
	NodeSlot         uint64
	NodeVersion      uint64
	Suite            string
	Target           string
}

type probeRemoval struct {
	epochID     RuntimeEpochID
	revision    CatalogRevision
	nodeID      NodeID
	nodeSlot    uint64
	nodeVersion uint64
}

type ProbeResult struct {
	Outcome ObservationOutcome
	Delay   time.Duration
	Reason  string
	Settled bool
}

type ProbeTask struct {
	Key               ProbeKey
	Source            string
	Priority          ProbePriority
	DueAt             time.Time
	SubmittedAt       time.Time
	Interval          time.Duration
	FailureInterval   time.Duration
	FailureStreak     uint8
	SuccessStreak     uint8
	Timeout           time.Duration
	FreshAfterCurrent bool
	Run               func(context.Context) ProbeResult
	Observe           func(ProbeTask, ProbeResult)
}

type ProbeSubmitStatus string

const (
	ProbeAccepted  ProbeSubmitStatus = "accepted"
	ProbeCoalesced ProbeSubmitStatus = "coalesced"
	ProbeDeferred  ProbeSubmitStatus = "deferred"
	ProbeRejected  ProbeSubmitStatus = "rejected"
)

type ProbeSubmission struct {
	Status ProbeSubmitStatus
	Future *ProbeFuture
	Err    error
}

type ProbeFuture struct {
	result <-chan ProbeResult
	cancel func()
	once   sync.Once
}

func (f *ProbeFuture) Await(ctx context.Context) (ProbeResult, error) {
	if f == nil {
		return ProbeResult{}, errors.New("adaptive probe has no future")
	}
	select {
	case result, loaded := <-f.result:
		if !loaded {
			return ProbeResult{Outcome: OutcomeDeferred, Reason: "probe future closed"}, nil
		}
		return result, nil
	case <-ctx.Done():
		f.Cancel()
		return ProbeResult{Outcome: OutcomeDeferred, Reason: ctx.Err().Error()}, ctx.Err()
	}
}

func (f *ProbeFuture) Cancel() {
	if f != nil && f.cancel != nil {
		f.once.Do(f.cancel)
	}
}

type probeWaiter struct {
	id     uint64
	result chan ProbeResult
}

type scheduledProbe struct {
	task    ProbeTask
	waiters map[uint64]probeWaiter
}

type activeProbe struct {
	entry  *scheduledProbe
	cancel context.CancelFunc
}

type probeSubmitRequest struct {
	task   ProbeTask
	waiter probeWaiter
	reply  chan ProbeSubmission
}

type probeCancelRequest struct {
	key      ProbeKey
	waiterID uint64
}

type probeCompletion struct {
	key    ProbeKey
	task   ProbeTask
	result ProbeResult
}

type probeJob struct {
	task ProbeTask
	ctx  context.Context
}

type schedulerStats struct {
	accepted  atomic.Uint64
	coalesced atomic.Uint64
	deferred  atomic.Uint64
	rejected  atomic.Uint64
	completed atomic.Uint64
	stalled   atomic.Uint64
}

type SchedulerCoordinator struct {
	access     sync.Mutex
	owner      RuntimeEpochID
	generation uint64
	token      *SchedulerOwnershipToken
	drain      <-chan struct{}
	stats      schedulerStats
}

func (c *SchedulerCoordinator) cleanupState() (<-chan struct{}, bool) {
	if c == nil {
		return nil, true
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.owner != 0 || c.token != nil {
		return c.drain, false
	}
	if c.drain == nil {
		return nil, true
	}
	select {
	case <-c.drain:
		return c.drain, true
	default:
		return c.drain, false
	}
}

type SchedulerOwnershipToken struct {
	EpochID    RuntimeEpochID
	Generation uint64
	revoke     chan struct{}
	done       chan struct{}
	ready      chan struct{}
	drained    chan struct{}
	revokeOnce sync.Once
	doneOnce   sync.Once
}

func (t *SchedulerOwnershipToken) markDone() {
	if t != nil {
		t.doneOnce.Do(func() { close(t.done) })
	}
}

func (t *SchedulerOwnershipToken) revokeOwner() {
	if t != nil {
		t.revokeOnce.Do(func() { close(t.revoke) })
	}
}

func (c *SchedulerCoordinator) Claim(epochID RuntimeEpochID) (*SchedulerOwnershipToken, error) {
	if epochID == 0 {
		return nil, errors.New("adaptive scheduler owner epoch is required")
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.owner == epochID && c.token != nil {
		return c.token, nil
	}
	previousDrain := c.drain
	if c.token != nil {
		c.token.revokeOwner()
	}
	c.generation++
	c.owner = epochID
	c.token = &SchedulerOwnershipToken{EpochID: epochID, Generation: c.generation, revoke: make(chan struct{}), done: make(chan struct{}), ready: make(chan struct{}), drained: make(chan struct{})}
	if previousDrain == nil {
		close(c.token.ready)
	} else {
		next := c.token
		go func() {
			<-previousDrain
			close(next.ready)
		}()
	}
	next := c.token
	go func() {
		<-next.ready
		<-next.done
		close(next.drained)
	}()
	c.drain = c.token.drained
	return c.token, nil
}

func (c *SchedulerCoordinator) Release(epochID RuntimeEpochID, generation uint64) {
	c.access.Lock()
	if c.owner == epochID && c.generation == generation && c.token != nil {
		token := c.token
		token.revokeOwner()
		c.owner = 0
		c.token = nil
	}
	c.access.Unlock()
}

func (c *SchedulerCoordinator) IsOwner(token *SchedulerOwnershipToken) bool {
	c.access.Lock()
	owned := token != nil && c.token == token && c.owner == token.EpochID && c.generation == token.Generation
	c.access.Unlock()
	return owned
}

func (c *SchedulerCoordinator) Stats() (owner RuntimeEpochID, generation, accepted, coalesced, deferred, rejected, completed, stalled uint64) {
	c.access.Lock()
	owner = c.owner
	generation = c.generation
	c.access.Unlock()
	return owner, generation, c.stats.accepted.Load(), c.stats.coalesced.Load(), c.stats.deferred.Load(), c.stats.rejected.Load(), c.stats.completed.Load(), c.stats.stalled.Load()
}

type ProbeScheduler struct {
	ctx       context.Context
	cancel    context.CancelFunc
	queueSize int
	workers   int
	epochID   RuntimeEpochID
	ownerGen  uint64
	owner     *SchedulerCoordinator
	ownership *SchedulerOwnershipToken

	submit       chan probeSubmitRequest
	cancelWaiter chan probeCancelRequest
	remove       chan probeRemoval
	jobs         chan probeJob
	done         chan probeCompletion
	closed       chan struct{}
	worker       sync.WaitGroup
	close        sync.Once
	stats        schedulerStats
	depth        atomic.Int64
	waiterID     atomic.Uint64
}

func NewProbeScheduler(parent context.Context, workers, queueSize int) *ProbeScheduler {
	return newOwnedProbeScheduler(parent, nil, nil, workers, queueSize)
}

func newOwnedProbeScheduler(parent context.Context, owner *SchedulerCoordinator, ownership *SchedulerOwnershipToken, workers, queueSize int) *ProbeScheduler {
	if workers <= 0 {
		workers = 4
	}
	if queueSize <= 0 {
		queueSize = 4096
	}
	ctx, cancel := context.WithCancel(parent)
	scheduler := &ProbeScheduler{
		ctx: ctx, cancel: cancel, queueSize: queueSize, workers: workers, owner: owner, ownership: ownership,
		submit: make(chan probeSubmitRequest), cancelWaiter: make(chan probeCancelRequest), remove: make(chan probeRemoval),
		jobs: make(chan probeJob), done: make(chan probeCompletion, workers), closed: make(chan struct{}),
	}
	if ownership != nil {
		scheduler.epochID = ownership.EpochID
		scheduler.ownerGen = ownership.Generation
		go func() {
			select {
			case <-ownership.revoke:
				cancel()
			case <-ctx.Done():
			}
		}()
		go func() {
			<-scheduler.closed
			scheduler.worker.Wait()
			ownership.markDone()
		}()
	}
	for range workers {
		scheduler.worker.Add(1)
		go scheduler.runWorker()
	}
	go scheduler.runDispatcher()
	return scheduler
}

func (s *ProbeScheduler) Submit(task ProbeTask) ProbeSubmission {
	if task.Run == nil {
		s.stats.rejected.Add(1)
		return ProbeSubmission{Status: ProbeRejected, Err: errors.New("adaptive probe task has no runner")}
	}
	if s.owner != nil && !s.owner.IsOwner(s.ownership) {
		s.stats.rejected.Add(1)
		return ProbeSubmission{Status: ProbeRejected, Err: ErrProbeSchedulerOwner}
	}
	if task.DueAt.IsZero() {
		task.DueAt = time.Now()
	}
	if task.SubmittedAt.IsZero() {
		task.SubmittedAt = time.Now()
	}
	if task.Timeout <= 0 {
		task.Timeout = 5 * time.Second
	}
	if task.Priority == 0 {
		task.Priority = ProbePriorityCoverage
	}
	waiterID := s.waiterID.Add(1)
	result := make(chan ProbeResult, 1)
	reply := make(chan ProbeSubmission, 1)
	request := probeSubmitRequest{task: task, waiter: probeWaiter{id: waiterID, result: result}, reply: reply}
	select {
	case s.submit <- request:
	case <-s.ctx.Done():
		s.stats.rejected.Add(1)
		return ProbeSubmission{Status: ProbeRejected, Err: s.ctx.Err()}
	}
	select {
	case submission := <-reply:
		submission.Future = &ProbeFuture{result: result, cancel: func() {
			select {
			case s.cancelWaiter <- probeCancelRequest{key: task.Key, waiterID: waiterID}:
			case <-s.ctx.Done():
			}
		}}
		return submission
	case <-s.ctx.Done():
		return ProbeSubmission{Status: ProbeRejected, Err: s.ctx.Err()}
	}
}

func (s *ProbeScheduler) Enqueue(task ProbeTask) error {
	submission := s.Submit(task)
	if submission.Status == ProbeDeferred {
		return ErrProbeQueueFull
	}
	return submission.Err
}

func (s *ProbeScheduler) Remove(nodeID NodeID) {
	s.removeMatching(probeRemoval{nodeID: nodeID})
}

func (s *ProbeScheduler) RemoveVersion(nodeID NodeID, nodeVersion uint64) {
	s.removeMatching(probeRemoval{nodeID: nodeID, nodeVersion: nodeVersion})
}

func (s *ProbeScheduler) RemoveHandle(handle NodeHandle) {
	s.removeMatching(probeRemoval{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version})
}

func (s *ProbeScheduler) RemoveRevision(epochID RuntimeEpochID, revision CatalogRevision) {
	s.removeMatching(probeRemoval{epochID: epochID, revision: revision})
}

func (s *ProbeScheduler) removeMatching(removal probeRemoval) {
	select {
	case s.remove <- removal:
	case <-s.ctx.Done():
	}
}

func (s *ProbeScheduler) Stats() (queueDepth int, deferred, completed uint64) {
	return int(s.depth.Load()), s.stats.deferred.Load(), s.stats.completed.Load()
}

func (s *ProbeScheduler) SubmissionStats() (accepted, coalesced, deferred, rejected uint64) {
	return s.stats.accepted.Load(), s.stats.coalesced.Load(), s.stats.deferred.Load(), s.stats.rejected.Load()
}

func (s *ProbeScheduler) ActiveOwner() bool {
	return s != nil && (s.owner == nil || s.owner.IsOwner(s.ownership))
}

func (s *ProbeScheduler) Close() error {
	s.close.Do(s.cancel)
	<-s.closed
	s.worker.Wait()
	return nil
}

func (s *ProbeScheduler) runWorker() {
	defer s.worker.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobs:
			startedAt := time.Now()
			result, panicked := runProbeTask(job.task, job.ctx)
			if panicked {
				s.stats.rejected.Add(1)
				if s.owner != nil {
					s.owner.stats.rejected.Add(1)
				}
			}
			if result.Delay <= 0 {
				result.Delay = time.Since(startedAt)
			}
			if runErr := job.ctx.Err(); runErr != nil {
				result = ProbeResult{Outcome: OutcomeDeferred, Delay: result.Delay, Reason: runErr.Error()}
			} else if s.owner != nil && !s.owner.IsOwner(s.ownership) {
				result = ProbeResult{Outcome: OutcomeDeferred, Delay: result.Delay, Reason: ErrProbeSchedulerOwner.Error()}
			}
			select {
			case s.done <- probeCompletion{key: job.task.Key, task: job.task, result: result}:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

func runProbeTask(task ProbeTask, ctx context.Context) (result ProbeResult, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = ProbeResult{Outcome: OutcomeDeferred, Reason: "probe runner panic"}
			panicked = true
		}
	}()
	return task.Run(ctx), false
}

func (s *ProbeScheduler) runDispatcher() {
	defer close(s.closed)
	pending := make(map[ProbeKey]*scheduledProbe)
	active := make(map[ProbeKey]*activeProbe)
	rerun := make(map[ProbeKey]*scheduledProbe)
	lastSource := make(map[ProbePriority]string)
	highBurst := 0
	forcedPriority := ProbePriority(0)
	ownerReady := s.ownership == nil
	var ownerReadyChannel <-chan struct{}
	if s.ownership != nil {
		ownerReadyChannel = s.ownership.ready
	}
	var ownerStallTimer *time.Timer
	var ownerStallChannel <-chan time.Time
	if !ownerReady {
		ownerStallTimer = time.NewTimer(schedulerReadyTimeout)
		ownerStallChannel = ownerStallTimer.C
	}
	var dispatch *scheduledProbe
	var dispatchContext context.Context
	var dispatchCancel context.CancelFunc
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	defer func() {
		if ownerStallTimer != nil {
			ownerStallTimer.Stop()
		}
	}()

	finish := func(entry *scheduledProbe, result ProbeResult) {
		for _, waiter := range entry.waiters {
			waiter.result <- result
			close(waiter.result)
		}
		if entry.task.Observe != nil {
			if !observeProbeTask(entry.task, result) {
				s.stats.rejected.Add(1)
				if s.owner != nil {
					s.owner.stats.rejected.Add(1)
				}
			}
		}
	}
	defer func() {
		result := ProbeResult{Outcome: OutcomeDeferred, Reason: "scheduler stopped"}
		if dispatch != nil {
			dispatchCancel()
		}
		for _, entry := range pending {
			finish(entry, result)
		}
		for _, entry := range rerun {
			finish(entry, result)
		}
		for _, running := range active {
			running.cancel()
			finish(running.entry, result)
		}
		s.depth.Store(0)
	}()

	for {
		if dispatch == nil && ownerReady {
			if entry, loaded := nextScheduledProbe(time.Now(), pending, lastSource, &highBurst, &forcedPriority); loaded {
				dispatch = entry
				dispatchContext, dispatchCancel = newProbeDispatchContext(s.ctx, entry.task.Timeout)
			}
		}
		var jobChannel chan probeJob
		var job probeJob
		var timerC <-chan time.Time
		if dispatch != nil {
			jobChannel = s.jobs
			job = probeJob{task: dispatch.task, ctx: dispatchContext}
		} else if dueAt, loaded := earliestProbeDue(pending); loaded {
			delay := time.Until(dueAt)
			if delay < 0 {
				delay = 0
			}
			timer.Reset(delay)
			timerC = timer.C
		}
		s.depth.Store(int64(len(pending) + len(rerun)))

		select {
		case <-s.ctx.Done():
			return
		case <-ownerReadyChannel:
			ownerReady = true
			ownerReadyChannel = nil
			ownerStallChannel = nil
			if ownerStallTimer != nil {
				ownerStallTimer.Stop()
			}
		case <-ownerStallChannel:
			ownerStallChannel = nil
			if s.owner != nil {
				s.owner.stats.stalled.Add(1)
			}
		case request := <-s.submit:
			status := s.acceptSubmission(request, pending, active, rerun)
			request.reply <- ProbeSubmission{Status: status, Err: submissionError(status)}
		case cancellation := <-s.cancelWaiter:
			cancelProbeWaiter(cancellation, pending, active, rerun)
			if dispatch != nil && pending[dispatch.task.Key] == nil {
				dispatchCancel()
				dispatch, dispatchContext, dispatchCancel = nil, nil, nil
			}
		case removal := <-s.remove:
			removeProbes(removal, pending, active, rerun, finish)
			if dispatch != nil && pending[dispatch.task.Key] == nil {
				dispatchCancel()
				dispatch, dispatchContext, dispatchCancel = nil, nil, nil
			}
		case jobChannel <- job:
			delete(pending, dispatch.task.Key)
			active[dispatch.task.Key] = &activeProbe{entry: dispatch, cancel: dispatchCancel}
			dispatch = nil
			dispatchContext = nil
			dispatchCancel = nil
		case completion := <-s.done:
			running := active[completion.key]
			if running == nil {
				continue
			}
			running.cancel()
			delete(active, completion.key)
			s.stats.completed.Add(1)
			if s.owner != nil {
				s.owner.stats.completed.Add(1)
			}
			finish(running.entry, completion.result)
			next := rerun[completion.key]
			delete(rerun, completion.key)
			if completion.task.Interval > 0 {
				periodic := completion.task
				nextInterval := nextPeriodicProbeInterval(periodic, completion.result)
				if completion.result.Outcome == OutcomeFailure {
					if periodic.FailureStreak < 3 {
						periodic.FailureStreak++
					}
					periodic.SuccessStreak = 0
				} else if completion.result.Outcome == OutcomeSuccess {
					periodic.FailureStreak = 0
					if periodic.SuccessStreak < 3 {
						periodic.SuccessStreak++
					}
				}
				periodic.DueAt = time.Now().Add(nextInterval)
				periodic.SubmittedAt = time.Now()
				if next == nil {
					next = &scheduledProbe{task: periodic, waiters: make(map[uint64]probeWaiter)}
				} else if next.task.Interval <= 0 {
					next.task.Interval = periodic.Interval
					next.task.FailureInterval = periodic.FailureInterval
				}
			}
			if next != nil {
				if len(pending)+len(rerun) < s.queueSize {
					pending[next.task.Key] = next
				} else {
					s.deferEntry(next, finish, ErrProbeQueueFull.Error())
				}
			}
		case <-timerC:
		}
	}
}

func nextPeriodicProbeInterval(task ProbeTask, result ProbeResult) time.Duration {
	if result.Outcome == OutcomeFailure {
		switch task.FailureStreak {
		case 0:
			return 30 * time.Second
		case 1:
			return time.Minute
		default:
			return 5 * time.Minute
		}
	}
	if result.Outcome == OutcomeSuccess {
		switch task.SuccessStreak {
		case 0:
			return 5 * time.Minute
		case 1:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	return task.Interval
}

func newProbeDispatchContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func observeProbeTask(task ProbeTask, result ProbeResult) (ok bool) {
	ok = true
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	task.Observe(task, result)
	return ok
}

func (s *ProbeScheduler) acceptSubmission(request probeSubmitRequest, pending map[ProbeKey]*scheduledProbe, active map[ProbeKey]*activeProbe, rerun map[ProbeKey]*scheduledProbe) ProbeSubmitStatus {
	if existing := pending[request.task.Key]; existing != nil {
		existing.task = mergeProbeTask(existing.task, request.task)
		existing.waiters[request.waiter.id] = request.waiter
		s.stats.coalesced.Add(1)
		if s.owner != nil {
			s.owner.stats.coalesced.Add(1)
		}
		return ProbeCoalesced
	}
	if active[request.task.Key] != nil {
		if !request.task.FreshAfterCurrent {
			active[request.task.Key].entry.waiters[request.waiter.id] = request.waiter
			s.stats.coalesced.Add(1)
			if s.owner != nil {
				s.owner.stats.coalesced.Add(1)
			}
			return ProbeCoalesced
		}
		if existing := rerun[request.task.Key]; existing != nil {
			existing.task = mergeProbeTask(existing.task, request.task)
			existing.waiters[request.waiter.id] = request.waiter
		} else {
			if len(pending)+len(rerun) >= s.queueSize {
				s.deferWaiter(request.waiter, ErrProbeQueueFull.Error())
				return ProbeDeferred
			}
			rerun[request.task.Key] = &scheduledProbe{task: request.task, waiters: map[uint64]probeWaiter{request.waiter.id: request.waiter}}
		}
		s.stats.coalesced.Add(1)
		if s.owner != nil {
			s.owner.stats.coalesced.Add(1)
		}
		return ProbeCoalesced
	}
	if len(pending)+len(rerun) >= s.queueSize {
		s.deferWaiter(request.waiter, ErrProbeQueueFull.Error())
		return ProbeDeferred
	}
	pending[request.task.Key] = &scheduledProbe{task: request.task, waiters: map[uint64]probeWaiter{request.waiter.id: request.waiter}}
	s.stats.accepted.Add(1)
	if s.owner != nil {
		s.owner.stats.accepted.Add(1)
	}
	return ProbeAccepted
}

func submissionError(status ProbeSubmitStatus) error {
	if status == ProbeDeferred {
		return ErrProbeQueueFull
	}
	if status == ProbeRejected {
		return ErrProbeSchedulerOwner
	}
	return nil
}

func (s *ProbeScheduler) deferWaiter(waiter probeWaiter, reason string) {
	s.stats.deferred.Add(1)
	if s.owner != nil {
		s.owner.stats.deferred.Add(1)
	}
	waiter.result <- ProbeResult{Outcome: OutcomeDeferred, Reason: reason}
	close(waiter.result)
}

func (s *ProbeScheduler) deferEntry(entry *scheduledProbe, finish func(*scheduledProbe, ProbeResult), reason string) {
	s.stats.deferred.Add(1)
	if s.owner != nil {
		s.owner.stats.deferred.Add(1)
	}
	finish(entry, ProbeResult{Outcome: OutcomeDeferred, Reason: reason})
}

func cancelProbeWaiter(cancellation probeCancelRequest, pending map[ProbeKey]*scheduledProbe, active map[ProbeKey]*activeProbe, rerun map[ProbeKey]*scheduledProbe) {
	result := ProbeResult{Outcome: OutcomeDeferred, Reason: context.Canceled.Error()}
	if entry := pending[cancellation.key]; entry != nil {
		if waiter, loaded := entry.waiters[cancellation.waiterID]; loaded {
			waiter.result <- result
			close(waiter.result)
			delete(entry.waiters, cancellation.waiterID)
			if len(entry.waiters) == 0 && entry.task.Interval <= 0 {
				delete(pending, cancellation.key)
			}
		}
		return
	}
	if entry := rerun[cancellation.key]; entry != nil {
		if waiter, loaded := entry.waiters[cancellation.waiterID]; loaded {
			waiter.result <- result
			close(waiter.result)
			delete(entry.waiters, cancellation.waiterID)
			if len(entry.waiters) == 0 && entry.task.Interval <= 0 {
				delete(rerun, cancellation.key)
			}
		}
		return
	}
	if running := active[cancellation.key]; running != nil {
		if waiter, loaded := running.entry.waiters[cancellation.waiterID]; loaded {
			waiter.result <- result
			close(waiter.result)
			delete(running.entry.waiters, cancellation.waiterID)
			if len(running.entry.waiters) == 0 && running.entry.task.Interval <= 0 {
				running.cancel()
			}
		}
	}
}

func removeProbes(removal probeRemoval, pending map[ProbeKey]*scheduledProbe, active map[ProbeKey]*activeProbe, rerun map[ProbeKey]*scheduledProbe, finish func(*scheduledProbe, ProbeResult)) {
	result := ProbeResult{Outcome: OutcomeDeferred, Reason: "probe identity retired"}
	for key, entry := range pending {
		if probeRemovalMatches(removal, key) {
			delete(pending, key)
			finish(entry, result)
		}
	}
	for key, entry := range rerun {
		if probeRemovalMatches(removal, key) {
			delete(rerun, key)
			finish(entry, result)
		}
	}
	for key, running := range active {
		if probeRemovalMatches(removal, key) {
			running.cancel()
		}
	}
}

func probeRemovalMatches(removal probeRemoval, key ProbeKey) bool {
	return (removal.epochID == 0 || key.RuntimeEpochID == removal.epochID) &&
		(removal.revision == 0 || key.CatalogRevision == removal.revision) &&
		(removal.nodeID == (NodeID{}) || key.NodeID == removal.nodeID) &&
		(removal.nodeSlot == 0 || key.NodeSlot == removal.nodeSlot) &&
		(removal.nodeVersion == 0 || key.NodeVersion == removal.nodeVersion)
}

func mergeProbeTask(existing, next ProbeTask) ProbeTask {
	if next.DueAt.Before(existing.DueAt) {
		existing.DueAt = next.DueAt
	}
	if next.Priority > existing.Priority {
		existing.Priority = next.Priority
	}
	if existing.Source == "" {
		existing.Source = next.Source
	}
	existing.Run = next.Run
	existing.Observe = next.Observe
	if next.Interval > 0 || existing.Interval <= 0 {
		existing.Interval = next.Interval
	}
	if next.FailureInterval > 0 || existing.FailureInterval <= 0 {
		existing.FailureInterval = next.FailureInterval
	}
	if next.Timeout > 0 {
		existing.Timeout = next.Timeout
	}
	return existing
}

func nextScheduledProbe(now time.Time, pending map[ProbeKey]*scheduledProbe, lastSource map[ProbePriority]string, highBurst *int, forcedPriority *ProbePriority) (*scheduledProbe, bool) {
	readyByPriority := make(map[ProbePriority][]*scheduledProbe)
	var highest ProbePriority
	for _, entry := range pending {
		if entry.task.DueAt.After(now) {
			continue
		}
		priority := entry.task.Priority
		if priority == 0 {
			priority = ProbePriorityCoverage
		}
		readyByPriority[priority] = append(readyByPriority[priority], entry)
		if priority > highest {
			highest = priority
		}
	}
	if highest == 0 {
		return nil, false
	}
	selectedPriority := highest
	if *highBurst >= maxHighPriorityBurst {
		lower := make([]ProbePriority, 0, int(highest)-1)
		for priority := ProbePriorityCoverage; priority < highest; priority++ {
			if len(readyByPriority[priority]) > 0 {
				lower = append(lower, priority)
			}
		}
		if len(lower) > 0 {
			selectedPriority = lower[0]
			for _, priority := range lower {
				if priority > *forcedPriority {
					selectedPriority = priority
					break
				}
			}
			*forcedPriority = selectedPriority
		}
	}
	if selectedPriority != highest {
		*highBurst = 0
	} else {
		*highBurst++
	}
	candidates := readyByPriority[selectedPriority]
	sources := make([]string, 0)
	bySource := make(map[string][]*scheduledProbe)
	for _, entry := range candidates {
		source := entry.task.Source
		if source == "" {
			source = "default"
		}
		if _, loaded := bySource[source]; !loaded {
			sources = append(sources, source)
		}
		bySource[source] = append(bySource[source], entry)
	}
	sort.Strings(sources)
	selectedSource := sources[0]
	if previous := lastSource[selectedPriority]; previous != "" {
		index := sort.SearchStrings(sources, previous)
		if index < len(sources) && sources[index] == previous {
			selectedSource = sources[(index+1)%len(sources)]
		}
	}
	lastSource[selectedPriority] = selectedSource
	entries := bySource[selectedSource]
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].task.SubmittedAt.Equal(entries[j].task.SubmittedAt) {
			return entries[i].task.SubmittedAt.Before(entries[j].task.SubmittedAt)
		}
		return compareProbeKey(entries[i].task.Key, entries[j].task.Key) < 0
	})
	return entries[0], true
}

func compareProbeKey(left, right ProbeKey) int {
	if compared := bytes.Compare(left.NodeID[:], right.NodeID[:]); compared != 0 {
		return compared
	}
	if left.NodeSlot != right.NodeSlot {
		if left.NodeSlot < right.NodeSlot {
			return -1
		}
		return 1
	}
	if left.NodeVersion != right.NodeVersion {
		if left.NodeVersion < right.NodeVersion {
			return -1
		}
		return 1
	}
	if left.Suite < right.Suite {
		return -1
	}
	if left.Suite > right.Suite {
		return 1
	}
	if left.Target < right.Target {
		return -1
	}
	if left.Target > right.Target {
		return 1
	}
	return 0
}

func earliestProbeDue(pending map[ProbeKey]*scheduledProbe) (time.Time, bool) {
	var earliest time.Time
	for _, entry := range pending {
		if earliest.IsZero() || entry.task.DueAt.Before(earliest) {
			earliest = entry.task.DueAt
		}
	}
	return earliest, !earliest.IsZero()
}
