package adaptive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrBreakerAttemptDeferred = errors.New("adaptive attempt deferred by breaker")

type DialAttemptResult struct {
	Candidate  Candidate
	Err        error
	Delay      time.Duration
	Deferred   bool
	Panic      bool
	RemoteAddr net.Addr // set on successful dial so health can pin the family
}

type AttemptComplete func(DialAttemptResult)
type AttemptBegin func(Candidate, *AttemptPermit) (AttemptComplete, error)

type AttemptRunner struct {
	attemptTimeout time.Duration
	hedgeDelay     time.Duration
	bridge         ExecutionBridge
}

func NewAttemptRunner(attemptTimeout, hedgeDelay time.Duration, bridges ...ExecutionBridge) *AttemptRunner {
	if attemptTimeout <= 0 {
		attemptTimeout = 4 * time.Second
	}
	if hedgeDelay <= 0 {
		hedgeDelay = 450 * time.Millisecond
	}
	var bridge ExecutionBridge
	if len(bridges) > 0 {
		bridge = bridges[0]
	}
	return &AttemptRunner{attemptTimeout: attemptTimeout, hedgeDelay: hedgeDelay, bridge: bridge}
}

type dialResult struct {
	candidate Candidate
	conn      net.Conn
	err       error
	delay     time.Duration
	deferred  bool
}

func (r *AttemptRunner) Dial(ctx context.Context, network string, destination M.Socksaddr, plan DecisionPlan, begin AttemptBegin) (net.Conn, Candidate, error) {
	if len(plan.Candidates) == 0 {
		return nil, Candidate{}, ErrNoEligibleCandidates
	}
	parentCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	results := make(chan dialResult, len(plan.Candidates))
	start := func(candidate Candidate) {
		go func() {
			startedAt := time.Now()
			permit, allowed := plan.TryAcquireAttemptPermit(candidate.ID, time.Time{})
			if !allowed {
				results <- dialResult{candidate: candidate, err: ErrBreakerAttemptDeferred, deferred: true}
				return
			}
			var complete AttemptComplete
			if begin != nil {
				var beginErr error
				complete, beginErr = begin(candidate, permit)
				if beginErr != nil {
					permit.ReleaseDeferred()
					results <- dialResult{candidate: candidate, err: beginErr, deferred: true}
					return
				}
			}
			if complete == nil {
				complete = func(DialAttemptResult) { permit.ReleaseDeferred() }
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					panicErr := fmt.Errorf("adaptive outbound dial panic: %v", recovered)
					complete(DialAttemptResult{Candidate: candidate, Err: panicErr, Delay: time.Since(startedAt), Panic: true})
					results <- dialResult{candidate: candidate, err: panicErr}
				}
			}()
			attemptCtx, cancel := context.WithTimeout(parentCtx, r.attemptTimeout)
			defer cancel()
			execution, loaded := r.resolve(plan, candidate)
			if !loaded {
				complete(DialAttemptResult{Candidate: candidate, Err: ErrExecutionBindingUnavailable, Delay: time.Since(startedAt)})
				results <- dialResult{candidate: candidate, err: ErrExecutionBindingUnavailable}
				return
			}
			defer execution.Release()
			conn, err := execution.Port.DialContext(attemptCtx, network, destination)
			cancel()
			if err == nil && conn == nil {
				err = errors.New("adaptive outbound returned nil connection")
			}
			if err == nil && parentCtx.Err() != nil {
				_ = conn.Close()
				complete(DialAttemptResult{Candidate: candidate, Err: parentCtx.Err(), Delay: time.Since(startedAt), Deferred: true})
				return
			}
			if parentCtx.Err() != nil {
				complete(DialAttemptResult{Candidate: candidate, Err: parentCtx.Err(), Delay: time.Since(startedAt), Deferred: true})
				results <- dialResult{candidate: candidate, err: parentCtx.Err(), deferred: true}
				return
			}
			result := DialAttemptResult{Candidate: candidate, Err: err, Delay: time.Since(startedAt)}
			if err == nil && conn != nil {
				result.RemoteAddr = conn.RemoteAddr()
			}
			complete(result)
			results <- dialResult{candidate: candidate, conn: conn, err: err, delay: time.Since(startedAt)}
		}()
	}

	started := 1
	active := 1
	start(plan.Candidates[0])
	timer := time.NewTimer(r.hedgeDelay)
	defer timer.Stop()
	var timerChannel <-chan time.Time
	// No hedge on bulk/strict/warming-outage plans — parallel fan-out storms
	// dead nodes when every candidate is already blocked.
	if !plan.disableHedge && !plan.allowBlocked && plan.Mode != ModeBulk && plan.Mode != ModeStrictAffinity && len(plan.Candidates) > 1 {
		timerChannel = timer.C
	} else {
		if !timer.Stop() {
			<-timer.C
		}
	}
	var attemptErrors []error
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, Candidate{}, errors.Join(append(attemptErrors, ctx.Err())...)
		case <-timerChannel:
			if started < len(plan.Candidates) {
				start(plan.Candidates[started])
				started++
				active++
			}
			if started < len(plan.Candidates) {
				timer.Reset(r.hedgeDelay)
				timerChannel = timer.C
			} else {
				timerChannel = nil
			}
		case result := <-results:
			active--
			if result.deferred {
				attemptErrors = append(attemptErrors, E.Cause(ErrBreakerAttemptDeferred, "adaptive candidate ", result.candidate.PrimaryTag))
				if started < len(plan.Candidates) {
					start(plan.Candidates[started])
					started++
					active++
				}
				continue
			}
			if result.err != nil {
				attemptErrors = append(attemptErrors, E.Cause(result.err, "adaptive candidate ", result.candidate.PrimaryTag))
				if started < len(plan.Candidates) {
					start(plan.Candidates[started])
					started++
					active++
				}
				continue
			}
			cancelAll()
			return result.conn, result.candidate, nil
		}
	}
	if len(attemptErrors) == 0 {
		return nil, Candidate{}, ErrNoEligibleCandidates
	}
	return nil, Candidate{}, errors.Join(attemptErrors...)
}

func (r *AttemptRunner) resolve(plan DecisionPlan, candidate Candidate) (*ExecutionLease, bool) {
	if r == nil || r.bridge == nil {
		return nil, false
	}
	return r.bridge.AcquireExecution(ExecutionToken{RuntimeEpochID: plan.RuntimeEpochID, CatalogRevision: plan.CatalogRevision, Handle: candidate.Handle})
}

func errorReason(err error) string {
	if err == nil {
		return ""
	}
	// Collapse multi-line proxy errors (e.g. joined read destination faults) so
	// status/filter_reasons stay single-line and bounded for operators.
	reason := strings.Join(strings.Fields(err.Error()), " ")
	if len(reason) > 160 {
		reason = reason[:160]
	}
	return reason
}
