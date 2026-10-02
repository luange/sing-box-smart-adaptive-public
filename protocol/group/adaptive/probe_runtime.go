package adaptive

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
)

// isProxyFramingProbeError reports encapsulation/parse faults seen when a DNS
// UDP probe rides a proxy protocol (trojan/vless). These must not hard-open the
// udp_dns breaker the way a real DNS path failure would.
func isProxyFramingProbeError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Timeouts keep the timeout classifier; only framing/parse faults match here.
	if strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded") {
		return false
	}
	return strings.Contains(msg, "unknown address family") ||
		strings.Contains(msg, "unknown version") ||
		(strings.Contains(msg, "read destination") && (strings.Contains(msg, "address family") || strings.Contains(msg, "unknown version") || strings.Contains(msg, "EOF")))
}

func (p *AdaptivePool) scheduleFailureProbe(handle NodeHandle) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return
	}
	candidate, loaded := snapshot.Candidate(handle.NodeID)
	if !loaded || candidate.Handle.Slot != handle.Slot || candidate.Handle.Version != handle.Version {
		return
	}
	_ = scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
	// Accelerate DNS recovery only for ipv4. Production showed automatic ipv6 DNS
	// probes mostly emit protocol noise (address family 0 / framing) and pile the
	// queue without improving TCP business selection. IPv6 DNS stays passive-only.
	health, _, _, _ := p.runtimeSnapshot()
	if health == nil {
		return
	}
	path := "udp_dns/ipv4"
	status := health.StatusHandle(handle, DomainTransport, path, "")
	if status.Breaker == BreakerOpen || status.Breaker == BreakerCooldown || status.Health == HealthUnreachable {
		_ = scheduler.Submit(p.dnsHealthProbeTask(snapshot, candidate, "ipv4", time.Now(), 0))
	}
}

func (p *AdaptivePool) startupProbeTasks(snapshot *ExecutionSnapshot, now time.Time) []ProbeTask {
	if snapshot == nil || len(snapshot.Candidates) == 0 {
		return nil
	}
	candidates := slices.Clone(snapshot.Candidates)
	slices.SortFunc(candidates, func(left, right Candidate) int {
		if compared := bytes.Compare(left.ID[:], right.ID[:]); compared != 0 {
			return compared
		}
		if left.Handle.Slot < right.Handle.Slot {
			return -1
		}
		if left.Handle.Slot > right.Handle.Slot {
			return 1
		}
		if left.Handle.Version < right.Handle.Version {
			return -1
		}
		if left.Handle.Version > right.Handle.Version {
			return 1
		}
		return 0
	})

	immediate := min(max(p.probeConcurrency, 1), len(candidates))
	spreadCount := len(candidates) - immediate
	spread := p.probeCoverage / 10
	if spread > 30*time.Second {
		spread = 30 * time.Second
	}
	if spread < 0 {
		spread = 0
	}
	// One HTTP endpoint probe per candidate. DNS/IPv4 only for non-replica
	// primaries — provider "(2)" siblings and endpoint-conflict secondaries are
	// endpoint-probed later (or on demand) so large OT pools do not bury the
	// queue under framing/TLS noise. DNS/IPv6 stays passive-only.
	tasks := make([]ProbeTask, 0, len(candidates)*2)
	replicaIndex := 0
	for index, candidate := range candidates {
		dueAt := now
		if index >= immediate && spreadCount > 0 {
			dueAt = now.Add(time.Duration(index-immediate+1) * spread / time.Duration(spreadCount))
		}
		replica := isProviderReplicaCandidate(candidate)
		if replica {
			// Push replica endpoint probes to the back of the stagger window so
			// primary tags claim workers first.
			replicaIndex++
			extra := spread
			if extra < 15*time.Second {
				extra = 15 * time.Second
			}
			dueAt = now.Add(extra + time.Duration(replicaIndex)*time.Second)
			tasks = append(tasks, p.probeTask(snapshot, candidate, dueAt, p.probeCoverage))
			continue
		}
		tasks = append(tasks,
			p.probeTask(snapshot, candidate, dueAt, p.probeCoverage),
			p.dnsHealthProbeTask(snapshot, candidate, "ipv4", dueAt, p.probeCoverage),
		)
	}
	return tasks
}

// isProviderReplicaCandidate reports subscription siblings such as
// "airport/香港-… (2)" that share an endpoint identity with a primary tag.
// These often fail TLS/framing while the primary stays healthy; auto DNS
// probing them mostly inflates the queue without improving selection.
func isProviderReplicaCandidate(candidate Candidate) bool {
	return isProviderReplicaTag(candidate.PrimaryTag)
}

// isProviderReplicaTag matches provider duplicate suffixes: " (2)", " (3)", …
func isProviderReplicaTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	open := strings.LastIndex(tag, " (")
	if open < 0 || !strings.HasSuffix(tag, ")") {
		return false
	}
	num := tag[open+2 : len(tag)-1]
	if num == "" || num == "1" {
		return false
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (p *AdaptivePool) runGenericProbe(ctx context.Context, snapshot *ExecutionSnapshot, candidate Candidate) (ProbeResult, uint16) {
	health, _, _, _ := p.runtimeSnapshot()
	if health == nil {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "adaptive health store unavailable"}, 0
	}
	current := p.catalog.load()
	if current == nil || snapshot == nil || current.RuntimeEpochID != snapshot.RuntimeEpochID || current.CatalogRevision != snapshot.CatalogRevision || current.Generation != snapshot.Generation {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "catalog revision unavailable"}, 0
	}
	currentCandidate, loaded := current.Candidate(candidate.ID)
	if !loaded || currentCandidate.Handle.Slot != candidate.Handle.Slot || currentCandidate.Handle.Version != candidate.Handle.Version {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "candidate handle retired"}, 0
	}
	permit, allowed := health.TryAcquireDomainPermitHandle(candidate.Handle, DomainEndpoint, "", "", health.Now())
	if !allowed {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "endpoint breaker deferred"}, 0
	}
	var attempt *observationAttempt
	var err error
	if current.RuntimeEpochID != 0 && current.CatalogRevision != 0 && p.runtimeManager != nil {
		attempt, err = p.beginObservationAttempt(current, currentCandidate, permit, N.NetworkTCP)
		if err != nil {
			permit.ReleaseDeferred()
			return ProbeResult{Outcome: OutcomeDeferred, Reason: err.Error()}, 0
		}
	}
	startedAt := time.Now()
	execution, loaded := p.catalog.AcquireExecution(ExecutionToken{RuntimeEpochID: current.RuntimeEpochID, CatalogRevision: current.CatalogRevision, Handle: currentCandidate.Handle})
	if !loaded {
		p.completeGenericProbe(attempt, ErrExecutionBindingUnavailable, time.Since(startedAt), true)
		return ProbeResult{Outcome: OutcomeDeferred, Reason: ErrExecutionBindingUnavailable.Error(), Settled: true}, 0
	}
	delay, probeErr := p.runProbe(ctx, execution.Port)
	execution.Release()
	elapsed := time.Since(startedAt)
	latest := p.catalog.load()
	latestCandidate, stillActive := Candidate{}, false
	if latest != nil {
		latestCandidate, stillActive = latest.Candidate(candidate.ID)
	}
	stale := latest == nil || latest.RuntimeEpochID != snapshot.RuntimeEpochID || latest.CatalogRevision != snapshot.CatalogRevision || latest.Generation != snapshot.Generation || !stillActive || latestCandidate.Handle.Slot != candidate.Handle.Slot || latestCandidate.Handle.Version != candidate.Handle.Version
	deferred := stale || !p.probeOwnerActive() || (p.ctx != nil && p.ctx.Err() != nil) || (ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded))
	if attempt == nil {
		permit.ReleaseDeferred()
	} else {
		p.completeGenericProbe(attempt, probeErr, elapsed, deferred)
	}
	if deferred {
		return ProbeResult{Outcome: OutcomeDeferred, Delay: elapsed, Reason: "probe identity retired", Settled: attempt != nil}, delay
	}
	if probeErr != nil {
		return ProbeResult{Outcome: OutcomeFailure, Delay: elapsed, Reason: probeErr.Error(), Settled: attempt != nil}, delay
	}
	return ProbeResult{Outcome: OutcomeSuccess, Delay: time.Duration(delay) * time.Millisecond, Settled: attempt != nil}, delay
}

func (p *AdaptivePool) runDNSHealthProbe(ctx context.Context, snapshot *ExecutionSnapshot, candidate Candidate, family string) ProbeResult {
	health, _, _, _ := p.runtimeSnapshot()
	if health == nil {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "adaptive health store unavailable"}
	}
	current := p.catalog.load()
	if current == nil || snapshot == nil || current.RuntimeEpochID != snapshot.RuntimeEpochID || current.CatalogRevision != snapshot.CatalogRevision || current.Generation != snapshot.Generation {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "catalog revision unavailable"}
	}
	currentCandidate, loaded := current.Candidate(candidate.ID)
	if !loaded || currentCandidate.Handle.Slot != candidate.Handle.Slot || currentCandidate.Handle.Version != candidate.Handle.Version {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "candidate handle retired"}
	}
	path := "udp_dns/" + family
	permit, allowed := health.TryAcquireDomainPermitHandle(candidate.Handle, DomainTransport, path, "", health.Now())
	if !allowed {
		return ProbeResult{Outcome: OutcomeDeferred, Reason: "DNS path breaker deferred"}
	}
	attempt, err := p.beginObservationAttempt(current, currentCandidate, permit, N.NetworkUDP, path)
	if err != nil {
		permit.ReleaseDeferred()
		return ProbeResult{Outcome: OutcomeDeferred, Reason: err.Error()}
	}
	startedAt := time.Now()
	execution, loaded := p.catalog.AcquireExecution(ExecutionToken{RuntimeEpochID: current.RuntimeEpochID, CatalogRevision: current.CatalogRevision, Handle: currentCandidate.Handle})
	if !loaded {
		p.completeDNSHealthProbe(attempt, ErrExecutionBindingUnavailable, time.Since(startedAt), true)
		return ProbeResult{Outcome: OutcomeDeferred, Reason: ErrExecutionBindingUnavailable.Error(), Settled: true}
	}
	probeErr := runDNSHealthTargets(ctx, execution.Port, family)
	execution.Release()
	elapsed := time.Since(startedAt)
	latest := p.catalog.load()
	latestCandidate, stillActive := Candidate{}, false
	if latest != nil {
		latestCandidate, stillActive = latest.Candidate(candidate.ID)
	}
	stale := latest == nil || latest.RuntimeEpochID != snapshot.RuntimeEpochID || latest.CatalogRevision != snapshot.CatalogRevision || latest.Generation != snapshot.Generation || !stillActive || latestCandidate.Handle != candidate.Handle
	deferred := stale || !p.probeOwnerActive() || (p.ctx != nil && p.ctx.Err() != nil) || (ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded))
	p.completeDNSHealthProbe(attempt, probeErr, elapsed, deferred)
	if deferred {
		return ProbeResult{Outcome: OutcomeDeferred, Delay: elapsed, Reason: "DNS probe identity retired", Settled: true}
	}
	if probeErr != nil {
		return ProbeResult{Outcome: OutcomeFailure, Delay: elapsed, Reason: probeErr.Error(), Settled: true}
	}
	return ProbeResult{Outcome: OutcomeSuccess, Delay: elapsed, Settled: true}
}

func (p *AdaptivePool) completeDNSHealthProbe(attempt *observationAttempt, probeErr error, delay time.Duration, deferred bool) {
	defer attempt.lease.Release()
	evidence := attempt.evidence
	evidence.Source = SourceDNS
	evidence.Stage = StageDNSHealth
	evidence.Confidence = ConfidenceHigh
	evidence.Delay = delay
	if attempt.reducer != nil && attempt.reducer.Store != nil {
		evidence.At = attempt.reducer.Store.Now()
	} else {
		evidence.At = time.Now()
	}
	evidence.Reason = errorReason(probeErr)
	switch {
	case deferred:
		evidence.Outcome, evidence.Failure = OutcomeDeferred, FailureCanceled
	case probeErr == nil:
		evidence.Outcome, evidence.Failure = OutcomeSuccess, FailureNone
	case errors.Is(probeErr, context.DeadlineExceeded) || isTimeoutError(probeErr):
		// Same matrix as dial timeout: medium quality; repeated → Unreachable.
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureTimeout
		evidence.Confidence = ConfidenceMedium
	case isProxyFramingProbeError(probeErr):
		// Trojan/VLESS "unknown address family: 0" / "unknown version" are
		// encapsulation faults, not proof the node cannot resolve DNS.
		// ConfidenceLow is metrics-only (weight < 0.5): never degrade/unreachable
		// the udp_dns ledger the way a real path blackhole would. Production rc30
		// showed Medium framing still stacking NonBreakerFailures → Unreachable.
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureProtocol
		evidence.Confidence = ConfidenceLow
	default:
		// Clear DNS protocol failures (bad rcode after a real response, etc.).
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureDNS
	}
	disposition, publishErr := PublishSettledObservationGuarded(p.sharedObservationIngestor(), attempt.guard, evidence, attempt.reducer)
	p.recordObservationResult(disposition, publishErr)
}

func (p *AdaptivePool) probeOwnerActive() bool {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	return scheduler == nil || scheduler.ActiveOwner()
}

func (p *AdaptivePool) completeGenericProbe(attempt *observationAttempt, probeErr error, delay time.Duration, deferred bool) {
	defer attempt.lease.Release()
	evidence := attempt.evidence
	evidence.Source = SourceProbe
	evidence.Stage = StageProxyTunnel
	// A single external target is useful quality evidence, but it cannot
	// distinguish a node failure from common-mode target failure or blocking.
	evidence.Confidence = ConfidenceMedium
	evidence.Delay = delay
	if attempt.reducer != nil && attempt.reducer.Store != nil {
		evidence.At = attempt.reducer.Store.Now()
	} else {
		evidence.At = time.Now()
	}
	evidence.Reason = errorReason(probeErr)
	switch {
	case deferred:
		evidence.Outcome, evidence.Failure = OutcomeDeferred, FailureCanceled
	case probeErr == nil:
		evidence.Outcome, evidence.Failure = OutcomeSuccess, FailureNone
	case errors.Is(probeErr, context.DeadlineExceeded):
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureTimeout
	default:
		evidence.Outcome, evidence.Failure = OutcomeFailure, FailureConnect
	}
	disposition, publishErr := PublishSettledObservationGuarded(p.sharedObservationIngestor(), attempt.guard, evidence, attempt.reducer)
	p.recordObservationResult(disposition, publishErr)
}

func (p *AdaptivePool) probeTask(snapshot *ExecutionSnapshot, candidate Candidate, dueAt time.Time, interval time.Duration) ProbeTask {
	priority := ProbePriorityOnDemand
	failureInterval := time.Duration(0)
	if interval > 0 {
		priority = ProbePriorityCoverage
		failureInterval = interval / 4
		if failureInterval > time.Minute {
			failureInterval = time.Minute
		}
		if failureInterval <= 0 {
			failureInterval = interval
		}
	}
	return ProbeTask{
		Key: ProbeKey{
			RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
			NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version, Suite: "generic-http", Target: p.probeURL,
		},
		Source:          firstOrDefault(candidate.Sources, "static"),
		Priority:        priority,
		DueAt:           dueAt,
		Interval:        interval,
		FailureInterval: failureInterval,
		Timeout:         p.probeTimeout,
		Run: func(ctx context.Context) ProbeResult {
			if !globalEndpointProfiles.Acquire(ctx, candidate.EndpointID, TrackTCP4) {
				return ProbeResult{Outcome: OutcomeDeferred, Reason: "endpoint probe wait canceled"}
			}
			defer globalEndpointProfiles.Release(candidate.EndpointID, TrackTCP4)
			result, _ := p.runGenericProbe(ctx, snapshot, candidate)
			globalEndpointProfiles.Record(candidate.EndpointID, TrackTCP4, result.Outcome == OutcomeSuccess, result.Delay, time.Now())
			return result
		},
	}
}

func (p *AdaptivePool) dnsHealthProbeTask(snapshot *ExecutionSnapshot, candidate Candidate, family string, dueAt time.Time, interval time.Duration) ProbeTask {
	priority := ProbePriorityOnDemand
	failureInterval := time.Duration(0)
	if interval > 0 {
		priority = ProbePriorityCoverage
		failureInterval = interval / 4
		if failureInterval > time.Minute {
			failureInterval = time.Minute
		}
		if failureInterval <= 0 {
			failureInterval = interval
		}
	}
	return ProbeTask{
		Key: ProbeKey{
			RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
			NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version, Suite: "dns-health", Target: family,
		},
		Source: firstOrDefault(candidate.Sources, "static"), Priority: priority, DueAt: dueAt,
		Interval: interval, FailureInterval: failureInterval, Timeout: max(p.probeTimeout, 5*time.Second),
		Run: func(ctx context.Context) ProbeResult {
			track := TrackDNSUDP4
			if family == "ipv6" {
				track = TrackDNSUDP6
			}
			if !globalEndpointProfiles.Acquire(ctx, candidate.EndpointID, track) {
				return ProbeResult{Outcome: OutcomeDeferred, Reason: "endpoint DNS probe wait canceled"}
			}
			defer globalEndpointProfiles.Release(candidate.EndpointID, track)
			result := p.runDNSHealthProbe(ctx, snapshot, candidate, family)
			globalEndpointProfiles.Record(candidate.EndpointID, track, result.Outcome == OutcomeSuccess, result.Delay, time.Now())
			return result
		},
	}
}

func (p *AdaptivePool) runProbe(ctx context.Context, candidate N.Dialer) (uint16, error) {
	if p.probeRunner == nil {
		return urltest.URLTest(ctx, p.probeURL, candidate)
	}
	return p.probeRunner(ctx, p.probeURL, candidate)
}
