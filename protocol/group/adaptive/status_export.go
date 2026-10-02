package adaptive

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func (p *AdaptivePool) AdaptiveStatus() adapter.AdaptivePoolStatus {
	snapshot := p.catalog.load()
	health, leases, control, policy := p.runtimeSnapshot()
	status := adapter.AdaptivePoolStatus{Shadow: p.shadow, UpdatedAt: time.Now()}
	status.MissedObservations = p.missedObservations.Load()
	status.ObservationStaleTotal = p.observationStale.Load()
	status.ObservationDuplicateTotal = p.observationDuplicate.Load()
	status.ObservationBackpressureTotal = p.observationBackpressure.Load()
	status.ObservationReducerFailureTotal = p.observationReducerFailure.Load()
	status.ObservationIdentityFailureTotal = p.observationIdentityFailure.Load()
	status.ObservationPanicTotal = p.observationPanic.Load()
	status.ObservationPermitBusyTotal = p.observationPermitBusy.Load()
	status.BusinessTLSFailuresTotal = p.businessTLSFailures.Load()
	status.TransportFailuresTotal = p.transportFailures.Load()
	status.AIIPv6Policy = p.aiIPv6Policy
	status.AIIPv6BlockedTotal = p.aiIPv6Blocked.Load()
	status.RecentSwitches, status.SelectionSwitchesTotal = p.switchAudit.Snapshot()
	status.DeltaAppliedTotal = p.deltaAppliedTotal.Load()
	status.DeltaFallbackTotal = p.deltaFallbackTotal.Load()
	if control == nil {
		control = new(ControlState)
	}
	control.access.RLock()
	status.Pinned = control.pinnedTag
	if p.shadow {
		status.Mode = "shadow"
	} else if control.pinned != (NodeID{}) {
		status.Mode = string(ModeManual)
	} else {
		status.Mode = string(p.defaultMode)
	}
	control.access.RUnlock()
	if leases != nil {
		status.ActiveLeases, status.LeaseEvictions = leases.Stats()
	}
	status.BulkSequence = control.bulkSequence.Load()
	status.ControlRevision = control.revision.Load()
	if p.resolver != nil {
		status.ServiceOverrideCount = len(p.resolver.Overrides(time.Now()))
	}
	if p.catalog != nil {
		bindings := p.catalog.BindingStats()
		status.ActiveBindingCount = bindings.Active
		status.RetiredBindingCount = bindings.Retired
	}
	if snapshot == nil {
		return status
	}
	var leaseSnapshot []SessionLease
	if leases != nil {
		leaseSnapshot = leases.PersistenceSnapshot(time.Now())
	}
	slices.SortFunc(leaseSnapshot, func(left, right SessionLease) int {
		if left.ServiceID != right.ServiceID {
			return bytes.Compare([]byte(left.ServiceID), []byte(right.ServiceID))
		}
		return bytes.Compare(left.NodeID[:], right.NodeID[:])
	})
	for _, lease := range leaseSnapshot {
		if len(status.ServiceLeases) >= statusCandidateLimit {
			break
		}
		tag := ""
		if candidate, loaded := snapshot.Candidate(lease.NodeID); loaded && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
			tag = safePersistentTag(candidate.PrimaryTag)
		}
		status.ServiceLeases = append(status.ServiceLeases, adapter.AdaptiveServiceLease{
			ServiceID: lease.ServiceID, AffinityID: serviceAffinityFamily(lease.ServiceID), SessionID: lease.Key.String(), Mode: string(lease.Mode), NodeID: lease.NodeID.String(), Tag: tag,
			ExpiresAt: lease.ExpiresAt, UpdatedAt: lease.UpdatedAt,
		})
	}
	status.Generation = snapshot.Generation
	status.CandidateCount = len(snapshot.Candidates)
	status.DuplicatesSuppressed = snapshot.DuplicatesSuppressed
	status.StableIdentityCount = snapshot.StableIdentityCount
	for _, candidate := range snapshot.Candidates {
		if candidate.EndpointConflictCount > 1 {
			status.EndpointConflictCount++
		}
	}
	// Live health under RLock-friendly snapshot. Bind the same switch stability
	// knobs as the dial path so status scores are not a parallel fictional policy.
	if health == nil {
		return status
	}
	healthView := health.ReadOnlySnapshot()
	policyView := NewPolicyEngine(healthView, p.policyMaxAttempts, p.manualFailure).
		BindNodeWeights(p.nodeWeights).
		BindSwitchStability(p.switchMargin, p.switchCooldown).
		BindAffinityMode(p.affinityMode)
	// Copy sticky prefs from the live engine so margin/cooldown explain matches dial.
	if policy != nil {
		policyView.importStickyFrom(policy)
	}
	defer policyView.Close()
	throughput := healthView.ThroughputByHandle()
	for _, candidate := range snapshot.Candidates {
		status.AliasCount += len(candidate.Aliases)
	}
	if len(snapshot.Candidates) > statusCandidateLimit {
		status.Candidates = make([]adapter.AdaptiveCandidateStatus, 0, statusCandidateLimit)
	} else {
		status.Candidates = make([]adapter.AdaptiveCandidateStatus, 0, len(snapshot.Candidates))
	}
	now := time.Now()
	for _, candidate := range snapshot.Candidates {
		if len(status.Candidates) >= statusCandidateLimit {
			break
		}
		health := healthView.EndpointHandle(candidate.Handle)
		throughputStatus := throughput[candidate.Handle]
		state := string(health.Health)
		if health.Breaker != BreakerClosed {
			state = string(health.Breaker)
		}
		weightMatch := p.nodeWeights.Explain(candidate.PrimaryTag)
		pathStatuses := make([]adapter.AdaptivePathStatus, 0, len(observableHealthPaths))
		for _, path := range observableHealthPaths {
			pathHealth := healthView.StatusHandle(candidate.Handle, DomainTransport, path, "")
			pathStatuses = append(pathStatuses, adapter.AdaptivePathStatus{
				Path: path, Health: string(pathHealth.Health), Breaker: string(pathHealth.Breaker),
				LastUpdated: pathHealth.LastUpdated, LastDelay: durationMillis32(pathHealth.LastDelay),
				SmoothedDelay: durationMillis32(pathHealth.SmoothedDelay), DelaySamples: pathHealth.DelaySamples,
				BackoffMs: uint32(max(0, pathHealth.Backoff.Milliseconds())), ConsecutiveFailures: pathHealth.ConsecutiveFailures,
				Successes: pathHealth.Successes, Failures: pathHealth.Failures, RecoverySuccesses: pathHealth.RecoverySuccesses,
				OpenUntil: pathHealth.CooldownUntil, Reason: pathHealth.Reason,
				HealthPriority: healthPriority(pathHealth.Health), ObservedDelay: durationMillis32(pathHealth.RankingDelay()),
				WeightedDelay: durationMillis32(pathHealth.RankingDelay()), DominantEvidence: path,
			})
		}
		// Rank score uses dual-stack best-family delay (same as dial candidateScore).
		endpointScore := policyView.candidateScore(candidate, ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/any"})
		// Portrait only for the candidates we emit (already capped) — avoid double work.
		profile := healthView.BuildCapabilityProfile(candidate.Handle, now)
		if throughputStatus.Samples > 0 {
			profile.ThroughputBPS = throughputStatus.BPS
			profile.ThroughputOK = throughputStatus.BPS >= 256*1024
		}
		// Multi-path exclusion summary from the portrait already built above.
		filterReasons := healthView.ExplainAllPathExclusions(candidate.Handle, now)
		memory := p.selectionMemoryForHandle(candidate.Handle)
		lastFailure := health.Reason
		if memory.latestFailure.failure != "" {
			lastFailure = memory.latestFailure.failure
		}
		for _, pathStatus := range pathStatuses {
			if pathStatus.Reason != "" && (pathStatus.Breaker == string(BreakerOpen) || pathStatus.Breaker == string(BreakerCooldown) || pathStatus.Health == string(HealthUnreachable)) {
				lastFailure = pathStatus.Path + ":" + pathStatus.Reason
				break
			}
		}
		filterReason := ""
		if len(filterReasons) > 0 {
			filterReason = filterReasons[0]
		}
		status.Candidates = append(status.Candidates, adapter.AdaptiveCandidateStatus{
			NodeID:                candidate.ID.String(),
			EndpointID:            candidate.EndpointID.String(),
			EndpointConflictCount: candidate.EndpointConflictCount,
			NodeSlot:              candidate.Handle.Slot,
			NodeVersion:           candidate.Handle.Version,
			Tag:                   candidate.PrimaryTag,
			Weight:                weightMatch.Weight,
			WeightRule:            weightMatch.Rule,
			WeightRuleExact:       weightMatch.Exact,
			Aliases:               append([]string(nil), candidate.Aliases...),
			IdentityStable:        candidate.IdentityStable,
			State:                 state,
			Health:                string(health.Health),
			Breaker:               string(health.Breaker),
			LastProbeAt:           health.LastUpdated,
			LastProbeDelay:        durationMillis32(health.LastDelay),
			SmoothedDelay:         durationMillis32(health.SmoothedDelay),
			DelaySamples:          health.DelaySamples,
			BackoffMs:             uint32(max(0, health.Backoff.Milliseconds())),
			ConsecutiveFailures:   health.ConsecutiveFailures,
			ThroughputBPS:         throughputStatus.BPS,
			ThroughputSamples:     throughputStatus.Samples,
			Successes:             health.Successes,
			Failures:              health.Failures,
			RecoverySuccesses:     health.RecoverySuccesses,
			EvidenceWeight:        health.EvidenceWeight,
			OpenUntil:             health.CooldownUntil,
			Reason:                health.Reason,
			HealthPriority:        endpointScore.HealthPriority,
			ObservedDelay:         durationMillis32(endpointScore.ObservedDelay),
			WeightedDelay:         durationMillis32(endpointScore.WeightedDelay),
			SelectionScore:        endpointScore.SelectionScore,
			DominantEvidence:      endpointScore.DominantEvidence,
			FilterReason:          filterReason,
			FilterReasons:         filterReasons,
			LastFailure:           lastFailure,
			LastFailureService:    memory.latestFailure.serviceID,
			LastFailurePath:       memory.latestFailure.path,
			LastSelectionReason:   memory.latestSelection.reason,
			LastSelectionService:  memory.latestSelection.serviceID,
			ServiceMemories:       memory.services,
			Capabilities:          adapterCapabilities(profile),
			Paths:                 pathStatuses,
		})
	}
	status.StateEntries, status.StateEvictions = healthView.Stats()
	status.StatePersistenceFailures = p.statePersistenceFailures.Load()
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	// D3/C1: capabilityControllers map is the single status source.
	capabilityControllers := cloneCapabilityControllers(p.capabilityControllers)
	capabilityEnabled := p.capabilityProvider != nil
	capabilityProvider := p.capabilityProvider
	p.lifecycleAccess.Unlock()
	status.CapabilityEnabled = capabilityEnabled
	status.CapabilityInitFailures = p.capabilityInitFailures.Load()
	status.ExitIdentityBaselines, status.ExitIdentityChangesTotal, status.ExitIdentitySaturatedNodes = p.exitIdentityStore.Stats()
	status.ExitIdentityIPv4Baselines, status.ExitIdentityIPv6Baselines, status.ExitIdentityDualStackNodes = p.exitIdentityStore.FamilyStats()
	for _, serviceID := range sortedCapabilityControllerIDs(capabilityControllers) {
		capabilityStatus := capabilityControllers[serviceID].Status()
		status.CapabilityRunning = status.CapabilityRunning || capabilityStatus.Running
		status.CapabilityCyclesStarted += capabilityStatus.CyclesStarted
		status.CapabilityCyclesCompleted += capabilityStatus.CyclesCompleted
		status.CapabilityRefreshFailures += capabilityStatus.RefreshFailures
		status.CapabilityViewFailures += capabilityStatus.ViewFailures
		status.CapabilitySuiteFailures += capabilityStatus.SuiteFailures
		if capabilityStatus.LastFailureStage != "" {
			status.CapabilityLastFailureStage = serviceID + ":" + capabilityStatus.LastFailureStage
		}
	}
	if capabilityProvider != nil {
		if targetSnapshot, targetErr := capabilityProvider.Snapshot(context.Background(), youtubeProbeServiceID); targetErr == nil {
			status.CapabilityTargetGeneration = targetSnapshot.Generation
		}
	}
	if scheduler != nil {
		status.ProbeQueueDepth, _, _ = scheduler.Stats()
	}
	if p.schedulerOwner != nil {
		owner, generation, accepted, coalesced, deferred, rejected, completed, stalled := p.schedulerOwner.Stats()
		status.ProbeOwnerEpoch = uint64(owner)
		status.ProbeOwnerGeneration = generation
		status.ProbeAcceptedTotal = accepted
		status.ProbeCoalescedTotal = coalesced
		status.ProbeDeferredTotal = deferred
		status.ProbeRejectedTotal = rejected
		status.ProbeCompletedTotal = completed
		status.ProbeSchedulerStalledTotal = stalled
	}
	return status
}
