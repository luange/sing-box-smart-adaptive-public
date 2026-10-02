package adaptive

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/nodeweight"
	N "github.com/sagernet/sing/common/network"
)

var (
	ErrNoEligibleCandidates      = errors.New("adaptive pool has no eligible candidates")
	ErrStrictAffinityUnavailable = errors.New("adaptive strict-affinity lease is unavailable")
)

const (
	defaultSwitchMargin   = 0.15
	defaultSwitchCooldown = 2 * time.Minute
	earlySwitchWindow     = 20 * time.Second
	maxStickyEntries      = 4096
)

type DecisionReason string

const (
	ReasonManualPin       DecisionReason = "manual_pin"
	ReasonLease           DecisionReason = "session_lease"
	ReasonRanked          DecisionReason = "ranked_health"
	ReasonFallback        DecisionReason = "manual_pin_fallback"
	ReasonStrictNew       DecisionReason = "strict_affinity_new"
	ReasonBulkSpread      DecisionReason = "bulk_spread"
	ReasonBulkThroughput  DecisionReason = "bulk_throughput"
	ReasonWarmingFallback DecisionReason = "warming_fallback"
	ReasonStickyMargin    DecisionReason = "sticky_margin"
	ReasonSwitchCooldown  DecisionReason = "switch_cooldown"
)

type DecisionPlan struct {
	RuntimeEpochID  RuntimeEpochID
	CatalogRevision CatalogRevision
	Generation      uint64
	Mode            PolicyMode
	Reason          DecisionReason
	Candidates      []Candidate
	health          *HealthStore
	service         ServiceContext
	allowBlocked    bool
	// disableHedge turns off parallel hedge starts (used for warming/outage plans
	// so a fully-blocked pool does not storm every leaf outbound).
	disableHedge bool
}

func (p DecisionPlan) TryAcquireAttemptPermit(nodeID NodeID, at time.Time) (*AttemptPermit, bool) {
	if p.health == nil {
		return &AttemptPermit{}, true
	}
	var handle NodeHandle
	for _, candidate := range p.Candidates {
		if candidate.ID == nodeID {
			handle = candidate.Handle
			break
		}
	}
	if p.allowBlocked {
		return p.health.TryAcquireConnectionFallbackPermitHandle(handle, serviceHealthTransport(p.service), at)
	}
	return p.health.TryAcquireConnectionPermitHandle(handle, serviceHealthTransport(p.service), at)
}

type stickyPreference struct {
	handle    NodeHandle
	until     time.Time
	updatedAt time.Time
}

type PolicyEngine struct {
	health         *HealthStore
	kernel         policyKernel
	maxAttempts    int
	manualFailure  string
	bulkSequence   *atomic.Uint64
	nodeWeights    *nodeweight.Matcher
	switchMargin   float64
	switchCooldown time.Duration
	// affinityMode: ""/"service" = per-product sticky; "disabled" = no sticky.
	affinityMode string
	// kernelAccess serializes the portable kernel boundary.  The Zig kernel has
	// its own internal lock, while the pure-Go implementation does not; keeping
	// the lifecycle and decision calls behind one lock also prevents Close from
	// racing a Plan/Remember call and observing a nil or freed kernel.
	kernelAccess sync.Mutex
	stickyAccess sync.Mutex
	sticky       map[string]stickyPreference
}

func NewPolicyEngine(health *HealthStore, maxAttempts int, manualFailure string) *PolicyEngine {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if manualFailure == "" {
		manualFailure = "fallback"
	}
	return &PolicyEngine{
		health:         health,
		kernel:         newAdaptivePolicyKernel(),
		maxAttempts:    maxAttempts,
		manualFailure:  manualFailure,
		bulkSequence:   new(atomic.Uint64),
		switchMargin:   defaultSwitchMargin,
		switchCooldown: defaultSwitchCooldown,
		sticky:         make(map[string]stickyPreference),
	}
}

func (e *PolicyEngine) BindBulkSequence(sequence *atomic.Uint64) *PolicyEngine {
	if e != nil && sequence != nil {
		e.bulkSequence = sequence
	}
	return e
}

func (e *PolicyEngine) BindNodeWeights(weights *nodeweight.Matcher) *PolicyEngine {
	if e != nil {
		e.nodeWeights = weights
	}
	return e
}

// BindAffinityMode configures sticky spine behavior (A5).
// "service" (default) keys sticky by AffinityID/service; "disabled" turns sticky off.
func (e *PolicyEngine) BindAffinityMode(mode string) *PolicyEngine {
	if e == nil {
		return e
	}
	switch mode {
	case "", "service":
		e.affinityMode = "service"
	case "disabled":
		e.affinityMode = "disabled"
	default:
		e.affinityMode = "service"
	}
	return e
}

func (e *PolicyEngine) BindSwitchStability(margin float64, cooldown time.Duration) *PolicyEngine {
	if e == nil {
		return e
	}
	if margin < 0 {
		margin = defaultSwitchMargin
	}
	if margin > 0.5 {
		margin = 0.5
	}
	if cooldown < 0 {
		cooldown = 0
	}
	e.switchMargin = margin
	e.switchCooldown = cooldown
	e.kernelAccess.Lock()
	if e.kernel != nil {
		e.kernel.Configure(margin, cooldown, e.manualFailure)
	}
	e.kernelAccess.Unlock()
	return e
}

// importStickyFrom copies live sticky preferences into a status-time engine so
// operator scores share the same cooldown/margin memory as dial Plan.
func (e *PolicyEngine) importStickyFrom(src *PolicyEngine) {
	if e == nil || src == nil {
		return
	}
	src.stickyAccess.Lock()
	defer src.stickyAccess.Unlock()
	e.stickyAccess.Lock()
	defer e.stickyAccess.Unlock()
	if e.sticky == nil {
		e.sticky = make(map[string]stickyPreference, len(src.sticky))
	}
	for key, pref := range src.sticky {
		e.sticky[key] = pref
	}
}

// Clear drops sticky selection state. Called on pool retire/reload so process
// lifetime health conclusions and sticky maps cannot leak across epochs.
func (e *PolicyEngine) Clear() {
	if e == nil {
		return
	}
	e.stickyAccess.Lock()
	e.sticky = make(map[string]stickyPreference)
	e.stickyAccess.Unlock()
	e.kernelAccess.Lock()
	if e.kernel != nil {
		e.kernel.Reset()
	}
	e.kernelAccess.Unlock()
}

// Close releases the portable kernel contexts when the pool is permanently
// retired. Clear already drops them on an epoch retirement; this method makes
// the final lifecycle boundary explicit for hosts that own PolicyEngine.
func (e *PolicyEngine) Close() {
	if e == nil {
		return
	}
	e.kernelAccess.Lock()
	defer e.kernelAccess.Unlock()
	if e.kernel == nil {
		return
	}
	e.kernel.Close()
	e.kernel = nil
}

// RememberSelection records the live egress for a service affinity so later
// plans can apply delay hysteresis and a short switch cooldown.
func (e *PolicyEngine) RememberSelection(key string, handle NodeHandle, now time.Time) {
	if e == nil || key == "" || handle.NodeID == (NodeID{}) || e.affinityMode == "disabled" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.stickyAccess.Lock()
	if e.sticky == nil {
		e.sticky = make(map[string]stickyPreference)
	}
	previous, hadPrevious := e.sticky[key]
	until := previous.until
	if !hadPrevious || previous.handle != handle {
		if e.switchCooldown > 0 {
			until = now.Add(e.switchCooldown)
		} else {
			until = time.Time{}
		}
	}
	e.sticky[key] = stickyPreference{handle: handle, until: until, updatedAt: now}
	if len(e.sticky) > maxStickyEntries {
		e.pruneStickyLocked(now)
	}
	e.stickyAccess.Unlock()
	e.kernelAccess.Lock()
	if e.kernel != nil {
		e.kernel.Remember(key, handle.NodeID, now, e.switchCooldown)
	}
	e.kernelAccess.Unlock()
}

// ForgetSelectionAfterEarlyFailure removes a newly selected incumbent when a
// high-confidence real failure arrives shortly after the switch.
func (e *PolicyEngine) ForgetSelectionAfterEarlyFailure(service ServiceContext, handle NodeHandle, now time.Time) bool {
	if e == nil || handle.NodeID == (NodeID{}) {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := e.stickyKey(service)
	e.stickyAccess.Lock()
	pref, loaded := e.sticky[key]
	age := now.Sub(pref.updatedAt)
	if !loaded || pref.handle != handle || age < 0 || age > earlySwitchWindow {
		e.stickyAccess.Unlock()
		return false
	}
	delete(e.sticky, key)
	e.stickyAccess.Unlock()
	e.kernelAccess.Lock()
	if e.kernel != nil {
		e.kernel.Forget(key)
	}
	e.kernelAccess.Unlock()
	return true
}

func (e *PolicyEngine) stickyKey(service ServiceContext) string {
	if e != nil && e.affinityMode == "disabled" {
		return ""
	}
	base := service.ID
	if service.AffinityID != "" {
		base = service.AffinityID
	}
	if service.Session != (SessionKey{}) {
		return service.Session.String() + "\x00" + base
	}
	return base
}

func (e *PolicyEngine) stickyPreferred(key string, now time.Time) (stickyPreference, bool) {
	if e == nil || key == "" {
		return stickyPreference{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.stickyAccess.Lock()
	defer e.stickyAccess.Unlock()
	pref, loaded := e.sticky[key]
	if !loaded || pref.handle.NodeID == (NodeID{}) {
		return stickyPreference{}, false
	}
	// Keep the last known preference even after cooldown so delay margin can
	// still damp ranking noise; cooldown only strengthens stickiness.
	if !pref.until.IsZero() && now.After(pref.until.Add(24*time.Hour)) {
		delete(e.sticky, key)
		return stickyPreference{}, false
	}
	return pref, true
}

func (e *PolicyEngine) pruneStickyLocked(now time.Time) {
	for key, pref := range e.sticky {
		if pref.until.IsZero() && now.Sub(pref.updatedAt) > 24*time.Hour {
			delete(e.sticky, key)
			continue
		}
		if !pref.until.IsZero() && now.After(pref.until.Add(24*time.Hour)) {
			delete(e.sticky, key)
		}
	}
	for len(e.sticky) > maxStickyEntries {
		var oldestKey string
		var oldest time.Time
		for key, pref := range e.sticky {
			if oldestKey == "" || pref.updatedAt.Before(oldest) {
				oldestKey = key
				oldest = pref.updatedAt
			}
		}
		delete(e.sticky, oldestKey)
	}
}

func (e *PolicyEngine) Plan(snapshot *ExecutionSnapshot, service ServiceContext, lease *SessionLease, pinned *NodeID) (DecisionPlan, error) {
	if snapshot == nil {
		return DecisionPlan{}, ErrNoCandidates
	}
	eligible := make([]Candidate, 0, len(snapshot.Candidates))
	supported := make([]Candidate, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		if !candidateSupports(candidate, service.Transport) {
			continue
		}
		supported = append(supported, candidate)
		if e.candidateBlocked(candidate, service) {
			continue
		}
		eligible = append(eligible, candidate)
	}
	if pinned != nil {
		if candidate, loaded := snapshot.Candidate(*pinned); loaded && candidateSupports(candidate, service.Transport) {
			if !e.candidateBlocked(candidate, service) {
				return e.plan(snapshot, ModeManual, ReasonManualPin, service, []Candidate{candidate}), nil
			}
			if e.manualFailure == "fail_closed" {
				return DecisionPlan{}, ErrNoEligibleCandidates
			}
		} else if e.manualFailure == "fail_closed" {
			return DecisionPlan{}, ErrNoEligibleCandidates
		}
	}
	mode := service.Mode
	if mode == "" {
		mode = ModeAdaptive
	}
	if len(eligible) == 0 {
		if len(supported) > 0 && (mode == ModeAdaptive || mode == ModeLatency || mode == ModeBulk) {
			// Cold start / total outage: one sequential probe path only — hedge would
			// fan out concurrent dials against every broken node.
			plan := e.plan(snapshot, mode, ReasonWarmingFallback, service, limitCandidates(supported, 1))
			plan.allowBlocked = true
			plan.disableHedge = true
			return plan, nil
		}
		return DecisionPlan{}, ErrNoEligibleCandidates
	}
	if mode == ModeAdaptive && lease != nil {
		for index, candidate := range eligible {
			if candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
				moveCandidateFirst(eligible, index)
				return e.plan(snapshot, mode, ReasonLease, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
		}
	}
	kernelUsed := false
	kernelReason := ReasonRanked
	bulkSequence := uint64(0)
	if mode == ModeBulk {
		bulkSequence = e.bulkSequence.Add(1)
	}
	e.kernelAccess.Lock()
	if e.kernel != nil {
		if mode == ModeBulk {
			e.kernel.SetBulkSequence(e.stickyKey(service), bulkSequence)
		}
		kernelCandidates := make([]policyKernelCandidate, 0, len(eligible))
		for _, candidate := range eligible {
			score := e.candidateScore(candidate, service)
			sortKeyHi, sortKeyLo := kernelCandidateSortKey(candidate.ID)
			throughput := HealthStatus{}
			if service.ID != "" {
				throughput = e.health.StatusHandle(candidate.Handle, DomainService, "", service.ID)
			}
			kernelCandidates = append(kernelCandidates, policyKernelCandidate{
				ID: kernelCandidateID(candidate.ID), SortKeyHi: sortKeyHi, SortKeyLo: sortKeyLo, HealthPriority: score.HealthPriority,
				WeightedDelayMS: float64(score.WeightedDelay) / float64(time.Millisecond),
				ThroughputBPS:   throughput.ThroughputBPS, ThroughputSamples: float64(throughput.ThroughputSamples),
				Supported: true, Eligible: true,
				Pinned: pinned != nil && candidate.ID == *pinned,
				Leased: lease != nil && candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion,
			})
		}
		decision := e.kernel.Choose(e.stickyKey(service), kernelCandidates, mode, time.Now())
		if decision.SelectedID != 0 {
			for index, candidate := range eligible {
				if kernelCandidateID(candidate.ID) == decision.SelectedID {
					moveCandidateFirst(eligible, index)
					kernelUsed = true
					kernelReason = kernelDecisionReason(decision.Reason)
					break
				}
			}
		}
	}
	e.kernelAccess.Unlock()
	sortStart := 0
	if kernelUsed {
		sortStart = 1
	}
	sort.SliceStable(eligible[sortStart:], func(i, j int) bool {
		i += sortStart
		j += sortStart
		leftScore := e.candidateScore(eligible[i], service)
		rightScore := e.candidateScore(eligible[j], service)
		if leftScore.HealthPriority != rightScore.HealthPriority {
			return leftScore.HealthPriority < rightScore.HealthPriority
		}
		if mode == ModeBulk {
			leftService := e.health.StatusHandle(eligible[i].Handle, DomainService, "", service.ID)
			rightService := e.health.StatusHandle(eligible[j].Handle, DomainService, "", service.ID)
			leftKnown, rightKnown := leftService.ThroughputSamples >= 2, rightService.ThroughputSamples >= 2
			if leftKnown != rightKnown {
				return leftKnown
			}
			if leftKnown && leftService.ThroughputBPS != rightService.ThroughputBPS {
				return leftService.ThroughputBPS > rightService.ThroughputBPS
			}
		}
		if leftScore.WeightedDelay != rightScore.WeightedDelay {
			return leftScore.WeightedDelay < rightScore.WeightedDelay
		}
		return bytes.Compare(eligible[i].ID[:], eligible[j].ID[:]) < 0
	})
	reason := kernelReason
	if pinned != nil {
		reason = ReasonFallback
	}
	// Sticky margin/cooldown apply to adaptive browsing AND to strict identity
	// replacement after a lease breaks. Without this, AI/account hosts (default
	// strict-affinity) thrash egress on every recovery dial.
	if !kernelUsed && (mode == ModeAdaptive || mode == ModeStrictAffinity) {
		if stickyReason, ok := e.applyStickyStability(eligible, service, time.Now()); ok {
			reason = stickyReason
		}
	}
	if mode == ModeStrictAffinity && lease != nil {
		for index, candidate := range eligible {
			if candidate.ID == lease.NodeID && candidate.Handle.Slot == lease.NodeSlot && candidate.Handle.Version == lease.NodeVersion {
				// Healthy lease: single candidate, no hedge. Identity stays put
				// until the breaker excludes this handle.
				return e.plan(snapshot, mode, ReasonLease, service, []Candidate{eligible[index]}), nil
			}
		}
		// Lease handle is gone from eligible. Prefer sticky stability (above) so
		// the next identity is not pure rank thrash; DialContext commits only
		// after a candidate actually connects.
	}
	switch mode {
	case ModeStrictAffinity:
		if reason == ReasonRanked {
			reason = ReasonStrictNew
		}
		return e.plan(snapshot, mode, reason, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeBulk:
		sequence := bulkSequence
		if kernelUsed {
			if kernelReason == ReasonBulkThroughput || kernelReason == ReasonBulkSpread {
				return e.plan(snapshot, mode, kernelReason, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
			return e.plan(snapshot, mode, ReasonBulkSpread, service, limitCandidates(eligible, e.maxAttempts)), nil
		}
		if hasTrustedBulkThroughput(e.health, eligible, service.ID) {
			if sequence%5 != 0 {
				return e.plan(snapshot, mode, ReasonBulkThroughput, service, limitCandidates(eligible, e.maxAttempts)), nil
			}
			eligible = rotateCandidates(eligible, int(sequence/5))
			return e.plan(snapshot, mode, ReasonBulkSpread, service, limitCandidates(eligible, e.maxAttempts)), nil
		}
		if !kernelUsed {
			eligible = rotateCandidates(eligible, int(sequence-1))
		}
		return e.plan(snapshot, mode, ReasonBulkSpread, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeAdaptive:
		return e.plan(snapshot, mode, reason, service, limitCandidates(eligible, e.maxAttempts)), nil
	case ModeLatency:
		return e.plan(snapshot, mode, reason, service, limitCandidates(eligible, e.maxAttempts)), nil
	default:
		return DecisionPlan{}, errors.New("adaptive policy mode is invalid")
	}
}

func (e *PolicyEngine) applyStickyStability(eligible []Candidate, service ServiceContext, now time.Time) (DecisionReason, bool) {
	pref, loaded := e.stickyPreferred(e.stickyKey(service), now)
	if !loaded {
		return "", false
	}
	incumbentIndex := -1
	for index, candidate := range eligible {
		if candidate.Handle == pref.handle || candidate.ID == pref.handle.NodeID && candidate.Handle.Slot == pref.handle.Slot && candidate.Handle.Version == pref.handle.Version {
			incumbentIndex = index
			break
		}
	}
	if incumbentIndex <= 0 {
		return "", false
	}
	challenger := eligible[0]
	incumbent := eligible[incumbentIndex]
	challengerScore := e.candidateScore(challenger, service)
	incumbentScore := e.candidateScore(incumbent, service)
	// A clearly healthier challenger always wins.
	if challengerScore.HealthPriority < incumbentScore.HealthPriority {
		return "", false
	}
	inCooldown := e.switchCooldown > 0 && !pref.until.IsZero() && !now.After(pref.until)
	if inCooldown {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonSwitchCooldown, true
	}
	if challengerScore.HealthPriority > incumbentScore.HealthPriority {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonStickyMargin, true
	}
	if !significantlyFaster(challengerScore.WeightedDelay, incumbentScore.WeightedDelay, e.switchMargin) {
		moveCandidateFirst(eligible, incumbentIndex)
		return ReasonStickyMargin, true
	}
	return "", false
}

func significantlyFaster(challenger, incumbent time.Duration, margin float64) bool {
	if incumbent <= 0 {
		return true
	}
	if challenger <= 0 {
		return false
	}
	if margin <= 0 {
		return challenger < incumbent
	}
	return float64(challenger) <= float64(incumbent)*(1-margin)
}

func weightedDelay(delay time.Duration, weight float64) time.Duration {
	if weight <= 0 {
		weight = nodeweight.Default
	}
	return time.Duration(float64(delay) / weight)
}

func modeUsesLease(mode PolicyMode) bool {
	return mode != ModeBulk && mode != ModeLatency
}

// candidatePriority combines generic endpoint health with transport- and
// service-specific evidence. A node that passes a generic URL test but fails a
// real TCP/UDP connection is therefore ranked below a proven working node.
func (e *PolicyEngine) candidatePriority(candidate Candidate, service ServiceContext) (int, time.Duration) {
	score := e.candidateScore(candidate, service)
	return score.HealthPriority, score.ObservedDelay
}

type CandidateScoreExplanation struct {
	HealthPriority   int
	ObservedDelay    time.Duration
	SmoothedDelay    time.Duration
	WeightedDelay    time.Duration
	SelectionScore   uint64
	DominantEvidence string
	ManualWeight     float64
}

func (e *PolicyEngine) candidateScore(candidate Candidate, service ServiceContext) CandidateScoreExplanation {
	endpoint := e.health.EndpointHandle(candidate.Handle)
	transportName, transport := e.transportScoreStatus(candidate.Handle, service)
	var serviceStatus HealthStatus
	if service.ID != "" {
		serviceStatus = e.health.StatusHandle(candidate.Handle, DomainService, "", service.ID)
	}

	// Health priority: worst across domains (conservative).
	priority := healthPriority(endpoint.Health)
	dominant := "endpoint"
	if current := healthPriority(transport.Health); current > priority {
		priority = current
		dominant = transportName
	}
	if service.ID != "" {
		if current := healthPriority(serviceStatus.Health); current > priority {
			priority = current
			dominant = "service:" + service.ID
		}
	}

	// Delay: dual-stack best usable family first, then worsen with endpoint/service.
	// DominantEvidence stays health-priority based (not rewritten by delay).
	delay := transport.RankingDelay()
	smoothed := transport.SmoothedDelay
	worsenDelay := func(status HealthStatus) {
		if r := status.RankingDelay(); r > 0 && (delay == 0 || r > delay) {
			delay = r
		}
		if status.SmoothedDelay > 0 && (smoothed == 0 || status.SmoothedDelay > smoothed) {
			smoothed = status.SmoothedDelay
		}
	}
	worsenDelay(endpoint)
	if service.ID != "" {
		worsenDelay(serviceStatus)
	}
	if delay == 0 {
		delay = 10 * time.Second
	}
	if smoothed == 0 {
		smoothed = delay
	}
	weight := nodeweight.Default
	if e != nil && e.nodeWeights != nil {
		weight = e.nodeWeights.Weight(candidate.PrimaryTag)
	}
	weighted := weightedDelay(smoothed, weight)
	// Deprioritize provider replica tags ("… (2)") and endpoint-conflict
	// secondaries so a healthy primary wins ties without waiting for the
	// replica's TLS blackhole to exhaust retries.
	if isProviderReplicaCandidate(candidate) {
		weighted += 8 * time.Second
	} else if candidate.EndpointConflictCount > 1 {
		weighted += 2 * time.Second
	}
	score := uint64(priority) * 1_000_000_000_000
	if weighted > 0 {
		score += uint64(weighted.Microseconds())
	}
	return CandidateScoreExplanation{
		HealthPriority:   priority,
		ObservedDelay:    delay,
		SmoothedDelay:    smoothed,
		WeightedDelay:    weighted,
		SelectionScore:   score,
		DominantEvidence: dominant,
		ManualWeight:     weight,
	}
}

// transportScoreStatus picks the transport ledger used for ranking delay.
//
// A3: rank against the dial family when the service already carries a concrete
// family (tcp/ipv4, udp_dns/ipv6, …). Dual-stack aggregates (*/any) use the
// best usable family delay so a dead peer family cannot poison ranking.
func (e *PolicyEngine) transportScoreStatus(handle NodeHandle, service ServiceContext) (string, HealthStatus) {
	path := serviceHealthTransport(service)
	if e == nil || e.health == nil {
		if normalized := normalizeHealthTransportPath(path); normalized != "" {
			return normalized, HealthStatus{Health: HealthUnknown, Breaker: BreakerClosed}
		}
		return path, HealthStatus{Health: HealthUnknown, Breaker: BreakerClosed}
	}
	normalized := normalizeHealthTransportPath(path)
	if normalized == "" {
		normalized = path
	}
	familyA, familyB, isDual := dualStackFamilyPaths(normalized)
	if !isDual {
		// Concrete dial family (or bare class already normalized): single ledger.
		return normalized, e.health.StatusHandle(handle, DomainTransport, normalized, "")
	}
	a := e.health.StatusHandle(handle, DomainTransport, familyA, "")
	b := e.health.StatusHandle(handle, DomainTransport, familyB, "")
	aOK := familyUsableForScore(a)
	bOK := familyUsableForScore(b)
	// When neither family has samples, rank from the aggregate ledger
	// (tcp/any etc.) so bare-class or */any observations are not invisible.
	agg := e.health.StatusHandle(handle, DomainTransport, normalized, "")
	switch {
	case aOK && bOK:
		if !familyHasEvidence(a) && !familyHasEvidence(b) && familyHasEvidence(agg) {
			return normalized, agg
		}
		if preferStatusDelay(a, b) {
			return familyA, a
		}
		return familyB, b
	case aOK:
		if !familyHasEvidence(a) && familyHasEvidence(agg) {
			return normalized, agg
		}
		return familyA, a
	case bOK:
		if !familyHasEvidence(b) && familyHasEvidence(agg) {
			return normalized, agg
		}
		return familyB, b
	default:
		return normalized, agg
	}
}

func familyHasEvidence(status HealthStatus) bool {
	return status.Successes > 0 || status.Failures > 0 || status.NonBreakerSuccesses > 0 || status.NonBreakerFailures > 0 ||
		status.DelaySamples > 0 || status.Health == HealthDegraded || status.Health == HealthUnreachable ||
		(status.Breaker != BreakerClosed && status.Breaker != "")
}

func familyUsableForScore(status HealthStatus) bool {
	if status.Breaker == BreakerOpen || status.Breaker == BreakerCooldown {
		return false
	}
	return status.Health != HealthUnreachable
}

func preferStatusDelay(left, right HealthStatus) bool {
	ld, rd := left.RankingDelay(), right.RankingDelay()
	if ld == 0 {
		return false
	}
	if rd == 0 {
		return true
	}
	return ld <= rd
}

func hasTrustedBulkThroughput(health *HealthStore, candidates []Candidate, serviceID string) bool {
	if health == nil {
		return false
	}
	for _, candidate := range candidates {
		if health.StatusHandle(candidate.Handle, DomainService, "", serviceID).ThroughputSamples >= 2 {
			return true
		}
	}
	return false
}

func (e *PolicyEngine) plan(snapshot *ExecutionSnapshot, mode PolicyMode, reason DecisionReason, service ServiceContext, candidates []Candidate) DecisionPlan {
	return DecisionPlan{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, Generation: snapshot.Generation, Mode: mode, Reason: reason, Candidates: candidates, health: e.health, service: service}
}

func (e *PolicyEngine) candidateBlocked(candidate Candidate, service ServiceContext) bool {
	if e == nil || e.health == nil {
		return false
	}
	// Single read-only gate: endpoint + service breakers + dual-stack transport
	// eligibility (transportPathEligible). Do not also BuildCapabilityProfile here —
	// that duplicated the same decision with more work and no extra user-facing
	// outcome. Status/Explain still use RequiredPathKnownBlocked / SupportsService.
	return !e.health.CanAttemptHandleReadOnly(candidate.Handle, service, time.Time{})
}

// ExclusionReason explains why a candidate is out of the plan for a service.
func (e *PolicyEngine) ExclusionReason(candidate Candidate, service ServiceContext) string {
	reasons := e.ExclusionReasons(candidate, service)
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0]
}

// ExclusionReasons returns all stable exclusion labels for status views.
// service may be empty to summarize every known path without inventing a fake default.
func (e *PolicyEngine) ExclusionReasons(candidate Candidate, service ServiceContext) []string {
	if e == nil || e.health == nil {
		return nil
	}
	if service.Transport != "" || service.HealthTransport != "" || service.ID != "" {
		if reason := e.health.ExplainExclusion(candidate.Handle, service, time.Time{}); reason != "" {
			return []string{reason}
		}
		profile := e.health.BuildCapabilityProfile(candidate.Handle, time.Time{})
		if ok, reason := profile.SupportsService(service); !ok && reason != "" {
			return []string{reason}
		}
		return nil
	}
	return e.health.ExplainAllPathExclusions(candidate.Handle, time.Time{})
}

func candidateSupports(candidate Candidate, transport string) bool {
	for _, network := range candidate.Transport {
		if N.NetworkName(network) == N.NetworkName(transport) {
			return true
		}
	}
	return false
}

func healthPriority(state HealthState) int {
	switch state {
	case HealthHealthy:
		return 0
	case HealthUnknown:
		return 1
	case HealthDegraded:
		return 2
	case HealthUnreachable:
		return 4
	default:
		return 3
	}
}

func moveCandidateFirst(candidates []Candidate, index int) {
	if index <= 0 || index >= len(candidates) {
		return
	}
	candidate := candidates[index]
	copy(candidates[1:index+1], candidates[:index])
	candidates[0] = candidate
}

func limitCandidates(candidates []Candidate, limit int) []Candidate {
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func rotateCandidates(candidates []Candidate, offset int) []Candidate {
	if len(candidates) < 2 {
		return candidates
	}
	offset %= len(candidates)
	if offset == 0 {
		return candidates
	}
	rotated := make([]Candidate, 0, len(candidates))
	rotated = append(rotated, candidates[offset:]...)
	rotated = append(rotated, candidates[:offset]...)
	return rotated
}
