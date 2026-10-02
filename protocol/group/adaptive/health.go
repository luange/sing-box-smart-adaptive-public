package adaptive

import (
	"container/list"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const healthDelayRingSize = 10

// FailureDomain is deliberately independent from the observation source. A
// later observation contract can map dial, TLS, HTTP and UDP evidence into
// these domains without changing breaker state management.
type FailureDomain string

const (
	DomainEndpoint  FailureDomain = "endpoint"
	DomainTransport FailureDomain = "transport"
	DomainService   FailureDomain = "service"
)

// ObservationScope is retained as a source-compatible name for existing
// callers; new code should use FailureDomain/Domain*.
type ObservationScope = FailureDomain

const (
	ScopeEndpoint  = DomainEndpoint
	ScopeTransport = DomainTransport
	ScopeService   = DomainService
)

type ObservationOutcome string

const (
	OutcomeSuccess  ObservationOutcome = "success"
	OutcomeFailure  ObservationOutcome = "failure"
	OutcomeBlocked  ObservationOutcome = "blocked"
	OutcomeDeferred ObservationOutcome = "deferred"
)

type BreakerState string

const (
	BreakerUnknown  BreakerState = "unknown"
	BreakerClosed   BreakerState = "closed"
	BreakerOpen     BreakerState = "open"
	BreakerCooldown BreakerState = "cooldown"
	BreakerHalfOpen BreakerState = "half_open"
)

type HealthState string

const (
	HealthUnknown     HealthState = "unknown"
	HealthHealthy     HealthState = "healthy"
	HealthDegraded    HealthState = "degraded"
	HealthUnreachable HealthState = "unreachable"
)

type Observation struct {
	NodeID        NodeID
	NodeSlot      uint64
	NodeVersion   uint64
	Scope         FailureDomain
	Transport     string
	Service       string
	Outcome       ObservationOutcome
	Delay         time.Duration
	ThroughputBPS float64
	At            time.Time
	Reason        string
}

type HealthStatus struct {
	Health              HealthState
	Breaker             BreakerState
	LastUpdated         time.Time
	LastDelay           time.Duration
	SmoothedDelay       time.Duration
	DelaySamples        int
	ThroughputBPS       float64
	ThroughputSamples   uint64
	Successes           uint64
	Failures            uint64
	NonBreakerSuccesses uint64
	NonBreakerFailures  uint64
	EvidenceWeight      float64
	ConsecutiveFailures int
	RecoverySuccesses   int
	CooldownUntil       time.Time
	Backoff             time.Duration
	HalfOpen            bool
	Reason              string
}

type ThroughputSummary struct {
	BPS       float64
	Samples   uint64
	UpdatedAt time.Time
}

type healthKey struct {
	nodeID      NodeID
	nodeSlot    uint64
	nodeVersion uint64
	domain      FailureDomain
	transport   string
	service     string
}

type healthRecord struct {
	key                healthKey
	status             HealthStatus
	consecutiveFailure int
	reopenCount        int
	recoverySuccesses  int
	openUntil          time.Time
	halfOpenToken      uint64
	version            uint64
	delaySamples       [healthDelayRingSize]time.Duration
	delayCount         int
	delayNext          int
	element            *list.Element
}

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Now is the store clock. Observation timestamps should use this so prune,
// breaker windows, and evidence.At stay on one timeline.
func (s *HealthStore) Now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now()
	}
	return s.clock.Now()
}

type BreakerConfig struct {
	FailureThreshold int
	BaseCooldown     time.Duration
	MaxCooldown      time.Duration
	// JitterFraction adds symmetric random jitter to open-breaker backoff
	// (for example 0.2 => ±20%). Zero disables jitter for deterministic tests.
	JitterFraction float64
	// JitterRandom is injectable for deterministic fault tests. It must return
	// a value in [0,1); nil uses the process-safe default source.
	JitterRandom func() float64
}

func defaultBreakerConfig() BreakerConfig {
	return BreakerConfig{FailureThreshold: 3, BaseCooldown: 5 * time.Second, MaxCooldown: 5 * time.Minute, JitterFraction: 0.2, JitterRandom: rand.Float64}
}

// AttemptPermit owns only half-open tokens actually acquired by an attempt.
// Closed breakers do not need a token. CompleteDomains is idempotent and must
// be called exactly once by the attempt owner; ReleaseDeferred is for
// cancellation before an outcome exists and never increments failure counters.
type AttemptPermit struct {
	store     *HealthStore
	entries   []permitEntry
	completed atomic.Bool
}

type permitEntry struct {
	key           healthKey
	version       uint64
	halfOpenToken uint64
}

func (p *AttemptPermit) CompleteDomains(outcomes map[FailureDomain]ObservationOutcome, at time.Time, delay time.Duration, reason string) {
	if p == nil || p.store == nil || !p.completed.CompareAndSwap(false, true) {
		return
	}
	p.store.completePermitDomains(p.entries, outcomes, at, delay, reason)
}

func (p *AttemptPermit) ReleaseDeferred() {
	if p == nil || p.store == nil || !p.completed.CompareAndSwap(false, true) {
		return
	}
	p.store.releasePermit(p.entries)
}

type HealthStore struct {
	access     sync.RWMutex
	entries    map[healthKey]*healthRecord
	lru        list.List
	retention  time.Duration
	maxEntries int
	evictions  uint64
	clock      Clock
	breaker    BreakerConfig
	nextToken  uint64
}

func NewHealthStore(retention time.Duration, maxEntries int) *HealthStore {
	return NewHealthStoreWithClock(retention, maxEntries, realClock{}, defaultBreakerConfig())
}

func NewHealthStoreWithClock(retention time.Duration, maxEntries int, clock Clock, breaker BreakerConfig) *HealthStore {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	if clock == nil {
		clock = realClock{}
	}
	defaults := defaultBreakerConfig()
	if breaker.FailureThreshold <= 0 {
		breaker.FailureThreshold = defaults.FailureThreshold
	}
	if breaker.BaseCooldown <= 0 {
		breaker.BaseCooldown = defaults.BaseCooldown
	}
	if breaker.MaxCooldown < breaker.BaseCooldown {
		breaker.MaxCooldown = defaults.MaxCooldown
	}
	if breaker.JitterFraction < 0 {
		breaker.JitterFraction = defaults.JitterFraction
	}
	if breaker.JitterFraction > 0.5 {
		breaker.JitterFraction = 0.5
	}
	if breaker.JitterRandom == nil {
		breaker.JitterRandom = defaults.JitterRandom
	}
	return &HealthStore{entries: make(map[healthKey]*healthRecord), retention: retention, maxEntries: maxEntries, clock: clock, breaker: breaker}
}

func recordHealthDelay(record *healthRecord, delay time.Duration) {
	if record == nil || delay <= 0 {
		return
	}
	record.delaySamples[record.delayNext] = delay
	record.delayNext = (record.delayNext + 1) % healthDelayRingSize
	if record.delayCount < healthDelayRingSize {
		record.delayCount++
	}
	record.status.LastDelay = delay
	record.status.DelaySamples = record.delayCount
	record.status.SmoothedDelay = medianHealthDelay(record.delaySamples[:record.delayCount])
}

func medianHealthDelay(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	mid := len(ordered) / 2
	if len(ordered)%2 == 1 {
		return ordered[mid]
	}
	return (ordered[mid-1] + ordered[mid]) / 2
}

// RankingDelay prefers the recent median when available so a single noisy
// sample cannot reshuffle healthy candidates.
func (s HealthStatus) RankingDelay() time.Duration {
	if s.SmoothedDelay > 0 {
		return s.SmoothedDelay
	}
	return s.LastDelay
}

func (s *HealthStore) Observe(observation Observation) {
	s.ObserveEvidence(observation, true, 1)
}

func (s *HealthStore) ThroughputByHandle() map[NodeHandle]ThroughputSummary {
	s.access.RLock()
	defer s.access.RUnlock()
	type aggregate struct {
		weightedLog float64
		samples     uint64
		updatedAt   time.Time
	}
	aggregates := make(map[NodeHandle]aggregate)
	for _, record := range s.entries {
		if record.key.domain != DomainService || record.status.ThroughputSamples == 0 || record.status.ThroughputBPS <= 0 {
			continue
		}
		handle := NodeHandle{NodeID: record.key.nodeID, Slot: record.key.nodeSlot, Version: record.key.nodeVersion}
		current := aggregates[handle]
		current.weightedLog += math.Log1p(record.status.ThroughputBPS) * float64(record.status.ThroughputSamples)
		current.samples += record.status.ThroughputSamples
		if record.status.LastUpdated.After(current.updatedAt) {
			current.updatedAt = record.status.LastUpdated
		}
		aggregates[handle] = current
	}
	result := make(map[NodeHandle]ThroughputSummary, len(aggregates))
	for handle, aggregate := range aggregates {
		result[handle] = ThroughputSummary{BPS: math.Expm1(aggregate.weightedLog / float64(aggregate.samples)), Samples: aggregate.samples, UpdatedAt: aggregate.updatedAt}
	}
	return result
}

// ReadOnlySnapshot captures one internally consistent health view for status
// rendering. The clone has no live half-open ownership and is never used to
// mutate routing state.
func (s *HealthStore) ReadOnlySnapshot() *HealthStore {
	if s == nil {
		return NewHealthStore(time.Hour, 1)
	}
	s.access.RLock()
	defer s.access.RUnlock()
	clone := &HealthStore{
		entries: make(map[healthKey]*healthRecord, len(s.entries)), retention: s.retention,
		maxEntries: s.maxEntries, clock: s.clock, breaker: s.breaker,
	}
	for key, record := range s.entries {
		copied := *record
		copied.element = clone.lru.PushFront(&copied)
		clone.entries[key] = &copied
	}
	clone.evictions = s.evictions
	return clone
}

func (s *HealthStore) ObserveEvidence(observation Observation, breakerEligible bool, weight float64) {
	if observation.Outcome == OutcomeDeferred {
		return
	}
	if observation.At.IsZero() {
		observation.At = s.clock.Now()
	}
	// Always write the same qualified transport vocabulary as Status/permit.
	if observation.Scope == DomainTransport {
		if normalized := normalizeHealthTransportPath(observation.Transport); normalized != "" {
			observation.Transport = normalized
		}
	}
	s.access.Lock()
	key := healthKey{nodeID: observation.NodeID, nodeSlot: observation.NodeSlot, nodeVersion: observation.NodeVersion, domain: observation.Scope, transport: observation.Transport, service: observation.Service}
	if breakerEligible {
		s.observeLocked(key, observation.Outcome, observation.At, observation.Delay, observation.Reason, 0, 0, false)
	} else {
		s.observeQualityLocked(key, observation, weight)
	}
	s.access.Unlock()
}

func (s *HealthStore) observeQualityLocked(key healthKey, observation Observation, weight float64) {
	s.pruneExpiredLocked(observation.At)
	record := s.entries[key]
	if record != nil && !record.status.LastUpdated.IsZero() && observation.At.Before(record.status.LastUpdated) {
		return
	}
	if record == nil {
		record = &healthRecord{key: key}
		record.status.Breaker = BreakerClosed
		record.element = s.lru.PushFront(record)
		s.entries[key] = record
	} else {
		s.lru.MoveToFront(record.element)
	}
	if weight < 0 {
		weight = 0
	}
	record.status.LastUpdated = observation.At
	record.status.Reason = observation.Reason
	record.status.EvidenceWeight += weight
	if observation.Outcome == OutcomeSuccess && observation.Delay > 0 {
		recordHealthDelay(record, observation.Delay)
	}
	if observation.ThroughputBPS > 0 && !math.IsNaN(observation.ThroughputBPS) && !math.IsInf(observation.ThroughputBPS, 0) {
		logValue := math.Log1p(observation.ThroughputBPS)
		if record.status.ThroughputSamples == 0 || record.status.ThroughputBPS <= 0 {
			record.status.ThroughputBPS = observation.ThroughputBPS
		} else {
			window := min(float64(record.status.ThroughputSamples+1), 8)
			current := math.Log1p(record.status.ThroughputBPS)
			record.status.ThroughputBPS = math.Expm1(current + (logValue-current)/window)
		}
		record.status.ThroughputSamples++
	}
	// Low-weight quality (ConfidenceLow ≈ 0.25) is metrics-only: delay/counters
	// for permit-busy learning and soft probes — never flip Health enum.
	// Medium+ quality failures degrade, then mark unreachable at breaker
	// threshold so pure-timeout blackholes leave the plan without a hard errno.
	metricsOnly := weight > 0 && weight < 0.5
	if observation.Outcome == OutcomeSuccess {
		record.status.NonBreakerSuccesses++
		if !metricsOnly && record.status.Breaker == BreakerClosed {
			// Medium+ success clears a quality blackhole. Without this, timeout
			// Unreachable could never recover except via a high-conf breaker path.
			record.status.NonBreakerFailures = 0
			record.status.Health = HealthHealthy
		}
	} else {
		record.status.NonBreakerFailures++
		if !metricsOnly && record.status.Breaker == BreakerClosed {
			threshold := s.breaker.FailureThreshold
			if threshold <= 0 {
				threshold = 3
			}
			if int(record.status.NonBreakerFailures) >= threshold {
				record.status.Health = HealthUnreachable
			} else if record.status.Health != HealthUnreachable {
				record.status.Health = HealthDegraded
			}
		}
	}
	for len(s.entries) > s.maxEntries {
		s.removeOldestLocked()
	}
}

// transportLedgerKey normalizes DomainTransport keys so permit/status/observe agree.
func transportLedgerKey(transport string) string {
	if normalized := normalizeHealthTransportPath(transport); normalized != "" {
		return normalized
	}
	return transport
}

// mostRestrictiveTransportRecordLocked maps aggregate keys (tcp/any, bare class
// after normalize) onto an existing concrete family ledger when one is already
// open/half-open/cooldown. Prevents parallel any-key permits that bypass a
// family breaker.
func (s *HealthStore) mostRestrictiveTransportRecordLocked(handle NodeHandle, transport string) (*healthRecord, healthKey, bool) {
	if s == nil {
		return nil, healthKey{}, false
	}
	class, family := splitHealthTransport(transport)
	if class == "" {
		return nil, healthKey{}, false
	}
	prefix := class + "/"
	if family != "" && family != healthFamilyAny {
		// Concrete family already — nothing further to pin.
		return nil, healthKey{}, false
	}
	var (
		selected    *healthRecord
		selectedKey healthKey
	)
	for entryKey, candidate := range s.entries {
		if entryKey.nodeID != handle.NodeID || entryKey.nodeSlot != handle.Slot || entryKey.nodeVersion != handle.Version || entryKey.domain != DomainTransport {
			continue
		}
		if !strings.HasPrefix(entryKey.transport, prefix) {
			continue
		}
		if selected == nil || healthTransportStatusRank(candidate.status) > healthTransportStatusRank(selected.status) ||
			(healthTransportStatusRank(candidate.status) == healthTransportStatusRank(selected.status) && candidate.status.LastUpdated.After(selected.status.LastUpdated)) {
			selected = candidate
			selectedKey = entryKey
		}
	}
	if selected == nil || healthTransportStatusRank(selected.status) == 0 {
		return nil, healthKey{}, false
	}
	return selected, selectedKey, true
}

// healthTransportStatusRank is shared by aggregate transport eligibility and
// status rendering.  BreakerState is a string for API compatibility, so its
// lexical order must never be used as a health severity ordering.
func healthTransportStatusRank(status HealthStatus) int {
	switch status.Breaker {
	case BreakerHalfOpen:
		return 4
	case BreakerOpen:
		return 3
	case BreakerCooldown:
		return 2
	default:
		if status.Health == HealthUnreachable {
			return 1
		}
		return 0
	}
}

// TryAcquireAttemptPermit atomically acquires all required domains. The order
// is fixed so concurrent attempts cannot deadlock or partially reserve a node.
func (s *HealthStore) TryAcquireAttemptPermit(nodeID NodeID, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireAttemptPermitVersion(nodeID, 0, service, at)
}

func (s *HealthStore) TryAcquireAttemptPermitVersion(nodeID NodeID, nodeVersion uint64, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireAttemptPermitHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, service, at)
}

func (s *HealthStore) TryAcquireAttemptPermitHandle(handle NodeHandle, service ServiceContext, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	path := serviceHealthTransport(service)
	if !s.transportPathEligible(handle, path, at) {
		return nil, false
	}
	keys := s.permitKeysForDial(handle, path, service.ID, true)
	return s.tryAcquirePermit(keys, at)
}

// TryAcquireConnectionPermitHandle deliberately excludes the service domain.
// A service half-open token is acquired only after the first payload exists.
func (s *HealthStore) TryAcquireConnectionPermitHandle(handle NodeHandle, transport string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	if !s.transportPathEligible(handle, transport, at) {
		return nil, false
	}
	keys := s.permitKeysForDial(handle, transport, "", false)
	return s.tryAcquirePermit(keys, at)
}

// permitKeysForDial builds endpoint/transport(/service) keys for half-open ownership.
// For dual-stack aggregates: if the collapsed */any key is already blocked but a
// concrete family is still available, pin the permit to that family — otherwise
// eligibility would pass and acquisition would still bounce on the any-key.
// No family preference when both families are unknown (keep the aggregate key).
func (s *HealthStore) permitKeysForDial(handle NodeHandle, transport, serviceID string, includeService bool) []healthKey {
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}}
	transportKey := transportLedgerKey(transport)
	if familyA, familyB, isDual := dualStackFamilyPaths(transportKey); isDual && s != nil {
		now := s.clock.Now()
		agg := s.pathCapability(handle, transport, now)
		if agg.Known && !agg.Available {
			a := s.pathCapability(handle, familyA, now)
			b := s.pathCapability(handle, familyB, now)
			switch {
			case a.Known && a.Available:
				transportKey = familyA
			case b.Known && b.Available:
				transportKey = familyB
			}
		}
	}
	if transportKey != "" {
		keys = append(keys, healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: transportKey})
	}
	if includeService {
		keys = append(keys, healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainService, service: serviceID})
	}
	return keys
}

// TryAcquireConnectionFallbackPermitHandle permits one bounded last-resort
// attempt when policy has no normally eligible candidate. It preserves the
// captured record versions so a successful attempt can close an open breaker,
// but never competes with an existing half-open owner.
// Dual-stack family blocks are intentionally not re-checked here: fallback is
// last-resort and may probe a node the normal plan already filtered out.
func (s *HealthStore) TryAcquireConnectionFallbackPermitHandle(handle NodeHandle, transport string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	transport = transportLedgerKey(transport)
	keys := []healthKey{{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint}, {nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainTransport, transport: transport}}
	s.access.Lock()
	defer s.access.Unlock()
	entries := make([]permitEntry, 0, len(keys))
	for _, key := range keys {
		record := s.entries[key]
		if record == nil {
			entries = append(entries, permitEntry{key: key})
			continue
		}
		if record.status.Breaker == BreakerHalfOpen {
			return nil, false
		}
		entries = append(entries, permitEntry{key: key, version: record.version})
	}
	return &AttemptPermit{store: s, entries: entries}, true
}

func (s *HealthStore) tryAcquirePermit(keys []healthKey, at time.Time) (*AttemptPermit, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	entries := make([]permitEntry, 0, len(keys))
	for _, key := range keys {
		record, resolvedKey := s.recordForKeyLocked(key)
		key = resolvedKey
		if record == nil {
			entries = append(entries, permitEntry{key: key})
			continue
		}
		if !s.availableLocked(record, at) {
			for _, entry := range entries {
				s.releaseTokenLocked(entry)
			}
			return nil, false
		}
		if record.status.Breaker == BreakerOpen || record.status.Breaker == BreakerCooldown || record.status.Breaker == BreakerHalfOpen {
			record.status.Breaker = BreakerHalfOpen
			record.status.HalfOpen = true
			s.nextToken++
			record.halfOpenToken = s.nextToken
			entries = append(entries, permitEntry{key: key, version: record.version, halfOpenToken: record.halfOpenToken})
		} else {
			entries = append(entries, permitEntry{key: key, version: record.version})
		}
	}
	return &AttemptPermit{store: s, entries: entries}, true
}

func (s *HealthStore) TryAcquireDomainPermit(nodeID NodeID, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireDomainPermitVersion(nodeID, 0, domain, transport, service, at)
}

func (s *HealthStore) TryAcquireDomainPermitVersion(nodeID NodeID, nodeVersion uint64, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	return s.TryAcquireDomainPermitHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, domain, transport, service, at)
}

func (s *HealthStore) TryAcquireDomainPermitHandle(handle NodeHandle, domain FailureDomain, transport, service string, at time.Time) (*AttemptPermit, bool) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	if domain == DomainTransport {
		transport = transportLedgerKey(transport)
	}
	key := healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: domain, transport: transport, service: service}
	s.access.Lock()
	defer s.access.Unlock()
	// Same qualified→legacy resolution as StatusHandle / tryAcquirePermit so a
	// half-open token on tcp/ipv4 cannot be bypassed with bare "tcp" / "tcp/any".
	record, resolvedKey := s.recordForKeyLocked(key)
	key = resolvedKey
	if record == nil && domain == DomainTransport {
		if pinned, pinnedKey, ok := s.mostRestrictiveTransportRecordLocked(handle, key.transport); ok {
			record, key = pinned, pinnedKey
		}
	}
	if record == nil {
		return &AttemptPermit{store: s, entries: []permitEntry{{key: key}}}, true
	}
	if !s.availableLocked(record, at) {
		return nil, false
	}
	entry := permitEntry{key: key, version: record.version}
	if record.status.Breaker == BreakerOpen || record.status.Breaker == BreakerCooldown || record.status.Breaker == BreakerHalfOpen {
		record.status.Breaker = BreakerHalfOpen
		record.status.HalfOpen = true
		s.nextToken++
		record.halfOpenToken = s.nextToken
		entry.halfOpenToken = record.halfOpenToken
	}
	return &AttemptPermit{store: s, entries: []permitEntry{entry}}, true
}

func (s *HealthStore) CanAttempt(nodeID NodeID, service ServiceContext, at time.Time) bool {
	return s.CanAttemptVersion(nodeID, 0, service, at)
}

func (s *HealthStore) CanAttemptVersion(nodeID NodeID, nodeVersion uint64, service ServiceContext, at time.Time) bool {
	return s.CanAttemptHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, service, at)
}

// CanAttemptHandle may advance open->cooldown labels as a side effect of
// inspecting availability. New plan/status code must use PeekAvailable /
// CanAttemptHandleReadOnly instead. Dial paths should prefer TryAcquire* so
// half-open tokens are the only intentional write on the attempt boundary.
func (s *HealthStore) CanAttemptHandle(handle NodeHandle, service ServiceContext, at time.Time) bool {
	if at.IsZero() {
		at = s.clock.Now()
	}
	// Transport uses dual-stack-aware eligibility (family ledger), not only the
	// single aggregate key which may miss concrete tcp/ipv4|ipv6 failures.
	if !s.transportPathEligible(handle, serviceHealthTransport(service), at) {
		return false
	}
	keys := []healthKey{
		{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint},
		{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainService, service: service.ID},
	}
	s.access.Lock()
	defer s.access.Unlock()
	for _, key := range keys {
		if record, _ := s.recordForKeyLocked(key); record != nil && !s.availableLocked(record, at) {
			return false
		}
	}
	return true
}

// CanAttemptHandleReadOnly reports current availability without advancing a
// breaker or acquiring a half-open token. Status/API/Plan paths must use this form.
// Transport eligibility is dual-stack aware so Plan shares policy with
// RequiredPathKnownBlocked / SupportsService.
func (s *HealthStore) CanAttemptHandleReadOnly(handle NodeHandle, service ServiceContext, at time.Time) bool {
	if s == nil {
		return true
	}
	if at.IsZero() {
		at = s.clock.Now()
	}
	if !s.transportPathEligible(handle, serviceHealthTransport(service), at) {
		return false
	}
	keys := []healthKey{
		{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainEndpoint},
		{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: DomainService, service: service.ID},
	}
	s.access.RLock()
	defer s.access.RUnlock()
	for _, key := range keys {
		record, _ := s.recordForKeyLocked(key)
		if record != nil && !availableReadOnly(record, at) {
			return false
		}
	}
	return true
}

func availableReadOnly(record *healthRecord, now time.Time) bool {
	if record == nil {
		return true
	}
	switch record.status.Breaker {
	case BreakerOpen, BreakerCooldown:
		return !now.Before(record.openUntil)
	case BreakerHalfOpen:
		return record.halfOpenToken == 0
	default:
		return true
	}
}

func (s *HealthStore) availableLocked(record *healthRecord, now time.Time) bool {
	switch record.status.Breaker {
	case BreakerOpen:
		if now.Before(record.openUntil) {
			record.status.Breaker = BreakerCooldown
			record.status.CooldownUntil = record.openUntil
			return false
		}
		return true
	case BreakerCooldown:
		return !now.Before(record.openUntil)
	case BreakerHalfOpen:
		return record.halfOpenToken == 0
	default:
		return true
	}
}

func (s *HealthStore) completePermitDomains(entries []permitEntry, outcomes map[FailureDomain]ObservationOutcome, at time.Time, delay time.Duration, reason string) {
	if at.IsZero() {
		at = s.clock.Now()
	}
	s.access.Lock()
	for _, entry := range entries {
		outcome, loaded := outcomes[entry.key.domain]
		if !loaded || outcome == OutcomeDeferred {
			s.releaseTokenLocked(entry)
			continue
		}
		s.observeLocked(entry.key, outcome, at, delay, reason, entry.version, entry.halfOpenToken, true)
	}
	s.access.Unlock()
}

func (s *HealthStore) releasePermit(entries []permitEntry) {
	s.access.Lock()
	for _, entry := range entries {
		s.releaseTokenLocked(entry)
	}
	s.access.Unlock()
}

func (s *HealthStore) releaseTokenLocked(entry permitEntry) {
	if record := s.entries[entry.key]; record != nil && record.version == entry.version && record.halfOpenToken == entry.halfOpenToken && entry.halfOpenToken != 0 && record.status.Breaker == BreakerHalfOpen {
		record.status.Breaker = BreakerCooldown
		record.status.HalfOpen = false
		record.status.CooldownUntil = record.openUntil
		record.halfOpenToken = 0
	}
}

func (s *HealthStore) observeLocked(key healthKey, outcome ObservationOutcome, at time.Time, delay time.Duration, reason string, version, halfOpenToken uint64, active bool) {
	s.pruneExpiredLocked(at)
	record := s.entries[key]
	if record != nil && !record.status.LastUpdated.IsZero() && at.Before(record.status.LastUpdated) {
		return
	}
	if record == nil {
		if active && version != 0 {
			return
		}
		record = &healthRecord{key: key}
		record.element = s.lru.PushFront(record)
		s.entries[key] = record
	} else {
		s.lru.MoveToFront(record.element)
	}
	if active && record.version != version {
		return
	}
	// Passive observations can build evidence while closed, but cannot recover
	// an open breaker. Active recovery requires both the captured version and
	// the unique half-open owner token.
	if !active && record.status.Breaker != BreakerClosed && record.status.Breaker != "" {
		return
	}
	if record.status.Breaker == BreakerHalfOpen && halfOpenToken != record.halfOpenToken {
		return
	}
	record.status.LastUpdated = at
	record.status.Reason = reason
	if outcome == OutcomeSuccess && delay > 0 {
		recordHealthDelay(record, delay)
	}
	if outcome == OutcomeSuccess {
		record.status.Successes++
		record.consecutiveFailure = 0
		if record.status.Breaker == BreakerHalfOpen {
			record.recoverySuccesses++
			record.status.RecoverySuccesses = record.recoverySuccesses
			record.halfOpenToken = 0
			if record.recoverySuccesses < 2 {
				record.status.Health = HealthDegraded
				record.status.Breaker = BreakerHalfOpen
				record.status.HalfOpen = true
				record.status.CooldownUntil = time.Time{}
				record.status.ConsecutiveFailures = 0
				return
			}
		}
		record.reopenCount = 0
		record.recoverySuccesses = 0
		record.openUntil = time.Time{}
		record.halfOpenToken = 0
		record.status.Health = HealthHealthy
		record.status.Breaker = BreakerClosed
		record.status.HalfOpen = false
		record.status.CooldownUntil = time.Time{}
		record.status.Backoff = 0
		record.status.RecoverySuccesses = 0
	} else {
		record.status.Failures++
		record.consecutiveFailure++
		record.recoverySuccesses = 0
		record.status.RecoverySuccesses = 0
		if record.status.Breaker == BreakerHalfOpen || record.consecutiveFailure >= s.breaker.FailureThreshold {
			record.status.Health = HealthUnreachable
			record.reopenCount++
			s.openBreakerRecordLocked(record, at)
		} else {
			record.status.Health = HealthDegraded
			record.status.Breaker = BreakerClosed
		}
	}
	record.status.ConsecutiveFailures = record.consecutiveFailure
	for len(s.entries) > s.maxEntries {
		s.removeOldestLocked()
	}
}

func (s *HealthStore) openBreakerRecordLocked(record *healthRecord, now time.Time) {
	backoff := s.breaker.BaseCooldown
	for i := 1; i < record.reopenCount; i++ {
		if backoff >= s.breaker.MaxCooldown/2 {
			backoff = s.breaker.MaxCooldown
			break
		}
		backoff *= 2
	}
	if backoff > s.breaker.MaxCooldown {
		backoff = s.breaker.MaxCooldown
	}
	backoff = applyBackoffJitter(backoff, s.breaker.JitterFraction, s.breaker.JitterRandom)
	if backoff > s.breaker.MaxCooldown {
		backoff = s.breaker.MaxCooldown
	}
	if backoff < s.breaker.BaseCooldown/2 && s.breaker.BaseCooldown > 0 {
		// Keep a floor so jitter cannot collapse the first open window to near-zero.
		minBackoff := s.breaker.BaseCooldown / 2
		if backoff < minBackoff {
			backoff = minBackoff
		}
	}
	record.openUntil = now.Add(backoff)
	record.version++
	record.status.Breaker = BreakerOpen
	record.status.HalfOpen = false
	record.status.CooldownUntil = record.openUntil
	record.status.Backoff = backoff
	record.halfOpenToken = 0
	record.recoverySuccesses = 0
	record.status.RecoverySuccesses = 0
}

func applyBackoffJitter(backoff time.Duration, fraction float64, random func() float64) time.Duration {
	if backoff <= 0 || fraction <= 0 {
		return backoff
	}
	if random == nil {
		random = rand.Float64
	}
	// Symmetric jitter in [-fraction, +fraction].
	sample := random()
	if sample < 0 {
		sample = 0
	} else if sample >= 1 {
		sample = math.Nextafter(1, 0)
	}
	scale := 1 + (sample*2-1)*fraction
	if scale < 0.1 {
		scale = 0.1
	}
	return time.Duration(float64(backoff) * scale)
}

func (s *HealthStore) Endpoint(nodeID NodeID) HealthStatus {
	return s.Status(nodeID, DomainEndpoint, "", "")
}

func (s *HealthStore) EndpointVersion(nodeID NodeID, nodeVersion uint64) HealthStatus {
	return s.StatusVersion(nodeID, nodeVersion, DomainEndpoint, "", "")
}

func (s *HealthStore) EndpointHandle(handle NodeHandle) HealthStatus {
	return s.StatusHandle(handle, DomainEndpoint, "", "")
}

func (s *HealthStore) Status(nodeID NodeID, domain FailureDomain, transport, service string) HealthStatus {
	return s.StatusVersion(nodeID, 0, domain, transport, service)
}

func (s *HealthStore) StatusVersion(nodeID NodeID, nodeVersion uint64, domain FailureDomain, transport, service string) HealthStatus {
	return s.StatusHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, domain, transport, service)
}

func (s *HealthStore) StatusHandle(handle NodeHandle, domain FailureDomain, transport, service string) HealthStatus {
	s.access.RLock()
	defer s.access.RUnlock()
	key := healthKey{nodeID: handle.NodeID, nodeSlot: handle.Slot, nodeVersion: handle.Version, domain: domain, transport: transport, service: service}
	// Use the same qualified→legacy resolution as permit acquisition so Plan
	// pathCapability and TryAcquire never disagree on bare "tcp"/"udp" ledgers.
	record, _ := s.recordForKeyLocked(key)
	if record == nil && domain == DomainTransport && !strings.Contains(transport, "/") {
		var selected *healthRecord
		for entryKey, candidate := range s.entries {
			if entryKey.nodeID != handle.NodeID || entryKey.nodeSlot != handle.Slot || entryKey.nodeVersion != handle.Version || entryKey.domain != domain || entryKey.service != service || !strings.HasPrefix(entryKey.transport, transport+"/") {
				continue
			}
			if selected == nil || healthTransportStatusRank(candidate.status) > healthTransportStatusRank(selected.status) ||
				(healthTransportStatusRank(candidate.status) == healthTransportStatusRank(selected.status) && candidate.status.LastUpdated.After(selected.status.LastUpdated)) {
				selected = candidate
			}
		}
		record = selected
	}
	if record == nil {
		return HealthStatus{Health: HealthUnknown, Breaker: BreakerClosed}
	}
	return record.status
}

// recordForKeyLocked keeps old process-local health records useful while a
// caller starts supplying purpose/family-qualified transport keys. New
// observations always create the qualified key; the fallback disappears with
// the process, matching AdaptivePool's process-lifetime health contract.
func (s *HealthStore) recordForKeyLocked(key healthKey) (*healthRecord, healthKey) {
	if record := s.entries[key]; record != nil {
		return record, key
	}
	if key.domain != DomainTransport {
		return nil, key
	}
	if separator := strings.IndexByte(key.transport, '/'); separator > 0 {
		legacyKey := key
		legacyKey.transport = key.transport[:separator]
		if strings.HasPrefix(legacyKey.transport, "udp_") {
			legacyKey.transport = "udp"
		}
		if record := s.entries[legacyKey]; record != nil {
			return record, legacyKey
		}
	}
	return nil, key
}

func (s *HealthStore) RetireNodeVersion(nodeID NodeID, nodeVersion uint64) {
	s.RetireNodeHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion})
}

func (s *HealthStore) RetireNodeHandle(handle NodeHandle) {
	s.access.Lock()
	for key, record := range s.entries {
		if key.nodeID == handle.NodeID && key.nodeSlot == handle.Slot && key.nodeVersion == handle.Version {
			s.removeLocked(record)
		}
	}
	s.access.Unlock()
}

func (s *HealthStore) Stats() (entries int, evictions uint64) {
	s.access.RLock()
	entries = len(s.entries)
	evictions = s.evictions
	s.access.RUnlock()
	return
}

func (s *HealthStore) pruneExpiredLocked(now time.Time) {
	for element := s.lru.Back(); element != nil; {
		previous := element.Prev()
		record := element.Value.(*healthRecord)
		if now.Sub(record.status.LastUpdated) <= s.retention {
			break
		}
		s.removeLocked(record)
		element = previous
	}
}

func (s *HealthStore) removeOldestLocked() {
	if element := s.lru.Back(); element != nil {
		s.removeLocked(element.Value.(*healthRecord))
	}
}

func (s *HealthStore) removeLocked(record *healthRecord) {
	delete(s.entries, record.key)
	s.lru.Remove(record.element)
	s.evictions++
}
