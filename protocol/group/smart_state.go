package group

import (
	"math"
	"sort"
	"sync"
	"time"
)

type smartMetricKey struct {
	Network   string
	Site      string
	Candidate string
	Transport string
}

const smartSurgeHistorySlots = 20

type smartSurgeSample struct {
	Site  string
	Value float64
	At    time.Time
}

type smartSurgeHistory struct {
	Delay       [smartSurgeHistorySlots]smartSurgeSample
	Loss        [smartSurgeHistorySlots]smartSurgeSample
	DelayCursor int
	LossCursor  int
}

type smartMetric struct {
	Network             string    `json:"network"`
	Site                string    `json:"site,omitempty"`
	Candidate           string    `json:"candidate"`
	Transport           string    `json:"transport"`
	Successes           float64   `json:"successes"`
	Failures            float64   `json:"failures"`
	ConnectMS           float64   `json:"connect_ms,omitempty"`
	ConnectP95MS        float64   `json:"connect_p95_ms,omitempty"`
	FirstByteMS         float64   `json:"first_byte_ms,omitempty"`
	FirstByteP95MS      float64   `json:"first_byte_p95_ms,omitempty"`
	ThroughputLog       float64   `json:"throughput_log,omitempty"`
	JitterMS            float64   `json:"jitter_ms,omitempty"`
	ConnectSamples      float64   `json:"connect_samples,omitempty"`
	FirstByteSamples    float64   `json:"first_byte_samples,omitempty"`
	ThroughputSamples   float64   `json:"throughput_samples,omitempty"`
	RetransmitRatio     float64   `json:"tcp_retransmit_ratio,omitempty"`
	RetransmitSamples   float64   `json:"tcp_retransmit_samples,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	CircuitUntil        time.Time `json:"circuit_until,omitempty"`
	LastUpdated         time.Time `json:"last_updated"`
}

type smartEstimate struct {
	Reliability            float64
	ConnectMS              float64
	ConnectP95MS           float64
	FirstByteMS            float64
	FirstByteP95MS         float64
	ThroughputBPS          float64
	ThroughputSamples      float64
	RetransmitRatio        float64
	RetransmitSamples      float64
	LocalThroughputBPS     float64
	LocalThroughputSamples float64
	JitterMS               float64
	Samples                float64
	State                  string
	CircuitUntil           time.Time
	HasConnect             bool
	HasConnectP95          bool
	HasFirstByte           bool
	HasFirstByteP95        bool
	HasThroughput          bool
	HasRetransmit          bool
}

type smartStore struct {
	access          sync.RWMutex
	metrics         map[smartMetricKey]*smartMetric
	halfLife        time.Duration
	breakerFailures int
	breakerCooldown time.Duration
	retention       time.Duration
	maxEntries      int
	surgeHistories  map[smartMetricKey]*smartSurgeHistory
}

func (s *smartStore) clear() {
	if s == nil {
		return
	}
	s.access.Lock()
	clear(s.metrics)
	// A real connection may finish after the group is retired. Keep a small,
	// writable map for that late observation while releasing the old buckets.
	s.metrics = make(map[smartMetricKey]*smartMetric)
	s.surgeHistories = make(map[smartMetricKey]*smartSurgeHistory)
	s.access.Unlock()
}

func newSmartStore(halfLife time.Duration, breakerFailures int, breakerCooldown time.Duration) *smartStore {
	if halfLife <= 0 {
		halfLife = 30 * time.Minute
	}
	if breakerFailures <= 0 {
		breakerFailures = 3
	}
	if breakerCooldown <= 0 {
		breakerCooldown = 2 * time.Minute
	}
	return &smartStore{
		metrics:         make(map[smartMetricKey]*smartMetric),
		surgeHistories:  make(map[smartMetricKey]*smartSurgeHistory),
		halfLife:        halfLife,
		breakerFailures: breakerFailures,
		breakerCooldown: breakerCooldown,
	}
}

func (s *smartStore) setPolicy(halfLife time.Duration, breakerFailures int, breakerCooldown time.Duration) {
	if halfLife <= 0 {
		halfLife = 30 * time.Minute
	}
	if breakerFailures <= 0 {
		breakerFailures = 3
	}
	if breakerCooldown <= 0 {
		breakerCooldown = 2 * time.Minute
	}
	s.access.Lock()
	s.halfLife = halfLife
	s.breakerFailures = breakerFailures
	s.breakerCooldown = breakerCooldown
	s.access.Unlock()
}

func (s *smartStore) setBounds(retention time.Duration, maxEntries int) {
	s.access.Lock()
	s.retention = retention
	s.maxEntries = maxEntries
	s.pruneLocked(time.Now(), retention, maxEntries)
	s.access.Unlock()
}

func (s *smartStore) metric(key smartMetricKey, now time.Time) *smartMetric {
	metric := s.metrics[key]
	if metric == nil {
		if s.maxEntries > 0 && len(s.metrics) >= s.maxEntries {
			target := max(1, s.maxEntries-s.maxEntries/10)
			s.pruneLocked(now, s.retention, target)
			if len(s.metrics) >= s.maxEntries {
				s.removeOldestLocked()
			}
		}
		metric = &smartMetric{
			Network:   key.Network,
			Site:      key.Site,
			Candidate: key.Candidate,
			Transport: key.Transport,
		}
		s.metrics[key] = metric
	}
	return metric
}

func (s *smartStore) removeOldestLocked() {
	var (
		oldestKey smartMetricKey
		oldest    time.Time
		loaded    bool
	)
	for key, metric := range s.metrics {
		if !loaded || metric.LastUpdated.Before(oldest) {
			oldestKey = key
			oldest = metric.LastUpdated
			loaded = true
		}
	}
	if loaded {
		delete(s.metrics, oldestKey)
	}
}

func (s *smartStore) observeDial(now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	globalKey := smartMetricKey{Network: network, Candidate: candidate, Transport: transport}
	globalWeight := 1.0
	if !success && site != "" {
		globalWeight = 0.25
	}
	s.observeDialLocked(now, globalKey, success, elapsed, globalWeight, site == "")
	if site != "" {
		// Site failures are a Surge-style stain, not a circuit breaker. They
		// downgrade this endpoint only for the affected registered domain.
		s.observeDialLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, success, elapsed, 1, false)
	}
}

// observeDialAdvisory records dashboard/manual probe quality without touching
// breaker counters or clearing an existing circuit. A panel measurement is a
// user-visible hint, not real data-plane evidence: it must never make a
// healthy manual pin disappear because one probe raced a transient outage.
func (s *smartStore) observeDialAdvisory(now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	s.access.Lock()
	defer s.access.Unlock()
	observe := func(key smartMetricKey) {
		metric := s.metric(key, now)
		metric.decay(now, s.halfLife)
		if success {
			metric.Successes++
			if elapsed > 0 {
				metric.updateConnect(float64(elapsed.Microseconds()) / 1000)
			}
		} else {
			metric.Failures++
		}
		metric.LastUpdated = now
	}
	observe(smartMetricKey{Network: network, Candidate: candidate, Transport: transport})
	if site != "" {
		observe(smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport})
	}
}

func (s *smartStore) pruneCandidates(keep map[string]struct{}) {
	if s == nil {
		return
	}
	s.access.Lock()
	for key := range s.metrics {
		if _, retained := keep[key.Candidate]; !retained {
			delete(s.metrics, key)
		}
	}
	for key := range s.surgeHistories {
		if _, retained := keep[key.Candidate]; !retained {
			delete(s.surgeHistories, key)
		}
	}
	s.access.Unlock()
}

// quarantineDataPlaneFailure adds a short, site-local circuit after a real
// data-plane failure. It is deliberately separate from observeDial so
// background probe failures keep their endpoint-wide fail-open behavior. A
// site-specific failure never opens the global endpoint ledger; requests for
// another service can continue using the same node.
func (s *smartStore) quarantineDataPlaneFailure(now time.Time, network, site, candidate, transport string, duration time.Duration) {
	if s == nil || candidate == "" || duration <= 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	until := now.Add(duration)
	key := smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	if metric.CircuitUntil.Before(until) {
		metric.CircuitUntil = until
	}
	if metric.ConsecutiveFailures < 1 {
		metric.ConsecutiveFailures = 1
	}
	metric.LastUpdated = now
}

// openEndpointCircuit records authoritative node-level evidence. It is used
// only for protocol/authentication failures (or equivalent hard transport
// failures); ordinary site timeouts stay in the site ledger and never
// accumulate into an endpoint-wide circuit.
func (s *smartStore) openEndpointCircuit(now time.Time, network, candidate, transport string) {
	if s == nil || candidate == "" {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	metric := s.metric(smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, now)
	metric.decay(now, s.halfLife)
	metric.Failures++
	metric.ConsecutiveFailures = max(metric.ConsecutiveFailures, s.breakerFailures)
	metric.CircuitUntil = now.Add(s.breakerCooldown)
	metric.LastUpdated = now
}

func (s *smartStore) candidateDead(network, site, candidate, transport string, now time.Time) bool {
	if s == nil || candidate == "" {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	for key, metric := range s.metrics {
		if key.Candidate != candidate || key.Network != network || key.Transport != transport {
			continue
		}
		// A site-specific view may use either its local ledger or the global
		// endpoint ledger. Never borrow evidence from an unrelated site.
		if site != "" && key.Site != "" && key.Site != site {
			continue
		}
		if now.Sub(metric.LastUpdated) > 30*time.Second || !metric.CircuitUntil.After(now) {
			continue
		}
		if metric.ConsecutiveFailures >= s.breakerFailures {
			return true
		}
	}
	return false
}

func (s *smartStore) endpointDead(network, candidate, transport string, now time.Time) bool {
	if s == nil || candidate == "" {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	metric := s.metrics[smartMetricKey{Network: network, Candidate: candidate, Transport: transport}]
	return metric != nil && now.Sub(metric.LastUpdated) <= 30*time.Second &&
		metric.CircuitUntil.After(now) && metric.ConsecutiveFailures >= s.breakerFailures
}

func (s *smartStore) siteFailedRecently(now time.Time, network, site, candidate, transport string, ttl time.Duration) bool {
	if s == nil || site == "" || candidate == "" || ttl <= 0 {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	metric := s.metrics[smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}]
	return metric != nil && metric.ConsecutiveFailures > 0 &&
		!metric.LastUpdated.IsZero() && now.Sub(metric.LastUpdated) <= ttl
}

func (s *smartStore) siteSuccessSnapshot(now time.Time, network, site, candidate, transport string, ttl time.Duration) (float64, float64) {
	if s == nil || site == "" || candidate == "" || ttl <= 0 {
		return 0, 0
	}
	s.access.RLock()
	defer s.access.RUnlock()
	metric := s.metrics[smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}]
	if metric == nil || metric.Successes <= 0 || metric.LastUpdated.IsZero() || now.Sub(metric.LastUpdated) > ttl {
		return 0, 0
	}
	delay := firstNonZero(metric.FirstByteMS, metric.ConnectMS)
	return metric.Successes, delay
}

func (s *smartStore) observeDialLocked(now time.Time, key smartMetricKey, success bool, elapsed time.Duration, weight float64, updateBreaker bool) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	if success {
		metric.Successes += weight
		metric.ConsecutiveFailures = 0
		metric.CircuitUntil = time.Time{}
		if elapsed > 0 {
			metric.updateConnect(float64(elapsed.Microseconds()) / 1000)
		}
	} else {
		metric.Failures += weight
		metric.ConsecutiveFailures++
		if updateBreaker {
			if metric.ConsecutiveFailures >= s.breakerFailures {
				exponent := min(metric.ConsecutiveFailures-s.breakerFailures, 4)
				metric.CircuitUntil = now.Add(s.breakerCooldown * time.Duration(1<<exponent))
			}
		}
	}
	metric.LastUpdated = now
}

func (s *smartStore) observeFirstByte(now time.Time, network, site, candidate, transport string, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.observeFirstByteLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, elapsed)
	updateSmartSurgeDelay(s.surgeHistoryLocked(smartMetricKey{Network: network, Candidate: candidate, Transport: transport}), site, float64(elapsed.Microseconds())/1000, now)
	if site != "" {
		s.observeFirstByteLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, elapsed)
	}
}

func (s *smartStore) observeFirstByteLocked(now time.Time, key smartMetricKey, elapsed time.Duration) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	metric.updateFirstByte(float64(elapsed.Microseconds()) / 1000)
	metric.LastUpdated = now
}

func (s *smartStore) observeThroughput(now time.Time, network, site, candidate, transport string, bytes int64, elapsed time.Duration) {
	if bytes < 64*1024 || elapsed < time.Second {
		return
	}
	bps := float64(bytes) / elapsed.Seconds()
	if bps <= 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.observeThroughputLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, bps)
	if site != "" {
		s.observeThroughputLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, bps)
	}
}

func (s *smartStore) observeThroughputLocked(now time.Time, key smartMetricKey, bps float64) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	value := math.Log1p(bps)
	metric.ThroughputLog = updateEWMA(metric.ThroughputLog, value, metric.ThroughputSamples)
	metric.ThroughputSamples++
	metric.LastUpdated = now
}

// observeRetransmit records a kernel TCP_INFO retransmitted-byte ratio. It is
// advisory only: unsupported platforms simply never call it, and a single
// socket's loss cannot open a circuit by itself.
func (s *smartStore) observeRetransmit(now time.Time, network, site, candidate, transport string, ratio float64) {
	if ratio < 0 || math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return
	}
	if ratio > 1 {
		ratio = 1
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.observeRetransmitLocked(now, smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, ratio)
	updateSmartSurgeLoss(s.surgeHistoryLocked(smartMetricKey{Network: network, Candidate: candidate, Transport: transport}), ratio, now)
	if site != "" {
		s.observeRetransmitLocked(now, smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, ratio)
	}
}

func (s *smartStore) observeRetransmitLocked(now time.Time, key smartMetricKey, ratio float64) {
	metric := s.metric(key, now)
	metric.decay(now, s.halfLife)
	metric.RetransmitRatio = updateEWMA(metric.RetransmitRatio, ratio, metric.RetransmitSamples)
	metric.RetransmitSamples++
	metric.LastUpdated = now
}

func (s *smartStore) surgeHistoryLocked(key smartMetricKey) *smartSurgeHistory {
	history := s.surgeHistories[key]
	if history == nil {
		history = &smartSurgeHistory{}
		s.surgeHistories[key] = history
	}
	return history
}

func updateSmartSurgeDelay(history *smartSurgeHistory, site string, value float64, now time.Time) {
	if history == nil || value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	if site != "" {
		for index := range history.Delay {
			sample := &history.Delay[index]
			if sample.Site == site && !sample.At.IsZero() && now.Sub(sample.At) <= 5*time.Minute {
				sample.Value = (sample.Value + value) * 0.5
				sample.At = now
				return
			}
		}
	}
	history.Delay[history.DelayCursor] = smartSurgeSample{Site: site, Value: value, At: now}
	history.DelayCursor = (history.DelayCursor + 1) % len(history.Delay)
}

func updateSmartSurgeLoss(history *smartSurgeHistory, value float64, now time.Time) {
	if history == nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	history.Loss[history.LossCursor] = smartSurgeSample{Value: math.Min(1, value), At: now}
	history.LossCursor = (history.LossCursor + 1) % len(history.Loss)
}

func smartSurgeWeightedAverage(samples []smartSurgeSample) float64 {
	latest := time.Time{}
	for _, sample := range samples {
		if sample.Value >= 0 && sample.At.After(latest) {
			latest = sample.At
		}
	}
	if latest.IsZero() {
		return 0
	}
	windowStart := latest.Add(-5 * time.Minute)
	weighted, weights := 0.0, 0.0
	for _, sample := range samples {
		if sample.At.IsZero() || !sample.At.After(windowStart) || sample.At.After(latest) {
			continue
		}
		weight := sample.At.Sub(windowStart).Seconds() / (5 * time.Minute).Seconds()
		weighted += sample.Value * weight
		weights += weight
	}
	if weights == 0 {
		return 0
	}
	return weighted / weights
}

func (s *smartStore) surgeScoreSnapshot(network, candidate, transport string) (delayMS, loss float64) {
	if s == nil {
		return 0, 0
	}
	s.access.RLock()
	history := s.surgeHistories[smartMetricKey{Network: network, Candidate: candidate, Transport: transport}]
	if history != nil {
		delay := history.Delay
		losses := history.Loss
		s.access.RUnlock()
		return smartSurgeWeightedAverage(delay[:]), smartSurgeWeightedAverage(losses[:])
	}
	s.access.RUnlock()
	return 0, 0
}

func (s *smartStore) estimate(now time.Time, network, site, candidate, transport string, minSamples int) smartEstimate {
	s.access.RLock()
	defer s.access.RUnlock()
	global, globalOK := s.metricCopy(smartMetricKey{Network: network, Candidate: candidate, Transport: transport}, now)
	local, localOK := s.metricCopy(smartMetricKey{Network: network, Site: site, Candidate: candidate, Transport: transport}, now)
	return blendSmartEstimate(global, globalOK, local, localOK, minSamples, now)
}

func (s *smartStore) metricCopy(key smartMetricKey, now time.Time) (smartMetric, bool) {
	metric := s.metrics[key]
	if metric == nil {
		return smartMetric{}, false
	}
	copyMetric := *metric
	copyMetric.decay(now, s.halfLife)
	return copyMetric, true
}

func (s *smartStore) pruneLocked(now time.Time, retention time.Duration, maxEntries int) {
	if retention > 0 {
		for key, metric := range s.metrics {
			if !metric.LastUpdated.IsZero() && now.Sub(metric.LastUpdated) > retention {
				delete(s.metrics, key)
			}
		}
	}
	if maxEntries <= 0 || len(s.metrics) <= maxEntries {
		return
	}
	type metricAge struct {
		key       smartMetricKey
		updatedAt time.Time
	}
	ages := make([]metricAge, 0, len(s.metrics))
	for key, metric := range s.metrics {
		ages = append(ages, metricAge{key: key, updatedAt: metric.LastUpdated})
	}
	sort.Slice(ages, func(i, j int) bool {
		return ages[i].updatedAt.After(ages[j].updatedAt)
	})
	for _, entry := range ages[maxEntries:] {
		delete(s.metrics, entry.key)
	}
}

func (m *smartMetric) decay(now time.Time, halfLife time.Duration) {
	if m.LastUpdated.IsZero() || !now.After(m.LastUpdated) || halfLife <= 0 {
		return
	}
	factor := math.Exp(-math.Ln2 * now.Sub(m.LastUpdated).Seconds() / halfLife.Seconds())
	m.Successes *= factor
	m.Failures *= factor
	m.ConnectSamples *= factor
	m.FirstByteSamples *= factor
	m.ThroughputSamples *= factor
	m.RetransmitSamples *= factor
	// The counters above are the confidence carried by each metric. Once an
	// evidence class has less than a quarter of an effective sample, retaining its old
	// EWMA/tail value would let stale latency or throughput influence a new
	// decision as if it were fresh. Drop only that class; reliability counts
	// remain available as the neutral Bayesian prior in estimateMetric.
	if m.ConnectSamples < 0.25 {
		m.ConnectMS = 0
		m.ConnectP95MS = 0
		m.JitterMS = 0
		m.ConnectSamples = 0
	}
	if m.FirstByteSamples < 0.25 {
		m.FirstByteMS = 0
		m.FirstByteP95MS = 0
		m.FirstByteSamples = 0
	}
	if m.ThroughputSamples < 0.25 {
		m.ThroughputLog = 0
		m.ThroughputSamples = 0
	}
	if m.RetransmitSamples < 0.25 {
		m.RetransmitRatio = 0
		m.RetransmitSamples = 0
	}
}

func (m *smartMetric) updateConnect(value float64) {
	if m.ConnectSamples == 0 {
		m.ConnectMS = value
		m.ConnectP95MS = value
		m.JitterMS = 0
	} else {
		deviation := math.Abs(value - m.ConnectMS)
		m.ConnectMS = updateEWMA(m.ConnectMS, value, m.ConnectSamples)
		m.ConnectP95MS = updateTailEWMA(m.ConnectP95MS, value)
		m.JitterMS = updateEWMA(m.JitterMS, deviation, m.ConnectSamples)
	}
	m.ConnectSamples++
}

func (m *smartMetric) updateFirstByte(value float64) {
	m.FirstByteMS = updateEWMA(m.FirstByteMS, value, m.FirstByteSamples)
	m.FirstByteP95MS = updateTailEWMA(m.FirstByteP95MS, value)
	m.FirstByteSamples++
}

// updateTailEWMA is a bounded, allocation-free approximation of a p95. High
// observations move the estimate quickly while normal observations decay it
// slowly. Unlike a retained sample ring, it keeps the Smart store bounded even
// with thousands of provider lines and survives snapshot/restore unchanged.
func updateTailEWMA(current, value float64) float64 {
	if value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return current
	}
	if current <= 0 || math.IsNaN(current) || math.IsInf(current, 0) {
		return value
	}
	alpha := 0.02
	if value > current {
		// A tail sample is the signal we want to preserve. Move quickly on
		// spikes so a single multi-second stall is visible to the selector;
		// let ordinary samples decay slowly to avoid oscillation.
		alpha = 0.80
	}
	return current + alpha*(value-current)
}

func updateEWMA(current, value, samples float64) float64 {
	if samples <= 0 {
		return value
	}
	alpha := 2.0 / (math.Min(samples, 9) + 2)
	return current + alpha*(value-current)
}

func blendSmartEstimate(global smartMetric, globalOK bool, local smartMetric, localOK bool, minSamples int, now time.Time) smartEstimate {
	if minSamples <= 0 {
		minSamples = 3
	}
	if !globalOK && !localOK {
		return smartEstimate{Reliability: 0.13, State: "unknown"}
	}
	var globalEstimate smartEstimate
	if globalOK {
		globalEstimate = estimateMetric(global, now, minSamples)
	}
	if !localOK || local.Site == "" {
		return globalEstimate
	}
	localEstimate := estimateMetric(local, now, minSamples)
	localWeight := math.Min(0.85, localEstimate.Samples/float64(minSamples)*0.85)
	if !globalOK {
		localWeight = 1
	}
	return smartEstimate{
		Reliability:            blendValue(globalEstimate.Reliability, localEstimate.Reliability, localWeight),
		ConnectMS:              blendOptional(globalEstimate.ConnectMS, localEstimate.ConnectMS, globalEstimate.HasConnect, localEstimate.HasConnect, localWeight),
		ConnectP95MS:           blendOptional(globalEstimate.ConnectP95MS, localEstimate.ConnectP95MS, globalEstimate.HasConnectP95, localEstimate.HasConnectP95, localWeight),
		FirstByteMS:            blendOptional(globalEstimate.FirstByteMS, localEstimate.FirstByteMS, globalEstimate.HasFirstByte, localEstimate.HasFirstByte, localWeight),
		FirstByteP95MS:         blendOptional(globalEstimate.FirstByteP95MS, localEstimate.FirstByteP95MS, globalEstimate.HasFirstByteP95, localEstimate.HasFirstByteP95, localWeight),
		ThroughputBPS:          blendOptional(globalEstimate.ThroughputBPS, localEstimate.ThroughputBPS, globalEstimate.HasThroughput, localEstimate.HasThroughput, localWeight),
		ThroughputSamples:      math.Max(globalEstimate.ThroughputSamples, localEstimate.ThroughputSamples),
		RetransmitRatio:        blendOptional(globalEstimate.RetransmitRatio, localEstimate.RetransmitRatio, globalEstimate.HasRetransmit, localEstimate.HasRetransmit, localWeight),
		RetransmitSamples:      math.Max(globalEstimate.RetransmitSamples, localEstimate.RetransmitSamples),
		LocalThroughputBPS:     localEstimate.ThroughputBPS,
		LocalThroughputSamples: localEstimate.ThroughputSamples,
		JitterMS:               blendOptional(globalEstimate.JitterMS, localEstimate.JitterMS, globalEstimate.HasConnect, localEstimate.HasConnect, localWeight),
		Samples:                math.Max(globalEstimate.Samples, localEstimate.Samples),
		State:                  strongerState(globalEstimate.State, localEstimate.State),
		CircuitUntil:           laterTime(globalEstimate.CircuitUntil, localEstimate.CircuitUntil),
		HasConnect:             globalEstimate.HasConnect || localEstimate.HasConnect,
		HasConnectP95:          globalEstimate.HasConnectP95 || localEstimate.HasConnectP95,
		HasFirstByte:           globalEstimate.HasFirstByte || localEstimate.HasFirstByte,
		HasFirstByteP95:        globalEstimate.HasFirstByteP95 || localEstimate.HasFirstByteP95,
		HasThroughput:          globalEstimate.HasThroughput || localEstimate.HasThroughput,
		HasRetransmit:          globalEstimate.HasRetransmit || localEstimate.HasRetransmit,
	}
}

func estimateMetric(metric smartMetric, now time.Time, minSamples int) smartEstimate {
	alpha := 1 + metric.Successes
	beta := 1 + metric.Failures
	mean := alpha / (alpha + beta)
	variance := alpha * beta / (math.Pow(alpha+beta, 2) * (alpha + beta + 1))
	reliability := math.Max(0, mean-1.28*math.Sqrt(variance))
	samples := metric.Successes + metric.Failures
	state := "healthy"
	if metric.CircuitUntil.After(now) {
		state = "open"
	} else if !metric.CircuitUntil.IsZero() {
		state = "half_open"
	} else if samples < float64(minSamples) {
		state = "warming"
	} else if reliability < 0.65 {
		state = "suspect"
	}
	return smartEstimate{
		Reliability:       reliability,
		ConnectMS:         metric.ConnectMS,
		ConnectP95MS:      firstNonZero(metric.ConnectP95MS, metric.ConnectMS),
		FirstByteMS:       metric.FirstByteMS,
		FirstByteP95MS:    firstNonZero(metric.FirstByteP95MS, metric.FirstByteMS),
		ThroughputBPS:     math.Expm1(metric.ThroughputLog),
		ThroughputSamples: metric.ThroughputSamples,
		RetransmitRatio:   metric.RetransmitRatio,
		RetransmitSamples: metric.RetransmitSamples,
		JitterMS:          metric.JitterMS,
		Samples:           samples,
		State:             state,
		CircuitUntil:      metric.CircuitUntil,
		HasConnect:        metric.ConnectSamples > 0,
		HasConnectP95:     metric.ConnectSamples > 0,
		HasFirstByte:      metric.FirstByteSamples > 0,
		HasFirstByteP95:   metric.FirstByteSamples > 0,
		HasThroughput:     metric.ThroughputSamples > 0,
		HasRetransmit:     metric.RetransmitSamples > 0,
	}
}

func firstNonZero(primary, fallback float64) float64 {
	if primary > 0 && !math.IsNaN(primary) && !math.IsInf(primary, 0) {
		return primary
	}
	return fallback
}

func smartConnectScoreMS(estimate smartEstimate) float64 {
	return firstNonZero(estimate.ConnectP95MS, estimate.ConnectMS)
}

func smartFirstByteScoreMS(estimate smartEstimate) float64 {
	return firstNonZero(estimate.FirstByteP95MS, estimate.FirstByteMS)
}

func smartSurgeScore(estimate smartEstimate) float64 {
	// Surge scores only its first-response history. A policy without a valid
	// first-response sample has score zero and receives the cold exploration
	// privilege; dial latency/URLTest latency do not replace this field.
	delay := estimate.FirstByteMS
	if delay < 1 || math.IsNaN(delay) || math.IsInf(delay, 0) {
		return 0
	}
	loss := estimate.RetransmitRatio
	if loss > 0 && !math.IsNaN(loss) && !math.IsInf(loss, 0) {
		delay += math.Min(1, loss) * 5000
	}
	return math.Max(1, delay)
}

type smartTrafficProfile uint8

const (
	smartProfileInteractive smartTrafficProfile = iota
	smartProfileBulk
	smartProfileUDP
)

func detectSmartTrafficProfile(transport string, estimates map[string]smartEstimate) smartTrafficProfile {
	if transport == "udp" {
		return smartProfileUDP
	}
	for _, estimate := range estimates {
		if estimate.ThroughputSamples >= 2 {
			return smartProfileBulk
		}
	}
	return smartProfileInteractive
}

func (p smartTrafficProfile) String() string {
	switch p {
	case smartProfileBulk:
		return "bulk"
	case smartProfileUDP:
		return "udp"
	default:
		return "interactive"
	}
}

func smartScoreForProfile(estimate smartEstimate, profile smartTrafficProfile, exploration, totalSamples float64) float64 {
	if estimate.State == "open" {
		return 100
	}
	var reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight, confidenceWeight float64
	switch profile {
	case smartProfileBulk:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight, confidenceWeight = 0.30, 0.15, 0.20, 0.30, 0.00, 0.05
	case smartProfileUDP:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight, confidenceWeight = 0.50, 0.25, 0, 0, 0.20, 0.05
	default:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight, confidenceWeight = 0.30, 0.25, 0.30, 0, 0.10, 0.05
	}
	connectValue := firstNonZero(estimate.ConnectP95MS, estimate.ConnectMS)
	connectCost := 0.50
	if estimate.HasConnect {
		connectCost = normalizedLogCost(connectValue, 5000)
	}
	firstByteCost := 0.50
	if estimate.HasFirstByte {
		firstByteCost = normalizedLogCost(firstNonZero(estimate.FirstByteP95MS, estimate.FirstByteMS), 10000)
	}
	// Mirrors scoring.zig: only a finite positive throughput earns a cost
	// reduction; anything else is the neutral 0.60.
	throughputCost := 0.60
	if estimate.HasThroughput && estimate.ThroughputBPS > 0 &&
		!math.IsInf(estimate.ThroughputBPS, 1) && !math.IsNaN(estimate.ThroughputBPS) {
		speedUtility := math.Min(1, math.Log1p(estimate.ThroughputBPS)/math.Log1p(64*1024*1024))
		throughputCost = 1 - speedUtility
	}
	// Mirrors scoring.zig: jitter evidence is only valid when the same flow
	// produced a positive connect latency; a zero/sub-µs connect (possible
	// via µs truncation) leaves both costs at the unknown prior.
	jitterCost := 0.50
	if estimate.HasConnect && connectValue > 0 {
		jitterCost = math.Min(1, estimate.JitterMS/1000)
	}
	samples := estimate.Samples
	if math.IsNaN(samples) || math.IsInf(samples, 0) {
		samples = 0
	}
	confidenceCost := 0.0
	if samples < 3 {
		confidenceCost = math.Max(0, 1-samples/3)
	}
	reliability := estimate.Reliability
	if math.IsNaN(reliability) {
		reliability = 0.5
	}
	score := reliabilityWeight*(1-reliability) +
		connectWeight*connectCost +
		firstByteWeight*firstByteCost +
		throughputWeight*throughputCost +
		jitterWeight*jitterCost +
		confidenceWeight*confidenceCost
	if estimate.State == "half_open" {
		score += 0.20
	}
	// Mirrors scoring.zig: a candidate without samples pays the full
	// exploration budget; the sqrt decay only applies once it has evidence.
	if exploration > 0 {
		if samples > 0 && totalSamples > 0 {
			score -= exploration * math.Sqrt(math.Log(totalSamples+2)/(samples+1))
		} else {
			score -= exploration
		}
	}
	return math.Max(0, score)
}

// smartHealthTier enforces primary/backup semantics before latency ranking.
// A lower latency suspect line must not displace a healthy primary merely
// because its current sample is faster; hard failures still move the next
// eligible backup to the front immediately.
func smartHealthTier(state string) int {
	switch state {
	case "healthy":
		return 0
	case "warming", "unknown":
		return 1
	case "suspect":
		return 2
	case "half_open":
		return 3
	case "open":
		return 4
	default:
		return 2
	}
}

func smartTotalSamplesForBestTier(ranks []smartRank) float64 {
	bestTier := int(^uint(0) >> 1)
	for _, rank := range ranks {
		if !rank.eligible {
			continue
		}
		if tier := smartHealthTier(rank.status.State); tier < bestTier {
			bestTier = tier
		}
	}
	if bestTier == int(^uint(0)>>1) {
		return 0
	}
	var total float64
	for _, rank := range ranks {
		if rank.eligible && smartHealthTier(rank.status.State) == bestTier && rank.estimate.Samples > 0 {
			total += rank.estimate.Samples
		}
	}
	return total
}

// passiveThroughputBelowFloor is intentionally separate from probing. It is
// evaluated only from bytes observed on a real connection, so a candidate is
// never penalized merely because no bulk traffic has used it yet.
func passiveThroughputBelowFloor(estimate smartEstimate, floorBPS uint64, minSamples int) bool {
	if floorBPS == 0 || !estimate.HasThroughput || estimate.ThroughputBPS <= 0 {
		return false
	}
	if minSamples <= 0 {
		minSamples = 2
	}
	throughput := estimate.ThroughputBPS
	// Prefer the service-local EWMA whenever it has enough samples. A fast
	// global history must not hide a slow YouTube (or other bulk) service path.
	if estimate.LocalThroughputSamples >= float64(minSamples) && estimate.LocalThroughputBPS > 0 {
		throughput = estimate.LocalThroughputBPS
	}
	return estimate.ThroughputSamples >= float64(minSamples) && throughput < float64(floorBPS)
}

// normalizedLogCost mirrors scoring.zig normalizedCost: a missing, negative
// or non-finite value is an unknown cost (0.5), infinity saturates at 1, and
// positive values are log1p-normalized. Returning 0 for unknowns (the old
// behavior) made an unmeasured endpoint look free next to a measured one.
func normalizedLogCost(value, ceiling float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, -1) {
		return 0.5
	}
	if math.IsInf(value, 1) {
		return 1
	}
	if value <= 0 {
		return 0.5
	}
	return math.Min(1, math.Log1p(value)/math.Log1p(ceiling))
}

// smartRetransmitPenaltyMS follows Surge's useful intuition without making
// loss a hard circuit failure: one percent retransmitted bytes contributes
// roughly 50ms to the score, capped so a pathological socket cannot dominate
// all other evidence.
func smartRetransmitPenaltyMS(ratio float64) float64 {
	if ratio <= 0 || math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return 0
	}
	return math.Min(5000, ratio*5000)
}

// smartRetransmitPenaltyMSWithConfidence prevents one close-time TCP_INFO
// sample from outweighing a well-established portrait. Retransmit evidence is
// intentionally advisory: it reaches the score only after a bounded sample
// ramp, while the raw ratio remains available for diagnostics.
func smartRetransmitPenaltyMSWithConfidence(ratio, samples float64) float64 {
	penalty := smartRetransmitPenaltyMS(ratio)
	if penalty == 0 || samples >= 3 {
		return penalty
	}
	if samples <= 0 || math.IsNaN(samples) || math.IsInf(samples, 0) {
		return 0
	}
	return penalty * samples / 3
}

func blendValue(global, local, localWeight float64) float64 {
	return global*(1-localWeight) + local*localWeight
}

func blendOptional(global, local float64, hasGlobal, hasLocal bool, localWeight float64) float64 {
	switch {
	case hasGlobal && hasLocal:
		return blendValue(global, local, localWeight)
	case hasLocal:
		return local
	default:
		return global
	}
}

func strongerState(global, local string) string {
	priority := map[string]int{
		"unknown":   0,
		"healthy":   1,
		"warming":   2,
		"suspect":   3,
		"half_open": 4,
		"open":      5,
	}
	if priority[local] > priority[global] {
		return local
	}
	return global
}

func laterTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
