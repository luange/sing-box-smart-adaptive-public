package adaptive

import (
	"bytes"
	"container/heap"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrProbeTargetExpired       = errors.New("adaptive probe target snapshot is expired")
	ErrProbeTargetRollback      = errors.New("adaptive probe target generation is not newer")
	ErrProbeTargetUntrusted     = errors.New("adaptive probe target source is not trusted")
	ErrProbeTargetBackpressure  = errors.New("adaptive probe target catalog is full")
	ErrProbeRunBackpressure     = errors.New("adaptive probe aggregator pending capacity is full")
	ErrProbeRunTooLarge         = errors.New("adaptive probe run exceeds sample capacity")
	ErrProbeRunUnknown          = errors.New("adaptive probe run is unknown")
	ErrProbeSampleIdentity      = errors.New("adaptive probe sample identity mismatch")
	ErrProbeSampleTargetUnknown = errors.New("adaptive probe sample target is unknown")
)

type ProbeSuiteClass string

const (
	ProbeSuiteEndpointRecovery  ProbeSuiteClass = "endpoint_recovery"
	ProbeSuiteServiceCapability ProbeSuiteClass = "service_capability"
)

type ProbeCapability string

const (
	ProbeCapabilityEndpoint     ProbeCapability = "endpoint"
	ProbeCapabilityTLS          ProbeCapability = "tls"
	ProbeCapabilityAuthHTTP     ProbeCapability = "auth_http"
	ProbeCapabilityWebWAF       ProbeCapability = "web_waf"
	ProbeCapabilityHTTP         ProbeCapability = "http"
	ProbeCapabilityHTTP3        ProbeCapability = "http3"
	ProbeCapabilityRange        ProbeCapability = "range"
	ProbeCapabilityExitIdentity ProbeCapability = "exit_identity"
)

const minimumProbeTargetValidity = 30 * time.Second

type ProbeTargetID [16]byte

func (i ProbeTargetID) String() string { return hex.EncodeToString(i[:]) }

type ProbeByteRange struct {
	Start int64
	End   int64
}

func (r ProbeByteRange) Len() int64 {
	if r.Start < 0 || r.End < r.Start {
		return 0
	}
	return r.End - r.Start + 1
}

// redactedProbeURL deliberately refuses every fmt representation. Signed
// media URLs are bearer-like credentials and must not leak through %+v, logs,
// JSON status, or panic formatting.
type redactedProbeURL struct{ value string }

func (u redactedProbeURL) String() string   { return "<redacted-probe-url>" }
func (u redactedProbeURL) GoString() string { return "<redacted-probe-url>" }
func (u redactedProbeURL) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<redacted-probe-url>")
}

type ProbeTarget struct {
	ID                  ProbeTargetID
	Generation          uint64
	Host                string
	Capability          ProbeCapability
	RequireTLS          bool
	RequirePayload      bool
	Range               *ProbeByteRange
	ExpectedDigest      [32]byte
	HasDigest           bool
	RedirectHosts       []string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	secretURL           *redactedProbeURL
	secretHost          *redactedProbeURL
	secretRedirectHosts []*redactedProbeURL
}

type ProbeTargetDescriptor struct {
	ID             ProbeTargetID
	Generation     uint64
	Host           string
	Capability     ProbeCapability
	RequireTLS     bool
	RequirePayload bool
	Range          *ProbeByteRange
	HasDigest      bool
	RedirectHosts  []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

func NewProbeTarget(rawURL string, generation uint64, capability ProbeCapability, issuedAt, expiresAt time.Time, byteRange *ProbeByteRange, expectedDigest []byte) (ProbeTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return ProbeTarget{}, errors.New("adaptive probe target URL is invalid")
	}
	if generation == 0 || issuedAt.IsZero() || !expiresAt.After(issuedAt) {
		return ProbeTarget{}, errors.New("adaptive probe target lifetime is invalid")
	}
	// auth_http / web_waf are sealed: reject at construct time so signed
	// manifests cannot re-enable AI-style service probes that proved ineffective.
	if capability == ProbeCapabilityAuthHTTP || capability == ProbeCapabilityWebWAF {
		return ProbeTarget{}, errors.New("adaptive probe capability auth_http/web_waf is sealed and disabled")
	}
	if capability != ProbeCapabilityEndpoint && capability != ProbeCapabilityTLS && capability != ProbeCapabilityHTTP && capability != ProbeCapabilityHTTP3 && capability != ProbeCapabilityRange && capability != ProbeCapabilityExitIdentity {
		return ProbeTarget{}, errors.New("adaptive probe target capability is invalid")
	}
	if capability == ProbeCapabilityRange && (byteRange == nil || byteRange.Len() == 0) {
		return ProbeTarget{}, errors.New("adaptive range target requires a valid byte range")
	}
	digest := sha256.Sum256([]byte(rawURL))
	var id ProbeTargetID
	copy(id[:], digest[:len(id)])
	executionHost := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	target := ProbeTarget{
		ID: id, Generation: generation, Host: redactProbeHost(executionHost), Capability: capability,
		RequireTLS: strings.EqualFold(parsed.Scheme, "https"), RequirePayload: capability != ProbeCapabilityTLS && capability != ProbeCapabilityExitIdentity,
		Range: cloneProbeRange(byteRange), IssuedAt: issuedAt, ExpiresAt: expiresAt,
		secretURL: &redactedProbeURL{value: rawURL}, secretHost: &redactedProbeURL{value: executionHost},
	}
	if capability == ProbeCapabilityEndpoint {
		target.RequireTLS = false
		target.RequirePayload = false
	}
	if len(expectedDigest) > 0 {
		if len(expectedDigest) != sha256.Size {
			return ProbeTarget{}, errors.New("adaptive probe target digest length is invalid")
		}
		copy(target.ExpectedDigest[:], expectedDigest)
		target.HasDigest = true
	}
	return target, nil
}

func (t ProbeTarget) Descriptor() ProbeTargetDescriptor {
	return ProbeTargetDescriptor{
		ID: t.ID, Generation: t.Generation, Host: t.Host, Capability: t.Capability, RequireTLS: t.RequireTLS,
		RequirePayload: t.RequirePayload, Range: cloneProbeRange(t.Range), HasDigest: t.HasDigest,
		RedirectHosts: append([]string(nil), t.RedirectHosts...), IssuedAt: t.IssuedAt, ExpiresAt: t.ExpiresAt,
	}
}

func (t ProbeTarget) WithRedirectHosts(hosts ...string) (ProbeTarget, error) {
	cloned := cloneProbeTarget(t)
	seen := map[string]struct{}{t.executionHost(): {}}
	cloned.RedirectHosts = nil
	cloned.secretRedirectHosts = nil
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || strings.ContainsAny(host, "/:@?#") {
			return ProbeTarget{}, errors.New("adaptive probe redirect host is invalid")
		}
		if _, loaded := seen[host]; loaded {
			continue
		}
		seen[host] = struct{}{}
		cloned.RedirectHosts = append(cloned.RedirectHosts, redactProbeHost(host))
		cloned.secretRedirectHosts = append(cloned.secretRedirectHosts, &redactedProbeURL{value: host})
	}
	return cloned, nil
}

func redactProbeHost(host string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(host)))
	return "host-" + hex.EncodeToString(digest[:8])
}

func (t ProbeTarget) executionURL() string {
	if t.secretURL == nil {
		return ""
	}
	return t.secretURL.value
}

func (t ProbeTarget) executionHost() string {
	if t.secretHost == nil {
		return ""
	}
	return t.secretHost.value
}

func (t ProbeTarget) executionRedirectHosts() []string {
	result := make([]string, len(t.secretRedirectHosts))
	for index, host := range t.secretRedirectHosts {
		if host != nil {
			result[index] = host.value
		}
	}
	return result
}

func cloneProbeRange(source *ProbeByteRange) *ProbeByteRange {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

type ProbeTargetSnapshot struct {
	SourceID   string
	ServiceID  string
	Generation uint64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	targets    []ProbeTarget
}

func NewProbeTargetSnapshot(sourceID, serviceID string, generation uint64, issuedAt, expiresAt time.Time, targets []ProbeTarget) (*ProbeTargetSnapshot, error) {
	if sourceID == "" || serviceID == "" || generation == 0 || issuedAt.IsZero() || !expiresAt.After(issuedAt) || len(targets) == 0 {
		return nil, errors.New("adaptive probe target snapshot is invalid")
	}
	seen := make(map[ProbeTargetID]struct{}, len(targets))
	cloned := make([]ProbeTarget, len(targets))
	for index, target := range targets {
		if target.Generation != generation || target.IssuedAt.Before(issuedAt) || target.ExpiresAt.After(expiresAt) {
			return nil, errors.New("adaptive probe target is outside snapshot lifetime")
		}
		if _, loaded := seen[target.ID]; loaded {
			return nil, errors.New("adaptive probe target snapshot contains duplicate target")
		}
		seen[target.ID] = struct{}{}
		cloned[index] = cloneProbeTarget(target)
	}
	return &ProbeTargetSnapshot{SourceID: sourceID, ServiceID: serviceID, Generation: generation, IssuedAt: issuedAt, ExpiresAt: expiresAt, targets: cloned}, nil
}

func cloneProbeTarget(source ProbeTarget) ProbeTarget {
	cloned := source
	cloned.Range = cloneProbeRange(source.Range)
	cloned.RedirectHosts = append([]string(nil), source.RedirectHosts...)
	cloned.secretRedirectHosts = make([]*redactedProbeURL, len(source.secretRedirectHosts))
	for index, host := range source.secretRedirectHosts {
		if host != nil {
			cloned.secretRedirectHosts[index] = &redactedProbeURL{value: host.value}
		}
	}
	if source.secretURL != nil {
		cloned.secretURL = &redactedProbeURL{value: source.secretURL.value}
	}
	if source.secretHost != nil {
		cloned.secretHost = &redactedProbeURL{value: source.secretHost.value}
	}
	return cloned
}

func cloneProbeTargetSnapshot(source *ProbeTargetSnapshot) *ProbeTargetSnapshot {
	if source == nil {
		return nil
	}
	cloned := &ProbeTargetSnapshot{SourceID: source.SourceID, ServiceID: source.ServiceID, Generation: source.Generation, IssuedAt: source.IssuedAt, ExpiresAt: source.ExpiresAt, targets: make([]ProbeTarget, len(source.targets))}
	for index, target := range source.targets {
		cloned.targets[index] = cloneProbeTarget(target)
	}
	return cloned
}

func (s *ProbeTargetSnapshot) Targets() []ProbeTargetDescriptor {
	if s == nil {
		return nil
	}
	result := make([]ProbeTargetDescriptor, len(s.targets))
	for index, target := range s.targets {
		result[index] = target.Descriptor()
	}
	return result
}

func (s *ProbeTargetSnapshot) executionTargets(now time.Time) ([]ProbeTarget, error) {
	if s == nil || now.Before(s.IssuedAt) || s.ExpiresAt.Sub(now) < minimumProbeTargetValidity {
		return nil, ErrProbeTargetExpired
	}
	result := make([]ProbeTarget, len(s.targets))
	for index, target := range s.targets {
		if !probeTargetUsableAt(target, now) {
			return nil, ErrProbeTargetExpired
		}
		result[index] = cloneProbeTarget(target)
	}
	return result, nil
}

type ProbeTargetProvider interface {
	Snapshot(context.Context, string) (*ProbeTargetSnapshot, error)
}

type ProbeTargetCatalog struct {
	access         sync.RWMutex
	maxServices    int
	snapshots      map[string]*ProbeTargetSnapshot
	trustedSources map[string]struct{}
}

func NewProbeTargetCatalog(maxServices int, trustedSources ...string) *ProbeTargetCatalog {
	if maxServices <= 0 {
		maxServices = 64
	}
	trusted := make(map[string]struct{}, len(trustedSources))
	for _, source := range trustedSources {
		if source != "" {
			trusted[source] = struct{}{}
		}
	}
	return &ProbeTargetCatalog{maxServices: maxServices, snapshots: make(map[string]*ProbeTargetSnapshot), trustedSources: trusted}
}

func (c *ProbeTargetCatalog) Publish(snapshot *ProbeTargetSnapshot) error {
	if snapshot == nil {
		return errors.New("adaptive probe target snapshot is nil")
	}
	prepared := cloneProbeTargetSnapshot(snapshot)
	c.access.Lock()
	defer c.access.Unlock()
	if _, trusted := c.trustedSources[prepared.SourceID]; !trusted {
		return ErrProbeTargetUntrusted
	}
	current := c.snapshots[prepared.ServiceID]
	if current != nil && prepared.Generation <= current.Generation {
		return ErrProbeTargetRollback
	}
	if current == nil && len(c.snapshots) >= c.maxServices {
		return ErrProbeTargetBackpressure
	}
	c.snapshots[prepared.ServiceID] = prepared
	return nil
}

func probeTargetUsableAt(target ProbeTarget, now time.Time) bool {
	return target.Generation != 0 && !now.Before(target.IssuedAt) && target.ExpiresAt.Sub(now) >= minimumProbeTargetValidity
}

func (c *ProbeTargetCatalog) Snapshot(_ context.Context, serviceID string) (*ProbeTargetSnapshot, error) {
	c.access.RLock()
	snapshot := cloneProbeTargetSnapshot(c.snapshots[serviceID])
	c.access.RUnlock()
	if snapshot == nil {
		return nil, ErrProbeRunUnknown
	}
	return snapshot, nil
}

type ProbeRawResult struct {
	Canceled            bool
	TimedOut            bool
	ConnectFailed       bool
	ProtocolFailed      bool
	EndpointHandshakeOK bool
	TLSHandshakeOK      bool
	TargetPolicyErr     bool
	WAFChallenge        bool
	StatusCode          int
	ContentRange        string
	ContentType         string
	BytesRead           int64
	PayloadPrefix       []byte
	Digest              [32]byte
	HasDigest           bool
	Delay               time.Duration
	identityToken       exitIdentityToken
	hasIdentityToken    bool
	identityChanged     bool
}

type ProbeSampleClass string

const (
	ProbeSampleSuccess     ProbeSampleClass = "success"
	ProbeSampleBlocked     ProbeSampleClass = "blocked"
	ProbeSampleNodeFailure ProbeSampleClass = "node_failure"
	ProbeSampleTargetFault ProbeSampleClass = "target_fault"
	ProbeSampleDeferred    ProbeSampleClass = "deferred"
)

type ProbeSampleClassification struct {
	Class   ProbeSampleClass
	Failure FailureClass
}

func ClassifyProbeResult(target ProbeTarget, raw ProbeRawResult, now time.Time) ProbeSampleClassification {
	if !probeTargetUsableAt(target, now) {
		return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
	}
	if raw.Canceled {
		return ProbeSampleClassification{Class: ProbeSampleDeferred, Failure: FailureCanceled}
	}
	if raw.TargetPolicyErr {
		return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
	}
	if raw.TimedOut {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureTimeout}
	}
	if raw.ConnectFailed {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureConnect}
	}
	if raw.ProtocolFailed {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureProtocol}
	}
	if target.Capability == ProbeCapabilityEndpoint {
		if raw.EndpointHandshakeOK {
			return ProbeSampleClassification{Class: ProbeSampleSuccess, Failure: FailureNone}
		}
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureProtocol}
	}
	if target.RequireTLS && !raw.TLSHandshakeOK {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureTLS}
	}
	if target.Capability == ProbeCapabilityTLS {
		return ProbeSampleClassification{Class: ProbeSampleSuccess, Failure: FailureNone}
	}
	if target.Capability == ProbeCapabilityExitIdentity {
		if !raw.hasIdentityToken {
			return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
		}
		if raw.identityChanged {
			return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureIdentity}
		}
		return ProbeSampleClassification{Class: ProbeSampleSuccess, Failure: FailureNone}
	}
	// auth_http / web_waf are sealed at NewProbeTarget; no classifier branches.
	switch raw.StatusCode {
	case http.StatusForbidden, http.StatusUnavailableForLegalReasons:
		return ProbeSampleClassification{Class: ProbeSampleBlocked, Failure: FailureHTTPBlock}
	case http.StatusNotFound, http.StatusGone, http.StatusTooManyRequests:
		return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
	}
	if raw.StatusCode >= 500 || raw.StatusCode >= 300 && raw.StatusCode < 400 || raw.StatusCode == 0 {
		return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
	}
	if target.Capability == ProbeCapabilityRange {
		if raw.StatusCode != http.StatusPartialContent || target.Range == nil || !contentRangeMatches(raw.ContentRange, *target.Range) {
			return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
		}
		if raw.BytesRead != target.Range.Len() {
			return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureNoPayload}
		}
	} else if raw.StatusCode < 200 || raw.StatusCode >= 300 {
		return ProbeSampleClassification{Class: ProbeSampleTargetFault, Failure: FailureProtocol}
	}
	if target.RequirePayload && raw.BytesRead <= 0 {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureNoPayload}
	}
	if strings.Contains(strings.ToLower(raw.ContentType), "text/html") || looksLikeHTML(raw.PayloadPrefix) {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureProtocol}
	}
	if target.HasDigest && (!raw.HasDigest || raw.Digest != target.ExpectedDigest) {
		return ProbeSampleClassification{Class: ProbeSampleNodeFailure, Failure: FailureProtocol}
	}
	return ProbeSampleClassification{Class: ProbeSampleSuccess, Failure: FailureNone}
}

func contentRangeMatches(value string, expected ProbeByteRange) bool {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bytes") {
		return false
	}
	parts := strings.Split(fields[1], "/")
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	bounds := strings.Split(parts[0], "-")
	if len(bounds) != 2 {
		return false
	}
	start, err := strconv.ParseInt(bounds[0], 10, 64)
	if err != nil {
		return false
	}
	end, err := strconv.ParseInt(bounds[1], 10, 64)
	return err == nil && start == expected.Start && end == expected.End
}

func looksLikeHTML(prefix []byte) bool {
	trimmed := strings.ToLower(strings.TrimSpace(string(prefix)))
	return strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html")
}

type ProbeSuiteRunID uint64

type ProbeRunSpec struct {
	RunID              ProbeSuiteRunID
	Class              ProbeSuiteClass
	RuntimeEpochID     RuntimeEpochID
	CatalogRevision    CatalogRevision
	SourceGeneration   uint64
	ServiceID          string
	Source             ObservationSource
	TargetGeneration   uint64
	Nodes              []NodeHandle
	Targets            []ProbeTargetDescriptor
	Quorum             int
	CommonModeMinNodes int
	Deadline           time.Time
}

type ProbeSample struct {
	RunID            ProbeSuiteRunID
	Suite            ProbeSuiteClass
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
	Handle           NodeHandle
	TargetID         ProbeTargetID
	TargetGeneration uint64
	ServiceID        string
	Capability       ProbeCapability
	Class            ProbeSampleClass
	Failure          FailureClass
	HTTPStatus       int
	BytesRead        int64
	ContentRange     string
	Delay            time.Duration
	At               time.Time
}

type ProbeVerdict struct {
	RunID            ProbeSuiteRunID
	Suite            ProbeSuiteClass
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
	Handle           NodeHandle
	Domain           FailureDomain
	ServiceID        string
	Source           ObservationSource
	Outcome          ObservationOutcome
	Failure          FailureClass
	Confidence       ObservationConfidence
	BreakerEligible  bool
	Authoritative    bool
	Support          int
}

type ProbeCommonModeIncident struct {
	RunID    ProbeSuiteRunID
	TargetID ProbeTargetID
	Class    ProbeSampleClass
	Nodes    int
}

type ProbeRunResult struct {
	RunID     ProbeSuiteRunID
	Verdicts  []ProbeVerdict
	Incidents []ProbeCommonModeIncident
	Completed time.Time
}

type ProbeAggregateDisposition string

const (
	ProbeAggregateAccepted     ProbeAggregateDisposition = "accepted"
	ProbeAggregateDuplicate    ProbeAggregateDisposition = "duplicate"
	ProbeAggregateLate         ProbeAggregateDisposition = "late"
	ProbeAggregateStale        ProbeAggregateDisposition = "stale"
	ProbeAggregateBackpressure ProbeAggregateDisposition = "backpressure"
)

type ProbeSampleGuard interface {
	ValidateProbeSample(ProbeSample) bool
}

type ProbeAggregatorConfig struct {
	MaxPendingRuns   int
	MaxCommittedRuns int
	MaxSamplesPerRun int
	Retention        time.Duration
}

type probeSampleKey struct {
	handle NodeHandle
	target ProbeTargetID
}

type aggregateProbeRun struct {
	spec       ProbeRunSpec
	startedAt  time.Time
	nodes      map[NodeHandle]struct{}
	targets    map[ProbeTargetID]ProbeTargetDescriptor
	samples    map[probeSampleKey]ProbeSample
	deadlineID uint64
	deadline   *probeDeadline
}

type committedProbeRun struct {
	result    ProbeRunResult
	expiresAt time.Time
	element   *list.Element
}

type probeDeadline struct {
	runID ProbeSuiteRunID
	at    time.Time
	id    uint64
	index int
}

type probeDeadlineHeap []*probeDeadline

func (h probeDeadlineHeap) Len() int           { return len(h) }
func (h probeDeadlineHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h probeDeadlineHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *probeDeadlineHeap) Push(value any) {
	item := value.(*probeDeadline)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *probeDeadlineHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	last.index = -1
	return last
}

type ProbeAggregator struct {
	access    sync.Mutex
	clock     Clock
	guard     ProbeSampleGuard
	config    ProbeAggregatorConfig
	pending   map[ProbeSuiteRunID]*aggregateProbeRun
	committed map[ProbeSuiteRunID]*committedProbeRun
	order     list.List
	deadlines probeDeadlineHeap
	nextID    uint64
}

func NewProbeAggregator(config ProbeAggregatorConfig, clock Clock, guard ProbeSampleGuard) *ProbeAggregator {
	if config.MaxPendingRuns <= 0 {
		config.MaxPendingRuns = 128
	}
	if config.MaxCommittedRuns <= 0 {
		config.MaxCommittedRuns = 256
	}
	if config.MaxSamplesPerRun <= 0 {
		config.MaxSamplesPerRun = 4096
	}
	if config.Retention <= 0 {
		config.Retention = 10 * time.Minute
	}
	if clock == nil {
		clock = realClock{}
	}
	return &ProbeAggregator{clock: clock, guard: guard, config: config, pending: make(map[ProbeSuiteRunID]*aggregateProbeRun), committed: make(map[ProbeSuiteRunID]*committedProbeRun)}
}

func (a *ProbeAggregator) Begin(spec ProbeRunSpec) (ProbeAggregateDisposition, error) {
	now := a.clock.Now()
	if err := validateProbeRunSpec(spec, a.config.MaxSamplesPerRun, now); err != nil {
		return "", err
	}
	a.access.Lock()
	defer a.access.Unlock()
	a.expireLocked(now)
	if a.pending[spec.RunID] != nil || a.committed[spec.RunID] != nil {
		return ProbeAggregateDuplicate, nil
	}
	if len(a.pending) >= a.config.MaxPendingRuns {
		return ProbeAggregateBackpressure, ErrProbeRunBackpressure
	}
	run := &aggregateProbeRun{spec: cloneProbeRunSpec(spec), startedAt: now, nodes: make(map[NodeHandle]struct{}, len(spec.Nodes)), targets: make(map[ProbeTargetID]ProbeTargetDescriptor, len(spec.Targets)), samples: make(map[probeSampleKey]ProbeSample)}
	for _, node := range spec.Nodes {
		run.nodes[node] = struct{}{}
	}
	for _, target := range spec.Targets {
		run.targets[target.ID] = cloneProbeTargetDescriptor(target)
	}
	a.nextID++
	run.deadlineID = a.nextID
	run.deadline = &probeDeadline{runID: spec.RunID, at: spec.Deadline, id: run.deadlineID, index: -1}
	a.pending[spec.RunID] = run
	heap.Push(&a.deadlines, run.deadline)
	return ProbeAggregateAccepted, nil
}

func validateProbeRunSpec(spec ProbeRunSpec, maxSamples int, now time.Time) error {
	if spec.RunID == 0 || spec.RuntimeEpochID == 0 || spec.CatalogRevision == 0 || spec.SourceGeneration == 0 || spec.TargetGeneration == 0 || spec.Deadline.IsZero() || len(spec.Nodes) == 0 || len(spec.Targets) == 0 {
		return errors.New("adaptive probe run identity is incomplete")
	}
	if spec.Class != ProbeSuiteEndpointRecovery && spec.Class != ProbeSuiteServiceCapability {
		return errors.New("adaptive probe suite class is invalid")
	}
	if spec.Class == ProbeSuiteServiceCapability && spec.ServiceID == "" || spec.Class == ProbeSuiteEndpointRecovery && spec.ServiceID != "" {
		return errors.New("adaptive probe suite service scope is invalid")
	}
	if spec.Class == ProbeSuiteEndpointRecovery && spec.Source != SourceProbe {
		return errors.New("adaptive endpoint suite requires probe source")
	}
	if spec.Class == ProbeSuiteServiceCapability && spec.Source != SourceHTTP && spec.Source != SourceTLS {
		return errors.New("adaptive service suite requires HTTP or TLS source")
	}
	if spec.Quorum <= 0 || spec.Quorum > len(spec.Targets) {
		return errors.New("adaptive probe quorum is invalid")
	}
	if !spec.Deadline.After(now) {
		return errors.New("adaptive probe run deadline has passed")
	}
	if len(spec.Nodes) > maxSamples || len(spec.Targets) > maxSamples/len(spec.Nodes) {
		return ErrProbeRunTooLarge
	}
	seenNodes := make(map[NodeHandle]struct{}, len(spec.Nodes))
	for _, node := range spec.Nodes {
		if node.NodeID == (NodeID{}) || node.Slot == 0 || node.Version == 0 {
			return ErrProbeSampleIdentity
		}
		if _, loaded := seenNodes[node]; loaded {
			return errors.New("adaptive probe run contains duplicate node")
		}
		seenNodes[node] = struct{}{}
	}
	seenTargets := make(map[ProbeTargetID]struct{}, len(spec.Targets))
	for _, target := range spec.Targets {
		if target.Generation != spec.TargetGeneration || target.ID == (ProbeTargetID{}) {
			return ErrProbeSampleTargetUnknown
		}
		if now.Before(target.IssuedAt) || target.ExpiresAt.Sub(spec.Deadline) < minimumProbeTargetValidity {
			return ErrProbeTargetExpired
		}
		if spec.Class == ProbeSuiteEndpointRecovery && target.Capability != ProbeCapabilityEndpoint || spec.Class == ProbeSuiteServiceCapability && target.Capability == ProbeCapabilityEndpoint {
			return errors.New("adaptive probe target capability is incompatible with suite")
		}
		if _, loaded := seenTargets[target.ID]; loaded {
			return errors.New("adaptive probe run contains duplicate target")
		}
		seenTargets[target.ID] = struct{}{}
	}
	return nil
}

func cloneProbeRunSpec(source ProbeRunSpec) ProbeRunSpec {
	cloned := source
	cloned.Nodes = append([]NodeHandle(nil), source.Nodes...)
	cloned.Targets = make([]ProbeTargetDescriptor, len(source.Targets))
	for index, target := range source.Targets {
		cloned.Targets[index] = cloneProbeTargetDescriptor(target)
	}
	return cloned
}

func cloneProbeTargetDescriptor(source ProbeTargetDescriptor) ProbeTargetDescriptor {
	cloned := source
	cloned.Range = cloneProbeRange(source.Range)
	cloned.RedirectHosts = append([]string(nil), source.RedirectHosts...)
	return cloned
}

func (a *ProbeAggregator) Ingest(sample ProbeSample) (ProbeAggregateDisposition, error) {
	now := a.clock.Now()
	a.access.Lock()
	defer a.access.Unlock()
	a.expireLocked(now)
	run := a.pending[sample.RunID]
	if run == nil {
		if a.committed[sample.RunID] != nil {
			return ProbeAggregateLate, nil
		}
		return ProbeAggregateStale, ErrProbeRunUnknown
	}
	if !sampleIdentityMatches(run, sample) || a.guard != nil && !a.guard.ValidateProbeSample(sample) {
		return ProbeAggregateStale, ErrProbeSampleIdentity
	}
	key := probeSampleKey{handle: sample.Handle, target: sample.TargetID}
	if _, loaded := run.samples[key]; loaded {
		return ProbeAggregateDuplicate, nil
	}
	if len(run.samples) >= a.config.MaxSamplesPerRun {
		return ProbeAggregateBackpressure, ErrProbeRunBackpressure
	}
	run.samples[key] = sample
	return ProbeAggregateAccepted, nil
}

func sampleIdentityMatches(run *aggregateProbeRun, sample ProbeSample) bool {
	if sample.Suite != run.spec.Class || sample.ServiceID != run.spec.ServiceID || sample.RuntimeEpochID != run.spec.RuntimeEpochID || sample.CatalogRevision != run.spec.CatalogRevision || sample.SourceGeneration != run.spec.SourceGeneration || sample.TargetGeneration != run.spec.TargetGeneration || sample.At.IsZero() || sample.At.Before(run.startedAt) || sample.At.After(run.spec.Deadline) {
		return false
	}
	if _, loaded := run.nodes[sample.Handle]; !loaded {
		return false
	}
	target, loaded := run.targets[sample.TargetID]
	if !loaded || sample.Capability != target.Capability {
		return false
	}
	if run.spec.Class == ProbeSuiteEndpointRecovery && (sample.Class == ProbeSampleBlocked || sample.Failure == FailureTLS || sample.Failure == FailureHTTPBlock) {
		return false
	}
	switch sample.Class {
	case ProbeSampleSuccess:
		return sample.Failure == FailureNone
	case ProbeSampleBlocked:
		return sample.Failure == FailureHTTPBlock
	case ProbeSampleNodeFailure, ProbeSampleTargetFault:
		return sample.Failure != FailureNone && sample.Failure != FailureCanceled
	case ProbeSampleDeferred:
		return sample.Failure == FailureNone || sample.Failure == FailureCanceled
	default:
		return false
	}
}

func (a *ProbeAggregator) Complete(runID ProbeSuiteRunID) (ProbeRunResult, error) {
	now := a.clock.Now()
	a.access.Lock()
	defer a.access.Unlock()
	a.expireLocked(now)
	if record := a.committed[runID]; record != nil {
		return cloneProbeRunResult(record.result), nil
	}
	run := a.pending[runID]
	if run == nil {
		return ProbeRunResult{}, ErrProbeRunUnknown
	}
	return cloneProbeRunResult(a.commitLocked(run, now)), nil
}

func (a *ProbeAggregator) Abort(runID ProbeSuiteRunID) {
	a.access.Lock()
	run := a.pending[runID]
	if run != nil {
		delete(a.pending, runID)
		if run.deadline != nil && run.deadline.index >= 0 {
			heap.Remove(&a.deadlines, run.deadline.index)
		}
	}
	a.access.Unlock()
}

func (a *ProbeAggregator) Result(runID ProbeSuiteRunID) (ProbeRunResult, bool) {
	now := a.clock.Now()
	a.access.Lock()
	a.expireLocked(now)
	record := a.committed[runID]
	var result ProbeRunResult
	if record != nil {
		result = cloneProbeRunResult(record.result)
	}
	a.access.Unlock()
	return result, record != nil
}

func (a *ProbeAggregator) Stats() (pending, committed int) {
	a.access.Lock()
	a.expireLocked(a.clock.Now())
	pending, committed = len(a.pending), len(a.committed)
	a.access.Unlock()
	return
}

func (a *ProbeAggregator) expireLocked(now time.Time) {
	for a.deadlines.Len() > 0 {
		item := a.deadlines[0]
		if item.at.After(now) {
			break
		}
		heap.Pop(&a.deadlines)
		run := a.pending[item.runID]
		if run != nil && run.deadlineID == item.id {
			a.commitLocked(run, now)
		}
	}
	for element := a.order.Back(); element != nil; {
		record := element.Value.(*committedProbeRun)
		if now.Before(record.expiresAt) {
			break
		}
		previous := element.Prev()
		delete(a.committed, record.result.RunID)
		a.order.Remove(element)
		element = previous
	}
}

func (a *ProbeAggregator) commitLocked(run *aggregateProbeRun, now time.Time) ProbeRunResult {
	delete(a.pending, run.spec.RunID)
	if run.deadline != nil && run.deadline.index >= 0 {
		heap.Remove(&a.deadlines, run.deadline.index)
	}
	result := aggregateProbeVerdicts(run, now)
	record := &committedProbeRun{result: result, expiresAt: now.Add(a.config.Retention)}
	record.element = a.order.PushFront(record)
	a.committed[result.RunID] = record
	for len(a.committed) > a.config.MaxCommittedRuns {
		element := a.order.Back()
		oldest := element.Value.(*committedProbeRun)
		delete(a.committed, oldest.result.RunID)
		a.order.Remove(element)
	}
	return result
}

func aggregateProbeVerdicts(run *aggregateProbeRun, now time.Time) ProbeRunResult {
	commonMin := run.spec.CommonModeMinNodes
	if commonMin <= 0 {
		commonMin = 2
	}
	// A fixed small threshold is unsafe for large pools: two blocked nodes in a
	// 16-node pool are useful per-node evidence, not a target-wide incident.
	// Preserve the configured floor for small pools, but require a strict
	// majority before suppressing a target across the whole run.
	if strictMajority := len(run.nodes)/2 + 1; commonMin < strictMajority {
		commonMin = strictMajority
	}
	excluded := make(map[ProbeTargetID]ProbeCommonModeIncident)
	for targetID := range run.targets {
		classes := make(map[ProbeSampleClass]map[NodeHandle]struct{})
		for key, sample := range run.samples {
			if key.target != targetID || sample.Class == ProbeSampleSuccess || sample.Class == ProbeSampleDeferred {
				continue
			}
			if sample.Class == ProbeSampleTargetFault {
				excluded[targetID] = ProbeCommonModeIncident{RunID: run.spec.RunID, TargetID: targetID, Class: sample.Class, Nodes: 1}
				break
			}
			if classes[sample.Class] == nil {
				classes[sample.Class] = make(map[NodeHandle]struct{})
			}
			classes[sample.Class][sample.Handle] = struct{}{}
		}
		if _, loaded := excluded[targetID]; loaded {
			continue
		}
		for class, nodes := range classes {
			if len(nodes) >= commonMin {
				excluded[targetID] = ProbeCommonModeIncident{RunID: run.spec.RunID, TargetID: targetID, Class: class, Nodes: len(nodes)}
				break
			}
		}
	}
	result := ProbeRunResult{RunID: run.spec.RunID, Completed: now}
	for _, incident := range excluded {
		result.Incidents = append(result.Incidents, incident)
	}
	sort.Slice(result.Incidents, func(i, j int) bool {
		return bytes.Compare(result.Incidents[i].TargetID[:], result.Incidents[j].TargetID[:]) < 0
	})
	for node := range run.nodes {
		counts := make(map[ProbeSampleClass]int)
		failures := make(map[ProbeSampleClass]map[FailureClass]int)
		for targetID := range run.targets {
			if _, ignored := excluded[targetID]; ignored {
				continue
			}
			sample, loaded := run.samples[probeSampleKey{handle: node, target: targetID}]
			if !loaded || sample.Class == ProbeSampleDeferred || sample.Class == ProbeSampleTargetFault {
				continue
			}
			counts[sample.Class]++
			if sample.Failure != FailureNone {
				if failures[sample.Class] == nil {
					failures[sample.Class] = make(map[FailureClass]int)
				}
				failures[sample.Class][sample.Failure]++
			}
		}
		verdict := ProbeVerdict{
			RunID: run.spec.RunID, Suite: run.spec.Class, RuntimeEpochID: run.spec.RuntimeEpochID, CatalogRevision: run.spec.CatalogRevision,
			SourceGeneration: run.spec.SourceGeneration, Handle: node, ServiceID: run.spec.ServiceID, Source: run.spec.Source, Outcome: OutcomeDeferred,
		}
		if run.spec.Class == ProbeSuiteEndpointRecovery {
			verdict.Domain = DomainEndpoint
		} else {
			verdict.Domain = DomainService
		}
		winning := ProbeSampleClass("")
		winners := 0
		candidateClasses := []ProbeSampleClass{ProbeSampleSuccess, ProbeSampleBlocked, ProbeSampleNodeFailure}
		if run.spec.Class == ProbeSuiteEndpointRecovery {
			candidateClasses = []ProbeSampleClass{ProbeSampleSuccess, ProbeSampleNodeFailure}
		}
		for _, class := range candidateClasses {
			if counts[class] >= run.spec.Quorum {
				winning = class
				winners++
			}
		}
		if winners == 1 {
			verdict.Authoritative = true
			verdict.Confidence = ConfidenceAuthoritative
			verdict.BreakerEligible = true
			verdict.Support = counts[winning]
			switch winning {
			case ProbeSampleSuccess:
				verdict.Outcome = OutcomeSuccess
			case ProbeSampleBlocked:
				verdict.Outcome, verdict.Failure = OutcomeBlocked, FailureHTTPBlock
			case ProbeSampleNodeFailure:
				verdict.Outcome, verdict.Failure = OutcomeFailure, majorityFailure(failures[ProbeSampleNodeFailure])
			}
		}
		// Below-quorum samples are dropped: soft/partial capability feedback was
		// complex, noisy in production, and not used for selection. Authoritative
		// quorum only.
		result.Verdicts = append(result.Verdicts, verdict)
	}
	sort.Slice(result.Verdicts, func(i, j int) bool {
		if compared := bytes.Compare(result.Verdicts[i].Handle.NodeID[:], result.Verdicts[j].Handle.NodeID[:]); compared != 0 {
			return compared < 0
		}
		if result.Verdicts[i].Handle.Slot != result.Verdicts[j].Handle.Slot {
			return result.Verdicts[i].Handle.Slot < result.Verdicts[j].Handle.Slot
		}
		return result.Verdicts[i].Handle.Version < result.Verdicts[j].Handle.Version
	})
	return result
}

func majorityFailure(counts map[FailureClass]int) FailureClass {
	selected := FailureProtocol
	best := -1
	for failure, count := range counts {
		if count > best || count == best && failure < selected {
			selected, best = failure, count
		}
	}
	return selected
}

func cloneProbeRunResult(source ProbeRunResult) ProbeRunResult {
	cloned := source
	cloned.Verdicts = append([]ProbeVerdict(nil), source.Verdicts...)
	cloned.Incidents = append([]ProbeCommonModeIncident(nil), source.Incidents...)
	return cloned
}

// ProbeObservationSink is intentionally expressed in ObservationEvidence,
// not HealthStore mutations. Production wiring must implement it with the
// shared ObservationIngestor and reducer transaction.
type ProbeObservationSink interface {
	PublishProbeObservation(context.Context, ObservationEvidence) (IngestDisposition, error)
}

func (v ProbeVerdict) Observation(at time.Time) (ObservationEvidence, error) {
	if !v.Authoritative || !v.BreakerEligible || v.Confidence != ConfidenceAuthoritative || v.RunID == 0 {
		return ObservationEvidence{}, errors.New("adaptive probe verdict is not authoritative")
	}
	stage := StageServiceApplication
	if v.Domain == DomainEndpoint {
		stage = StageProxyTunnel
	} else if v.Domain != DomainService || v.ServiceID == "" {
		return ObservationEvidence{}, errors.New("adaptive probe verdict has invalid failure domain")
	}
	evidence := ObservationEvidence{
		RuntimeEpochID: v.RuntimeEpochID, CatalogRevision: v.CatalogRevision, SourceGeneration: v.SourceGeneration,
		Handle: v.Handle, Source: v.Source, Stage: stage, Failure: v.Failure, Confidence: v.Confidence, Outcome: v.Outcome,
		ServiceID: v.ServiceID, Transport: "tcp", AttemptID: AttemptID(v.RunID), At: at,
	}
	if err := evidence.ValidateShape(); err != nil {
		return ObservationEvidence{}, err
	}
	return evidence, nil
}

func PublishProbeRunResult(ctx context.Context, result ProbeRunResult, sink ProbeObservationSink) error {
	if sink == nil {
		return errors.New("adaptive probe observation sink is nil")
	}
	for _, verdict := range result.Verdicts {
		if !verdict.Authoritative {
			continue
		}
		evidence, err := verdict.Observation(result.Completed)
		if err != nil {
			return err
		}
		if _, err = sink.PublishProbeObservation(ctx, evidence); err != nil {
			return err
		}
	}
	return nil
}
