package adaptive

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ObservationSource string

const (
	SourceDial       ObservationSource = "dial"
	SourceTLS        ObservationSource = "tls"
	SourceDNS        ObservationSource = "dns"
	SourceFirstByte  ObservationSource = "first_byte"
	SourceHTTP       ObservationSource = "http"
	SourceUDP        ObservationSource = "udp"
	SourceProbe      ObservationSource = "probe"
	SourceThroughput ObservationSource = "throughput"
)

type ObservationStage string

const (
	StageProxyTunnel          ObservationStage = "proxy_tunnel"
	StageDestinationTransport ObservationStage = "destination_transport"
	StageServiceApplication   ObservationStage = "service_application"
	StageResolverBootstrap    ObservationStage = "resolver_bootstrap"
	StageBusinessDNS          ObservationStage = "business_dns"
	StageDNSHealth            ObservationStage = "dns_health"
)

type FailureClass string

const (
	FailureNone      FailureClass = ""
	FailureDNS       FailureClass = "dns"
	FailureConnect   FailureClass = "connect"
	FailureTimeout   FailureClass = "timeout"
	FailureTLS       FailureClass = "tls"
	FailureProtocol  FailureClass = "protocol"
	FailureHTTPBlock FailureClass = "http_block"
	FailureNoPayload FailureClass = "no_payload"
	FailureIdentity  FailureClass = "identity_changed"
	FailureCanceled  FailureClass = "canceled"
)

type ObservationConfidence uint8

const (
	ConfidenceLow           ObservationConfidence = 25
	ConfidenceMedium        ObservationConfidence = 60
	ConfidenceHigh          ObservationConfidence = 90
	ConfidenceAuthoritative ObservationConfidence = 100
)

type AttemptID uint64

type ObservationEvidence struct {
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
	Handle           NodeHandle
	Source           ObservationSource
	Stage            ObservationStage
	Failure          FailureClass
	Confidence       ObservationConfidence
	Outcome          ObservationOutcome
	ServiceID        string
	Transport        string
	NetworkPath      string
	AttemptID        AttemptID
	Delay            time.Duration
	ThroughputBPS    float64
	At               time.Time
	Reason           string
}

type DomainEvidence struct {
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
	Handle           NodeHandle
	Domain           FailureDomain
	Outcome          ObservationOutcome
	Failure          FailureClass
	Confidence       ObservationConfidence
	AttemptID        AttemptID
	BreakerEligible  bool
	Weight           float64
}

// ValidateShape validates semantic evidence independently from runtime
// identity. Mapping tests can use it with zero generation/attempt values.
func (e ObservationEvidence) ValidateShape() error {
	switch e.Source {
	case SourceDial, SourceTLS, SourceDNS, SourceFirstByte, SourceHTTP, SourceUDP, SourceProbe, SourceThroughput:
	default:
		return errors.New("adaptive observation has unknown source")
	}
	switch e.Stage {
	case StageProxyTunnel, StageDestinationTransport, StageServiceApplication, StageResolverBootstrap, StageBusinessDNS, StageDNSHealth:
	default:
		return errors.New("adaptive observation has unknown stage")
	}
	if e.Transport != "tcp" && e.Transport != "udp" {
		return errors.New("adaptive observation has unknown transport")
	}
	if e.NetworkPath != "" && e.NetworkPath != "tcp/any" && e.NetworkPath != "tcp/ipv4" && e.NetworkPath != "tcp/ipv6" && e.NetworkPath != "udp_dns/any" && e.NetworkPath != "udp_dns/ipv4" && e.NetworkPath != "udp_dns/ipv6" && e.NetworkPath != "udp_data/any" && e.NetworkPath != "udp_data/ipv4" && e.NetworkPath != "udp_data/ipv6" {
		return errors.New("adaptive observation has unknown network path")
	}
	if e.Confidence != ConfidenceLow && e.Confidence != ConfidenceMedium && e.Confidence != ConfidenceHigh && e.Confidence != ConfidenceAuthoritative {
		return errors.New("adaptive observation has unsupported confidence")
	}
	if e.Outcome == OutcomeDeferred || e.Failure == FailureCanceled {
		if e.Outcome != OutcomeDeferred || e.Failure != FailureCanceled {
			return errors.New("canceled observation must be deferred")
		}
		return nil
	}
	if e.Outcome != OutcomeSuccess && e.Outcome != OutcomeFailure && e.Outcome != OutcomeBlocked {
		return errors.New("adaptive observation has invalid outcome")
	}
	if e.Outcome == OutcomeSuccess && e.Failure != FailureNone {
		return errors.New("successful adaptive observation cannot contain failure class")
	}
	if (e.Outcome == OutcomeFailure || e.Outcome == OutcomeBlocked) && e.Failure == FailureNone {
		return errors.New("failed adaptive observation requires failure class")
	}
	if (e.Stage == StageServiceApplication || e.Stage == StageBusinessDNS) && e.ServiceID == "" {
		return errors.New("business observation requires service id")
	}
	if (e.Source == SourceFirstByte || e.Source == SourceHTTP) && (e.Stage != StageServiceApplication || e.ServiceID == "") {
		return errors.New("business source requires service application stage and service id")
	}
	if e.Source == SourceThroughput {
		if e.Stage != StageServiceApplication || e.ServiceID == "" || e.Outcome != OutcomeSuccess || e.Failure != FailureNone || e.Confidence != ConfidenceMedium || e.ThroughputBPS <= 0 {
			return errors.New("throughput observation is invalid")
		}
	} else if e.ThroughputBPS != 0 {
		return errors.New("non-throughput observation contains throughput")
	}
	switch e.Source {
	case SourceDNS:
		if e.Stage != StageResolverBootstrap && e.Stage != StageBusinessDNS && e.Stage != StageDNSHealth {
			return errors.New("dns source has incompatible stage")
		}
	case SourceHTTP, SourceFirstByte, SourceThroughput:
		if e.Stage != StageServiceApplication {
			return errors.New("business source has incompatible stage")
		}
	case SourceUDP:
		if e.Stage != StageServiceApplication && e.Stage != StageDestinationTransport {
			return errors.New("UDP source has incompatible stage")
		}
	case SourceDial:
		if e.Stage != StageProxyTunnel && e.Stage != StageDestinationTransport {
			return errors.New("dial source has incompatible stage")
		}
	case SourceTLS:
		if e.Stage != StageProxyTunnel && e.Stage != StageDestinationTransport && e.Stage != StageServiceApplication {
			return errors.New("tls source has incompatible stage")
		}
	case SourceProbe:
		if e.Stage != StageProxyTunnel {
			return errors.New("probe source has incompatible stage")
		}
	}
	if e.Source == SourceProbe && e.Stage != StageProxyTunnel {
		return errors.New("generic probe is limited to proxy tunnel evidence")
	}
	if e.Source == SourceProbe && e.ServiceID != "" {
		return errors.New("generic probe cannot claim service evidence")
	}
	return nil
}

func (e ObservationEvidence) MapDomains() ([]DomainEvidence, error) {
	if err := e.ValidateShape(); err != nil {
		return nil, err
	}
	if e.Outcome == OutcomeDeferred {
		return nil, nil
	}
	weight, breakerEligible := confidencePolicy(e.Confidence)
	domain := DomainTransport
	switch e.Stage {
	case StageProxyTunnel:
		domain = DomainEndpoint
	case StageDestinationTransport, StageResolverBootstrap, StageDNSHealth:
		domain = DomainTransport
	case StageServiceApplication, StageBusinessDNS:
		domain = DomainService
	}
	// Bootstrap resolver evidence is useful for quality diagnostics but must
	// never open a node breaker. Generic medium probes also cannot open or close
	// endpoint half-open; only high/authoritative active evidence may do so.
	if e.Stage == StageResolverBootstrap {
		breakerEligible = false
	}
	return []DomainEvidence{{
		RuntimeEpochID: e.RuntimeEpochID, CatalogRevision: e.CatalogRevision, SourceGeneration: e.SourceGeneration, Handle: e.Handle,
		Domain: domain, Outcome: e.Outcome, Failure: e.Failure, Confidence: e.Confidence, AttemptID: e.AttemptID,
		BreakerEligible: breakerEligible, Weight: weight,
	}}, nil
}

func confidencePolicy(confidence ObservationConfidence) (float64, bool) {
	switch confidence {
	case ConfidenceLow:
		return 0.25, false
	case ConfidenceMedium:
		return 0.60, false
	case ConfidenceHigh:
		return 0.90, true
	case ConfidenceAuthoritative:
		return 1.0, true
	default:
		return 0, false
	}
}

type ObservationIdentityGuard interface {
	ValidateObservation(ObservationEvidence) bool
}

type RuntimeEpochObservationGuard struct{ Lease *RuntimeEpochIdentityLease }

func (g RuntimeEpochObservationGuard) ValidateObservation(e ObservationEvidence) bool {
	return g.Lease != nil && g.Lease.ValidateEvidence(e.RuntimeEpochID, e.CatalogRevision, e.SourceGeneration, e.Handle)
}

type IngestDisposition string

const (
	IngestAccepted     IngestDisposition = "accepted"
	IngestDuplicate    IngestDisposition = "deferred_duplicate"
	IngestStale        IngestDisposition = "deferred_stale"
	IngestBackpressure IngestDisposition = "deferred_backpressure"
)

type ObservationReducer interface {
	Reduce(ObservationEvidence, []DomainEvidence) error
}

type ObservationSettlement interface {
	Complete(map[FailureDomain]ObservationOutcome, time.Time, time.Duration, string)
	ReleaseDeferred()
}

type AttemptPermitSettlement struct{ Permit *AttemptPermit }

func (s AttemptPermitSettlement) Complete(outcomes map[FailureDomain]ObservationOutcome, at time.Time, delay time.Duration, reason string) {
	if s.Permit != nil {
		s.Permit.CompleteDomains(outcomes, at, delay, reason)
	}
}

func (s AttemptPermitSettlement) ReleaseDeferred() {
	if s.Permit != nil {
		s.Permit.ReleaseDeferred()
	}
}

// HealthObservationReducer is the only observation reducer allowed to mutate
// HealthStore. Active attempts inject Settlement so the permit remains the
// sole owner of half-open completion.
type HealthObservationReducer struct {
	Store        *HealthStore
	Settlement   ObservationSettlement
	BeforeReduce func(ObservationEvidence, []DomainEvidence) error
}

func (r *HealthObservationReducer) Reduce(e ObservationEvidence, domains []DomainEvidence) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("adaptive health observation reducer panic: %v", recovered)
		}
	}()
	if r == nil || r.Store == nil {
		return errors.New("health observation reducer has no store")
	}
	if r.BeforeReduce != nil {
		if err := r.BeforeReduce(e, domains); err != nil {
			return err
		}
	}
	outcomes := make(map[FailureDomain]ObservationOutcome, len(domains))
	for _, domain := range domains {
		if domain.Handle != e.Handle || domain.RuntimeEpochID != e.RuntimeEpochID || domain.CatalogRevision != e.CatalogRevision || domain.SourceGeneration != e.SourceGeneration || domain.AttemptID != e.AttemptID {
			return errors.New("health observation domain identity mismatch")
		}
	}
	for _, domain := range domains {
		if domain.BreakerEligible {
			outcomes[domain.Domain] = domain.Outcome
		} else {
			r.Store.ObserveEvidence(healthObservationForDomain(e, domain), false, domain.Weight)
		}
	}
	if r.Settlement != nil {
		if len(outcomes) == 0 {
			r.Settlement.ReleaseDeferred()
		} else {
			r.Settlement.Complete(outcomes, e.At, e.Delay, e.Reason)
		}
		return nil
	}
	for _, domain := range domains {
		if !domain.BreakerEligible {
			continue
		}
		r.Store.ObserveEvidence(healthObservationForDomain(e, domain), true, domain.Weight)
	}
	return nil
}

func healthObservationForDomain(e ObservationEvidence, domain DomainEvidence) Observation {
	observation := Observation{NodeID: e.Handle.NodeID, NodeSlot: e.Handle.Slot, NodeVersion: e.Handle.Version, Scope: domain.Domain, Outcome: domain.Outcome, Delay: e.Delay, ThroughputBPS: e.ThroughputBPS, At: e.At, Reason: e.Reason}
	if domain.Domain == DomainTransport {
		// B1: always write qualified ledger keys so StatusHandle/permit/rank
		// never disagree on bare "tcp"/"udp" vs "tcp/any"/"udp_data/any".
		path := e.NetworkPath
		if path == "" {
			path = e.Transport
		}
		if normalized := normalizeHealthTransportPath(path); normalized != "" {
			path = normalized
		}
		observation.Transport = path
	}
	if domain.Domain == DomainService {
		observation.Service = e.ServiceID
	}
	return observation
}

func PublishSettledObservation(ingestor *ObservationIngestor, evidence ObservationEvidence, reducer *HealthObservationReducer) (IngestDisposition, error) {
	return PublishSettledObservationGuarded(ingestor, nil, evidence, reducer)
}

func PublishSettledObservationGuarded(ingestor *ObservationIngestor, guard ObservationIdentityGuard, evidence ObservationEvidence, reducer *HealthObservationReducer) (IngestDisposition, error) {
	if ingestor == nil || reducer == nil {
		return "", errors.New("settled observation pipeline is incomplete")
	}
	var disposition IngestDisposition
	var err error
	if guard == nil {
		disposition, err = ingestor.Publish(evidence, reducer)
	} else {
		disposition, err = ingestor.PublishGuarded(evidence, guard, reducer)
	}
	if err != nil || disposition != IngestAccepted || evidence.Outcome == OutcomeDeferred {
		if reducer.Settlement != nil {
			reducer.Settlement.ReleaseDeferred()
		}
	}
	return disposition, err
}

type observationDedupKey struct {
	epochID          RuntimeEpochID
	revision         CatalogRevision
	sourceGeneration uint64
	nodeID           NodeID
	nodeSlot         uint64
	attemptID        AttemptID
	source           ObservationSource
	stage            ObservationStage
	domain           FailureDomain
	version          uint64
}

type observationDedupRecord struct {
	key       observationDedupKey
	expiresAt time.Time
	element   *list.Element
}

// ObservationIngestor guards identity and performs bounded replay suppression.
// It intentionally does not reference HealthStore.
type ObservationIngestor struct {
	access      sync.Mutex
	guard       ObservationIdentityGuard
	clock       Clock
	ttl         time.Duration
	maxEntries  int
	entries     map[observationDedupKey]*observationDedupRecord
	pending     map[observationDedupKey]*observationDedupRecord
	lru         list.List
	pruneVisits uint64
}

func NewObservationIngestor(guard ObservationIdentityGuard, clock Clock, ttl time.Duration, maxEntries int) *ObservationIngestor {
	if clock == nil {
		clock = realClock{}
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 16384
	}
	return &ObservationIngestor{guard: guard, clock: clock, ttl: ttl, maxEntries: maxEntries, entries: make(map[observationDedupKey]*observationDedupRecord), pending: make(map[observationDedupKey]*observationDedupRecord)}
}

func (i *ObservationIngestor) Publish(e ObservationEvidence, reducer ObservationReducer) (IngestDisposition, error) {
	return i.PublishGuarded(e, i.guard, reducer)
}

func (i *ObservationIngestor) PublishGuarded(e ObservationEvidence, guard ObservationIdentityGuard, reducer ObservationReducer) (IngestDisposition, error) {
	disposition, domains, reservation, err := i.reserve(e, guard)
	if err != nil || disposition != IngestAccepted || len(domains) == 0 {
		return disposition, err
	}
	if reducer == nil {
		reservation.abort()
		return "", errors.New("observation ingestor has no reducer")
	}
	if err = reducer.Reduce(e, domains); err != nil {
		reservation.abort()
		return "", err
	}
	if err = reservation.commit(); err != nil {
		return "", err
	}
	return disposition, nil
}

func (i *ObservationIngestor) ingest(e ObservationEvidence) (IngestDisposition, []DomainEvidence, error) {
	disposition, domains, reservation, err := i.reserve(e, i.guard)
	if disposition == IngestAccepted && reservation != nil {
		err = reservation.commit()
	}
	return disposition, domains, err
}

type observationReservation struct {
	ingestor *ObservationIngestor
	records  []*observationDedupRecord
	state    atomic.Uint32
}

const (
	reservationReserved uint32 = iota
	reservationCommitted
	reservationAborted
)

func (r *observationReservation) commit() error {
	if r == nil {
		return nil
	}
	if !r.state.CompareAndSwap(reservationReserved, reservationCommitted) {
		return errors.New("observation reservation is no longer pending")
	}
	var commitErr error
	r.ingestor.access.Lock()
	for _, record := range r.records {
		if r.ingestor.pending[record.key] != record {
			commitErr = errors.New("observation reservation was evicted before commit")
			break
		}
	}
	if commitErr == nil {
		now := r.ingestor.clock.Now()
		for _, record := range r.records {
			delete(r.ingestor.pending, record.key)
			record.expiresAt = now.Add(r.ingestor.ttl)
			record.element = r.ingestor.lru.PushFront(record)
			r.ingestor.entries[record.key] = record
		}
	} else {
		for _, record := range r.records {
			if current := r.ingestor.pending[record.key]; current == record {
				delete(r.ingestor.pending, record.key)
			}
		}
		r.state.Store(reservationAborted)
	}
	r.ingestor.access.Unlock()
	return commitErr
}

func (r *observationReservation) abort() {
	if r == nil {
		return
	}
	if !r.state.CompareAndSwap(reservationReserved, reservationAborted) {
		return
	}
	r.ingestor.access.Lock()
	for _, record := range r.records {
		if current := r.ingestor.pending[record.key]; current == record {
			delete(r.ingestor.pending, record.key)
		}
	}
	r.ingestor.access.Unlock()
}

func (i *ObservationIngestor) reserve(e ObservationEvidence, guard ObservationIdentityGuard) (IngestDisposition, []DomainEvidence, *observationReservation, error) {
	if err := e.ValidateShape(); err != nil {
		return "", nil, nil, err
	}
	if e.RuntimeEpochID == 0 || e.CatalogRevision == 0 || e.SourceGeneration == 0 || e.Handle.NodeID == (NodeID{}) || e.Handle.Slot == 0 || e.Handle.Version == 0 || e.AttemptID == 0 {
		return "", nil, nil, errors.New("production observation requires epoch, revision, source generation, full handle and attempt")
	}
	if guard == nil {
		return "", nil, nil, errors.New("observation ingestor has no catalog guard")
	}
	if !guard.ValidateObservation(e) {
		return IngestStale, nil, nil, nil
	}
	domains, err := e.MapDomains()
	if err != nil || len(domains) == 0 {
		return IngestAccepted, domains, nil, err
	}
	return i.reserveMapped(e, domains)
}

func (i *ObservationIngestor) reserveMapped(e ObservationEvidence, domains []DomainEvidence) (IngestDisposition, []DomainEvidence, *observationReservation, error) {
	now := i.clock.Now()
	i.access.Lock()
	defer i.access.Unlock()
	i.pruneLocked(now)
	keys := make([]observationDedupKey, 0, len(domains))
	for _, evidence := range domains {
		key := observationDedupKey{epochID: e.RuntimeEpochID, revision: e.CatalogRevision, sourceGeneration: e.SourceGeneration, nodeID: e.Handle.NodeID, nodeSlot: e.Handle.Slot, attemptID: e.AttemptID, source: e.Source, stage: e.Stage, domain: evidence.Domain, version: e.Handle.Version}
		if i.pending[key] != nil {
			return IngestDuplicate, nil, nil, nil
		}
		if record := i.entries[key]; record != nil && now.Before(record.expiresAt) {
			return IngestDuplicate, nil, nil, nil
		}
		keys = append(keys, key)
	}
	for len(i.entries)+len(i.pending)+len(keys) > i.maxEntries {
		if !i.removeOldestCommittedLocked() {
			return IngestBackpressure, nil, nil, nil
		}
	}
	accepted := domains
	reservation := &observationReservation{ingestor: i}
	for _, key := range keys {
		record := &observationDedupRecord{key: key}
		i.pending[key] = record
		reservation.records = append(reservation.records, record)
	}
	return IngestAccepted, accepted, reservation, nil
}

func (i *ObservationIngestor) pruneLocked(now time.Time) {
	for element := i.lru.Back(); element != nil; {
		previous := element.Prev()
		record := element.Value.(*observationDedupRecord)
		i.pruneVisits++
		if now.Before(record.expiresAt) {
			break
		}
		delete(i.entries, record.key)
		i.lru.Remove(element)
		element = previous
	}
}

func (i *ObservationIngestor) removeOldestCommittedLocked() bool {
	element := i.lru.Back()
	if element == nil {
		return false
	}
	record := element.Value.(*observationDedupRecord)
	delete(i.entries, record.key)
	i.lru.Remove(element)
	return true
}
