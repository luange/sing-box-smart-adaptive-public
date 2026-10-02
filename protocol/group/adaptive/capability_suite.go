package adaptive

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

const (
	youtubeProbeServiceID = YouTubeProbeServiceID
	youtubeTargetSourceID = YouTubeTargetSourceID
)

// SignedProbeTargetFetcher is the trust boundary for short-lived signed media
// targets. Implementations belong to the control plane; the adaptive core does
// not discover, construct, log, or persist signed URLs.
type SignedProbeTargetFetcher interface {
	FetchSignedProbeTargets(context.Context) (*SignedProbeTargetManifest, error)
}

// TrustedYouTubeTargetProvider validates and atomically publishes snapshots
// from the injected trusted fetcher. It never falls back to a baked-in URL.
type TrustedYouTubeTargetProvider struct {
	clock   Clock
	fetcher SignedProbeTargetFetcher
	keyring map[string]ed25519.PublicKey
	catalog *ProbeTargetCatalog
}

func NewTrustedYouTubeTargetProvider(clock Clock, fetcher SignedProbeTargetFetcher, trustedKeys map[string]ed25519.PublicKey) (*TrustedYouTubeTargetProvider, error) {
	if fetcher == nil {
		return nil, errors.New("adaptive YouTube target fetcher is nil")
	}
	if clock == nil {
		clock = realClock{}
	}
	keyring, err := cloneProbeTargetKeyring(trustedKeys)
	if err != nil {
		return nil, err
	}
	return &TrustedYouTubeTargetProvider{
		clock: clock, fetcher: fetcher, keyring: keyring,
		catalog: NewProbeTargetCatalog(1, youtubeTargetSourceID),
	}, nil
}

func (p *TrustedYouTubeTargetProvider) Refresh(ctx context.Context) error {
	manifest, err := p.fetcher.FetchSignedProbeTargets(ctx)
	if err != nil {
		return ErrProbeTargetFetch
	}
	snapshot, err := manifest.verifyAndDecode(p.keyring, p.clock.Now())
	if err != nil {
		return err
	}
	if _, err = snapshot.executionTargets(p.clock.Now()); err != nil {
		return err
	}
	current, currentErr := p.catalog.Snapshot(ctx, snapshot.ServiceID)
	if currentErr == nil {
		if snapshot.Generation < current.Generation {
			return ErrProbeTargetRollback
		}
		if snapshot.Generation == current.Generation {
			if probeTargetSnapshotsEquivalent(current, snapshot) {
				return nil
			}
			return ErrProbeTargetUntrusted
		}
	}
	return p.catalog.Publish(snapshot)
}

func probeTargetSnapshotsEquivalent(first, second *ProbeTargetSnapshot) bool {
	return first != nil && second != nil && first.SourceID == second.SourceID && first.ServiceID == second.ServiceID && first.Generation == second.Generation && first.IssuedAt.Equal(second.IssuedAt) && first.ExpiresAt.Equal(second.ExpiresAt) && reflect.DeepEqual(first.Targets(), second.Targets())
}

func (p *TrustedYouTubeTargetProvider) Snapshot(ctx context.Context, serviceID string) (*ProbeTargetSnapshot, error) {
	if serviceID != youtubeProbeServiceID {
		return nil, ErrProbeRunUnknown
	}
	return p.catalog.Snapshot(ctx, serviceID)
}

type CapabilitySuiteNode struct {
	Handle NodeHandle
	Dialer N.Dialer
}

type CapabilitySuiteRequest struct {
	RunID              ProbeSuiteRunID
	RuntimeEpochID     RuntimeEpochID
	CatalogRevision    CatalogRevision
	SourceGeneration   uint64
	ServiceID          string
	Nodes              []CapabilitySuiteNode
	Quorum             int
	CommonModeMinNodes int
	Deadline           time.Time
	Priority           ProbePriority
}

// CapabilityProbeSuite is intentionally epoch-local: tasks carry dialers only
// in scheduler closures, while the shared scheduler coordinator remains pure
// ownership data. Verdict publication is restricted to ProbeObservationSink.
type CapabilityProbeSuite struct {
	clock          Clock
	scheduler      *ProbeScheduler
	targets        ProbeTargetProvider
	runner         *CapabilityProbeRunner
	aggregator     *ProbeAggregator
	sessions       CapabilityObservationSessionFactory
	exitIdentities *ExitIdentityStore
}

func NewCapabilityProbeSuite(clock Clock, scheduler *ProbeScheduler, targets ProbeTargetProvider, runner *CapabilityProbeRunner, aggregator *ProbeAggregator, sessions CapabilityObservationSessionFactory, exitIdentities ...*ExitIdentityStore) (*CapabilityProbeSuite, error) {
	if clock == nil {
		clock = realClock{}
	}
	if scheduler == nil || targets == nil || runner == nil || aggregator == nil || sessions == nil {
		return nil, errors.New("adaptive capability probe suite dependency is nil")
	}
	var identityStore *ExitIdentityStore
	if len(exitIdentities) > 0 {
		identityStore = exitIdentities[0]
	}
	return &CapabilityProbeSuite{clock: clock, scheduler: scheduler, targets: targets, runner: runner, aggregator: aggregator, sessions: sessions, exitIdentities: identityStore}, nil
}

func (s *CapabilityProbeSuite) Run(ctx context.Context, request CapabilitySuiteRequest) (ProbeRunResult, error) {
	snapshot, err := s.targets.Snapshot(ctx, request.ServiceID)
	if err != nil {
		return ProbeRunResult{}, err
	}
	targets, err := snapshot.executionTargets(s.clock.Now())
	if err != nil {
		return ProbeRunResult{}, err
	}
	if request.ServiceID != snapshot.ServiceID || len(request.Nodes) == 0 {
		return ProbeRunResult{}, ErrProbeSampleIdentity
	}
	nodeHandles := make([]NodeHandle, len(request.Nodes))
	for index, node := range request.Nodes {
		if node.Dialer == nil {
			return ProbeRunResult{}, ErrProbeSampleIdentity
		}
		nodeHandles[index] = node.Handle
	}
	descriptors := make([]ProbeTargetDescriptor, len(targets))
	for index, target := range targets {
		descriptors[index] = target.Descriptor()
	}
	source := SourceHTTP
	if allProbeTargetsTLS(targets) {
		source = SourceTLS
	}
	spec := ProbeRunSpec{
		RunID: request.RunID, Class: ProbeSuiteServiceCapability,
		RuntimeEpochID: request.RuntimeEpochID, CatalogRevision: request.CatalogRevision, SourceGeneration: request.SourceGeneration,
		ServiceID: request.ServiceID, Source: source, TargetGeneration: snapshot.Generation,
		Nodes: nodeHandles, Targets: descriptors, Quorum: request.Quorum, CommonModeMinNodes: request.CommonModeMinNodes, Deadline: request.Deadline,
	}
	beginDisposition, err := s.aggregator.Begin(spec)
	if err != nil {
		return ProbeRunResult{}, err
	}
	if beginDisposition != ProbeAggregateAccepted {
		return ProbeRunResult{}, fmt.Errorf("adaptive capability probe run was not accepted: %s", beginDisposition)
	}
	session, err := s.sessions.OpenCapabilityObservation(CapabilityObservationIdentity{
		RuntimeEpochID: request.RuntimeEpochID, CatalogRevision: request.CatalogRevision, SourceGeneration: request.SourceGeneration,
	})
	if err != nil {
		s.aggregator.Abort(request.RunID)
		return ProbeRunResult{}, err
	}
	if session == nil {
		s.aggregator.Abort(request.RunID)
		return ProbeRunResult{}, errors.New("adaptive capability observation session is nil")
	}
	defer session.Close()
	attempts := make(map[NodeHandle]*capabilityNodeAttempt, len(request.Nodes))
	for _, node := range request.Nodes {
		attempts[node.Handle] = new(capabilityNodeAttempt)
	}
	defer func() {
		for _, attempt := range attempts {
			attempt.release()
		}
	}()

	priority := request.Priority
	if priority == 0 {
		priority = ProbePriorityService
	}
	timeout := request.Deadline.Sub(s.clock.Now())
	type taskCompletion struct {
		done   <-chan error
		future *ProbeFuture
		handle NodeHandle
		target ProbeTarget
		holder *capabilitySampleHolder
	}
	completions := make([]taskCompletion, 0, len(request.Nodes)*len(targets))
	for _, node := range request.Nodes {
		for _, target := range targets {
			done := make(chan error, 1)
			holder := new(capabilitySampleHolder)
			task := s.probeTask(spec, node, target, priority, timeout, holder, done, attempts[node.Handle], session)
			submission := s.scheduler.Submit(task)
			if submission.Status == ProbeRejected || submission.Status == ProbeDeferred {
				for _, completion := range completions {
					completion.future.Cancel()
				}
				s.aggregator.Abort(request.RunID)
				return ProbeRunResult{}, fmt.Errorf("adaptive capability probe submission %s: %w", submission.Status, submission.Err)
			}
			completions = append(completions, taskCompletion{done: done, future: submission.Future, handle: node.Handle, target: target, holder: holder})
		}
	}
	for _, completion := range completions {
		select {
		case completionErr := <-completion.done:
			if completionErr != nil {
				s.aggregator.Abort(request.RunID)
				return ProbeRunResult{}, completionErr
			}
		case <-ctx.Done():
			for _, pending := range completions {
				pending.future.Cancel()
			}
			s.aggregator.Abort(request.RunID)
			return ProbeRunResult{}, ctx.Err()
		}
	}
	if err = ctx.Err(); err != nil {
		s.aggregator.Abort(request.RunID)
		return ProbeRunResult{}, err
	}
	result, err := s.aggregator.Complete(request.RunID)
	if err != nil {
		return ProbeRunResult{}, err
	}
	if err = s.publishResult(ctx, result, attempts, session); err != nil {
		return ProbeRunResult{}, err
	}
	for _, completion := range completions {
		if completion.target.Capability != ProbeCapabilityExitIdentity || s.exitIdentities == nil {
			continue
		}
		completion.holder.access.Lock()
		raw := completion.holder.raw
		set := completion.holder.set
		completion.holder.access.Unlock()
		if set && raw.hasIdentityToken {
			s.exitIdentities.Commit(completion.handle, raw.identityToken)
		}
	}
	return result, nil
}

type CapabilityObservationIdentity struct {
	RuntimeEpochID   RuntimeEpochID
	CatalogRevision  CatalogRevision
	SourceGeneration uint64
}

type CapabilityObservationSessionFactory interface {
	OpenCapabilityObservation(CapabilityObservationIdentity) (CapabilityObservationSession, error)
}

type CapabilityObservationSession interface {
	AcquireCapabilityPermit(NodeHandle, string, time.Time) (ObservationSettlement, bool, error)
	PublishSettledProbeObservation(context.Context, ObservationEvidence, ObservationSettlement) (IngestDisposition, error)
	Close()
}

type capabilityNodeAttempt struct {
	once       sync.Once
	settlement ObservationSettlement
	allowed    bool
	err        error
}

func (a *capabilityNodeAttempt) begin(session CapabilityObservationSession, handle NodeHandle, serviceID string, at time.Time) (bool, error) {
	a.once.Do(func() {
		a.settlement, a.allowed, a.err = session.AcquireCapabilityPermit(handle, serviceID, at)
	})
	return a.allowed, a.err
}

func (a *capabilityNodeAttempt) release() {
	if a != nil && a.settlement != nil {
		a.settlement.ReleaseDeferred()
	}
}

func (s *CapabilityProbeSuite) publishResult(ctx context.Context, result ProbeRunResult, attempts map[NodeHandle]*capabilityNodeAttempt, session CapabilityObservationSession) error {
	for _, verdict := range result.Verdicts {
		attempt := attempts[verdict.Handle]
		if !verdict.Authoritative {
			if attempt != nil {
				attempt.release()
			}
			continue
		}
		if attempt == nil || attempt.settlement == nil || !attempt.allowed {
			return errors.New("adaptive capability verdict has no active permit")
		}
		evidence, err := verdict.Observation(result.Completed)
		if err != nil {
			attempt.release()
			return err
		}
		disposition, publishErr := session.PublishSettledProbeObservation(ctx, evidence, attempt.settlement)
		if publishErr != nil {
			return publishErr
		}
		if disposition != IngestAccepted {
			return fmt.Errorf("adaptive capability verdict was not accepted: %s", disposition)
		}
	}
	return nil
}

// IngestingProbeObservationSink is the only production-shaped verdict sink.
// It cannot mutate health directly: identity validation, bounded dedup and the
// injected reducer transaction always run inside ObservationIngestor.
type IngestingProbeObservationSink struct {
	ingestor *ObservationIngestor
	guard    ObservationIdentityGuard
	reducer  ObservationReducer
	close    func()
	closeOne sync.Once
}

func NewIngestingProbeObservationSink(ingestor *ObservationIngestor, guard ObservationIdentityGuard, reducer ObservationReducer) (*IngestingProbeObservationSink, error) {
	if ingestor == nil || guard == nil || reducer == nil {
		return nil, errors.New("adaptive probe observation pipeline dependency is nil")
	}
	return &IngestingProbeObservationSink{ingestor: ingestor, guard: guard, reducer: reducer}, nil
}

// OpenCapabilityObservation makes the fixed-guard sink usable as a test
// session factory. Production must use RuntimeCapabilityObservationFactory so
// the epoch lease is acquired and released per suite run.
func (s *IngestingProbeObservationSink) OpenCapabilityObservation(CapabilityObservationIdentity) (CapabilityObservationSession, error) {
	return s, nil
}

func (s *IngestingProbeObservationSink) Close() {
	if s != nil && s.close != nil {
		s.closeOne.Do(s.close)
	}
}

func (s *IngestingProbeObservationSink) PublishProbeObservation(_ context.Context, evidence ObservationEvidence) (IngestDisposition, error) {
	return s.ingestor.PublishGuarded(evidence, s.guard, s.reducer)
}

func (s *IngestingProbeObservationSink) healthReducer() (*HealthObservationReducer, error) {
	reducer, loaded := s.reducer.(*HealthObservationReducer)
	if !loaded || reducer == nil || reducer.Store == nil {
		return nil, errors.New("adaptive capability probe sink requires HealthObservationReducer")
	}
	return reducer, nil
}

func (s *IngestingProbeObservationSink) AcquireCapabilityPermit(handle NodeHandle, serviceID string, at time.Time) (ObservationSettlement, bool, error) {
	reducer, err := s.healthReducer()
	if err != nil {
		return nil, false, err
	}
	permit, allowed := reducer.Store.TryAcquireDomainPermitHandle(handle, DomainService, "", serviceID, at)
	if !allowed {
		return nil, false, nil
	}
	return AttemptPermitSettlement{Permit: permit}, true, nil
}

func (s *IngestingProbeObservationSink) PublishSettledProbeObservation(_ context.Context, evidence ObservationEvidence, settlement ObservationSettlement) (IngestDisposition, error) {
	reducer, err := s.healthReducer()
	if err != nil {
		if settlement != nil {
			settlement.ReleaseDeferred()
		}
		return "", err
	}
	settled := *reducer
	settled.Settlement = settlement
	return PublishSettledObservationGuarded(s.ingestor, s.guard, evidence, &settled)
}

// RuntimeCapabilityObservationFactory is the production epoch boundary for a
// capability run. It stores no execution view, outbound or private target.
type RuntimeCapabilityObservationFactory struct {
	manager      *RuntimeManager
	groupID      string
	ingestor     *ObservationIngestor
	store        *HealthStore
	beforeReduce func(ObservationEvidence, []DomainEvidence) error
}

func NewRuntimeCapabilityObservationFactory(manager *RuntimeManager, groupID string, ingestor *ObservationIngestor, store *HealthStore, beforeReduce func(ObservationEvidence, []DomainEvidence) error) (*RuntimeCapabilityObservationFactory, error) {
	if manager == nil || groupID == "" || ingestor == nil || store == nil {
		return nil, errors.New("adaptive runtime capability observation dependency is nil")
	}
	return &RuntimeCapabilityObservationFactory{manager: manager, groupID: groupID, ingestor: ingestor, store: store, beforeReduce: beforeReduce}, nil
}

func (f *RuntimeCapabilityObservationFactory) OpenCapabilityObservation(identity CapabilityObservationIdentity) (CapabilityObservationSession, error) {
	if identity.RuntimeEpochID == 0 || identity.CatalogRevision == 0 || identity.SourceGeneration == 0 {
		return nil, errors.New("adaptive capability observation identity is incomplete")
	}
	lease, err := f.manager.AcquireEpoch(f.groupID, identity.RuntimeEpochID)
	if err != nil {
		return nil, err
	}
	session := &IngestingProbeObservationSink{
		ingestor: f.ingestor,
		guard:    RuntimeEpochObservationGuard{Lease: lease},
		reducer:  &HealthObservationReducer{Store: f.store, BeforeReduce: f.beforeReduce},
		close:    lease.Release,
	}
	return session, nil
}

type capabilitySampleHolder struct {
	access sync.Mutex
	raw    ProbeRawResult
	set    bool
}

func (s *CapabilityProbeSuite) probeTask(spec ProbeRunSpec, node CapabilitySuiteNode, target ProbeTarget, priority ProbePriority, timeout time.Duration, holder *capabilitySampleHolder, done chan error, attempt *capabilityNodeAttempt, session CapabilityObservationSession) ProbeTask {
	return ProbeTask{
		Key: ProbeKey{
			RuntimeEpochID: spec.RuntimeEpochID, CatalogRevision: spec.CatalogRevision, SourceGeneration: spec.SourceGeneration,
			NodeID: node.Handle.NodeID, NodeSlot: node.Handle.Slot, NodeVersion: node.Handle.Version,
			Suite: fmt.Sprintf("capability:%d:%s", spec.RunID, spec.ServiceID), Target: target.ID.String(),
		},
		Source: spec.ServiceID, Priority: priority, Timeout: timeout,
		Run: func(runContext context.Context) ProbeResult {
			allowed, permitErr := attempt.begin(session, node.Handle, spec.ServiceID, s.clock.Now())
			if permitErr != nil || !allowed {
				return ProbeResult{Outcome: OutcomeDeferred, Reason: "capability permit unavailable"}
			}
			raw := s.runner.Run(runContext, node.Dialer, target)
			holder.access.Lock()
			holder.raw, holder.set = raw, true
			holder.access.Unlock()
			return ProbeResult{Outcome: OutcomeSuccess, Delay: raw.Delay}
		},
		Observe: func(_ ProbeTask, scheduled ProbeResult) {
			holder.access.Lock()
			raw, set := holder.raw, holder.set
			holder.access.Unlock()
			classification := ProbeSampleClassification{Class: ProbeSampleDeferred, Failure: FailureCanceled}
			if set && scheduled.Outcome != OutcomeDeferred {
				if target.Capability == ProbeCapabilityExitIdentity && raw.hasIdentityToken && s.exitIdentities != nil {
					changed, accepted := s.exitIdentities.Compare(node.Handle, raw.identityToken)
					raw.identityChanged = changed
					if !accepted {
						raw.hasIdentityToken = false
					}
				}
				classification = ClassifyProbeResult(target, raw, s.clock.Now())
			}
			sample := ProbeSample{
				RunID: spec.RunID, Suite: spec.Class, RuntimeEpochID: spec.RuntimeEpochID, CatalogRevision: spec.CatalogRevision,
				SourceGeneration: spec.SourceGeneration, Handle: node.Handle, TargetID: target.ID, TargetGeneration: spec.TargetGeneration,
				ServiceID: spec.ServiceID, Capability: target.Capability, Class: classification.Class, Failure: classification.Failure,
				HTTPStatus: raw.StatusCode, BytesRead: raw.BytesRead, ContentRange: raw.ContentRange, Delay: raw.Delay, At: s.clock.Now(),
			}
			_, ingestErr := s.aggregator.Ingest(sample)
			done <- ingestErr
			close(done)
		},
	}
}

func allProbeTargetsTLS(targets []ProbeTarget) bool {
	for _, target := range targets {
		if target.Capability != ProbeCapabilityTLS {
			return false
		}
	}
	return len(targets) > 0
}
