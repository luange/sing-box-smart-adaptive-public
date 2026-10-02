package adaptive

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type staticObservationGuard struct {
	epochID          RuntimeEpochID
	revision         CatalogRevision
	sourceGeneration uint64
	handle           NodeHandle
}

type collectingReducer struct{ calls int }

func (r *collectingReducer) Reduce(_ ObservationEvidence, _ []DomainEvidence) error {
	r.calls++
	return nil
}

type failingReducer struct {
	access sync.Mutex
	calls  int
	fail   bool
}

func (r *failingReducer) Reduce(_ ObservationEvidence, _ []DomainEvidence) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.calls++
	if r.fail {
		return errors.New("synthetic reducer failure")
	}
	return nil
}

func (g staticObservationGuard) ValidateObservation(e ObservationEvidence) bool {
	return e.RuntimeEpochID == g.epochID && e.CatalogRevision <= g.revision && e.SourceGeneration <= g.sourceGeneration && e.Handle == g.handle
}

func validEvidence() ObservationEvidence {
	return ObservationEvidence{
		RuntimeEpochID: 3, CatalogRevision: 7, SourceGeneration: 2,
		Handle: NodeHandle{NodeID: NodeID{1}, Slot: 4, Version: 3, BornRevision: 1}, Source: SourceHTTP, Stage: StageServiceApplication,
		Outcome: OutcomeSuccess, Confidence: ConfidenceHigh, ServiceID: "youtube", Transport: "tcp",
		AttemptID: 1,
	}
}

func guardFor(e ObservationEvidence) staticObservationGuard {
	return staticObservationGuard{epochID: e.RuntimeEpochID, revision: e.CatalogRevision, sourceGeneration: e.SourceGeneration, handle: e.Handle}
}

func TestObservationContractThroughputIsServiceQualityOnly(t *testing.T) {
	evidence := validEvidence()
	evidence.Source = SourceThroughput
	evidence.Confidence = ConfidenceMedium
	evidence.ThroughputBPS = 8 << 20
	domains, err := evidence.MapDomains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0].Domain != DomainService || domains[0].BreakerEligible {
		t.Fatalf("throughput escaped service quality domain: %+v", domains)
	}
	evidence.Confidence = ConfidenceHigh
	if _, err = evidence.MapDomains(); err == nil {
		t.Fatal("breaker-eligible throughput evidence was accepted")
	}
	evidence.Confidence = ConfidenceMedium
	evidence.ThroughputBPS = 0
	if _, err = evidence.MapDomains(); err == nil {
		t.Fatal("zero throughput evidence was accepted")
	}
}

func TestObservationContractProxyTLSAndServiceTLSMapDifferently(t *testing.T) {
	proxy := validEvidence()
	proxy.Source, proxy.Stage, proxy.Outcome, proxy.Failure, proxy.ServiceID = SourceTLS, StageProxyTunnel, OutcomeFailure, FailureTLS, ""
	service := validEvidence()
	service.Source, service.Stage, service.Outcome, service.Failure = SourceTLS, StageServiceApplication, OutcomeFailure, FailureTLS
	proxyDomains, err := proxy.MapDomains()
	if err != nil {
		t.Fatal(err)
	}
	serviceDomains, err := service.MapDomains()
	if err != nil {
		t.Fatal(err)
	}
	if len(proxyDomains) != 1 || proxyDomains[0].Domain != DomainEndpoint || len(serviceDomains) != 1 || serviceDomains[0].Domain != DomainService {
		t.Fatalf("TLS layers were conflated: proxy=%+v service=%+v", proxyDomains, serviceDomains)
	}
}

func TestObservationContractBusinessDNSDoesNotPolluteEndpoint(t *testing.T) {
	evidence := validEvidence()
	evidence.Source, evidence.Stage, evidence.Outcome, evidence.Failure = SourceDNS, StageBusinessDNS, OutcomeFailure, FailureDNS
	domains, err := evidence.MapDomains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0].Domain != DomainService {
		t.Fatalf("business DNS polluted node endpoint: %+v", domains)
	}
}

func TestObservationContractConfidenceControlsBreakerEligibility(t *testing.T) {
	for _, test := range []struct {
		confidence ObservationConfidence
		eligible   bool
	}{{ConfidenceLow, false}, {ConfidenceMedium, false}, {ConfidenceHigh, true}, {ConfidenceAuthoritative, true}} {
		evidence := validEvidence()
		evidence.Source, evidence.Stage, evidence.ServiceID, evidence.Confidence = SourceProbe, StageProxyTunnel, "", test.confidence
		domains, err := evidence.MapDomains()
		if err != nil {
			t.Fatal(err)
		}
		if domains[0].BreakerEligible != test.eligible || domains[0].Weight <= 0 {
			t.Fatalf("confidence policy mismatch for %d: %+v", test.confidence, domains[0])
		}
	}
}

func TestObservationContractRejectsInvalidFailureNone(t *testing.T) {
	evidence := validEvidence()
	evidence.Outcome, evidence.Failure = OutcomeFailure, FailureNone
	if err := evidence.ValidateShape(); err == nil {
		t.Fatal("failure without class was accepted")
	}
}

func TestObservationIngestorRejectsOldGenerationAndVersion(t *testing.T) {
	evidence := validEvidence()
	staleGuard := guardFor(evidence)
	staleGuard.handle.Version = 4
	ingestor := NewObservationIngestor(staleGuard, nil, 0, 0)
	disposition, domains, err := ingestor.ingest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != IngestStale || len(domains) != 0 {
		t.Fatalf("stale evidence was accepted: disposition=%s domains=%+v", disposition, domains)
	}
}

func TestObservationIngestorDeduplicatesReplayButAllowsDifferentStage(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, 0, 8)
	disposition, domains, err := ingestor.ingest(evidence)
	if err != nil || disposition != IngestAccepted || len(domains) != 1 {
		t.Fatalf("first evidence rejected: disposition=%s domains=%+v err=%v", disposition, domains, err)
	}
	disposition, domains, err = ingestor.ingest(evidence)
	if err != nil || disposition != IngestDuplicate || len(domains) != 0 {
		t.Fatalf("replayed evidence counted twice: disposition=%s domains=%+v err=%v", disposition, domains, err)
	}
	dial := evidence
	dial.Source, dial.Stage, dial.ServiceID, dial.Outcome = SourceDial, StageProxyTunnel, "", OutcomeSuccess
	firstByte := evidence
	firstByte.Source, firstByte.Stage = SourceFirstByte, StageServiceApplication
	disposition, domains, err = ingestor.ingest(dial)
	if err != nil || disposition != IngestAccepted || len(domains) != 1 || domains[0].Domain != DomainEndpoint {
		t.Fatalf("dial stage was not accepted: disposition=%s domains=%+v err=%v", disposition, domains, err)
	}
	disposition, domains, err = ingestor.ingest(firstByte)
	if err != nil || disposition != IngestAccepted || len(domains) != 1 || domains[0].Domain != DomainService {
		t.Fatalf("different stage on same attempt was suppressed: disposition=%s domains=%+v err=%v", disposition, domains, err)
	}
}

func TestObservationIngestorRequiresProductionIdentity(t *testing.T) {
	evidence := validEvidence()
	evidence.AttemptID = 0
	ingestor := NewObservationIngestor(guardFor(evidence), nil, 0, 8)
	if _, _, err := ingestor.ingest(evidence); err == nil {
		t.Fatal("zero production identity was accepted")
	}
}

func TestObservationPublishOnlyReducerEntryCountsReplayOnce(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, 0, 8)
	reducer := new(collectingReducer)
	if disposition, err := ingestor.Publish(evidence, reducer); err != nil || disposition != IngestAccepted {
		t.Fatalf("publish failed: disposition=%s err=%v", disposition, err)
	}
	if disposition, err := ingestor.Publish(evidence, reducer); err != nil || disposition != IngestDuplicate {
		t.Fatalf("duplicate publish was not deferred: disposition=%s err=%v", disposition, err)
	}
	if reducer.calls != 1 {
		t.Fatalf("reducer received replay twice: %d", reducer.calls)
	}
}

func TestHealthObservationReducerDuplicateWritesOnce(t *testing.T) {
	evidence := validEvidence()
	store := NewHealthStore(time.Hour, 8)
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Minute, 8)
	reducer := &HealthObservationReducer{Store: store}
	if disposition, err := ingestor.Publish(evidence, reducer); err != nil || disposition != IngestAccepted {
		t.Fatalf("first health evidence failed: %s %v", disposition, err)
	}
	if disposition, err := ingestor.Publish(evidence, reducer); err != nil || disposition != IngestDuplicate {
		t.Fatalf("duplicate health evidence was not deferred: %s %v", disposition, err)
	}
	status := store.StatusHandle(evidence.Handle, DomainService, "", evidence.ServiceID)
	if status.Successes != 1 {
		t.Fatalf("duplicate health evidence counted %d times", status.Successes)
	}
}

func TestObservationPublishReducerFailureAbortsForRetry(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Minute, 8)
	reducer := &failingReducer{fail: true}
	if _, err := ingestor.Publish(evidence, reducer); err == nil {
		t.Fatal("reducer failure was not returned")
	}
	reducer.fail = false
	if disposition, err := ingestor.Publish(evidence, reducer); err != nil || disposition != IngestAccepted {
		t.Fatalf("evidence could not be retried after reducer failure: disposition=%s err=%v", disposition, err)
	}
	if reducer.calls != 2 {
		t.Fatalf("unexpected reducer calls: %d", reducer.calls)
	}
}

func TestObservationPendingIsNotEvictedOrReentered(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Nanosecond, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	reducer := ObservationReducerFunc(func(ObservationEvidence, []DomainEvidence) error {
		close(entered)
		<-release
		return nil
	})
	done := make(chan error, 1)
	go func() { _, err := ingestor.Publish(evidence, reducer); done <- err }()
	<-entered
	if disposition, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil || disposition != IngestDuplicate {
		t.Fatalf("pending evidence was reentered: disposition=%s err=%v", disposition, err)
	}
	other := evidence
	other.AttemptID++
	health := NewHealthStore(time.Hour, 8)
	if disposition, err := ingestor.Publish(other, &HealthObservationReducer{Store: health}); err != nil || disposition != IngestBackpressure {
		t.Fatalf("pending capacity did not defer new evidence: disposition=%s err=%v", disposition, err)
	}
	if entries, _ := health.Stats(); entries != 0 {
		t.Fatalf("backpressure changed health entries: %d", entries)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type ObservationReducerFunc func(ObservationEvidence, []DomainEvidence) error

func (f ObservationReducerFunc) Reduce(e ObservationEvidence, d []DomainEvidence) error {
	return f(e, d)
}

func TestObservationDedupUsesIngestorClockNotEvidenceTime(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	evidence := validEvidence()
	evidence.At = clock.Now().Add(24 * time.Hour)
	ingestor := NewObservationIngestor(guardFor(evidence), clock, 10*time.Second, 8)
	if _, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	if disposition, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil || disposition != IngestDuplicate {
		t.Fatalf("future At broke TTL: %s %v", disposition, err)
	}
	clock.Advance(6 * time.Second)
	if disposition, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil || disposition != IngestAccepted {
		t.Fatalf("clock TTL did not expire: %s %v", disposition, err)
	}
}

func TestObservationCrossGenerationSameAttemptIsNotDeduplicated(t *testing.T) {
	evidence := validEvidence()
	guardValue := guardFor(evidence)
	guard := &guardValue
	ingestor := NewObservationIngestor(guard, nil, time.Minute, 8)
	if _, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil {
		t.Fatal(err)
	}
	guard.revision++
	evidence.CatalogRevision++
	if disposition, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil || disposition != IngestAccepted {
		t.Fatalf("generation reused dedup key: %s %v", disposition, err)
	}
}

func TestObservationRejectsIncompatibleSourceStage(t *testing.T) {
	evidence := validEvidence()
	evidence.Source, evidence.Stage = SourceDNS, StageServiceApplication
	if err := evidence.ValidateShape(); err == nil {
		t.Fatal("DNS/service stage combination accepted")
	}
	evidence.Source, evidence.Stage = SourceDial, StageServiceApplication
	if err := evidence.ValidateShape(); err == nil {
		t.Fatal("dial/service stage combination accepted")
	}
}

func TestObservationCapacityEvictsCommittedBeforeBackpressure(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Minute, 2)
	if _, err := ingestor.Publish(evidence, &collectingReducer{}); err != nil {
		t.Fatal(err)
	}
	pendingEvidence := evidence
	pendingEvidence.AttemptID = 2
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := ingestor.Publish(pendingEvidence, ObservationReducerFunc(func(ObservationEvidence, []DomainEvidence) error { close(entered); <-release; return nil }))
		done <- err
	}()
	<-entered
	newEvidence := evidence
	newEvidence.AttemptID = 3
	if disposition, err := ingestor.Publish(newEvidence, &collectingReducer{}); err != nil || disposition != IngestAccepted {
		t.Fatalf("committed record was not evicted for new evidence: disposition=%s err=%v", disposition, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestObservationPruneIsConstantForUnexpiredCommittedSet(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Hour, 16384)
	reducer := &collectingReducer{}
	for attempt := 1; attempt <= 16384; attempt++ {
		evidence.AttemptID = AttemptID(attempt)
		if _, err := ingestor.Publish(evidence, reducer); err != nil {
			t.Fatal(err)
		}
	}
	before := ingestor.pruneVisits
	evidence.AttemptID++
	if _, err := ingestor.Publish(evidence, reducer); err != nil {
		t.Fatal(err)
	}
	if visited := ingestor.pruneVisits - before; visited > 1 {
		t.Fatalf("unexpired prune scanned %d records", visited)
	}
}

func TestObservationTwoDomainPartialDuplicateLeavesNoPending(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Minute, 8)
	endpoint := DomainEvidence{RuntimeEpochID: evidence.RuntimeEpochID, CatalogRevision: evidence.CatalogRevision, SourceGeneration: evidence.SourceGeneration, Handle: evidence.Handle, Domain: DomainEndpoint, Outcome: OutcomeSuccess, AttemptID: evidence.AttemptID}
	service := endpoint
	service.Domain = DomainService
	disposition, _, first, err := ingestor.reserveMapped(evidence, []DomainEvidence{endpoint})
	if err != nil || disposition != IngestAccepted {
		t.Fatalf("first reserve failed: %s %v", disposition, err)
	}
	if err := first.commit(); err != nil {
		t.Fatal(err)
	}
	disposition, _, _, err = ingestor.reserveMapped(evidence, []DomainEvidence{service, endpoint})
	if err != nil || disposition != IngestDuplicate {
		t.Fatalf("partial duplicate not rejected atomically: %s %v", disposition, err)
	}
	if len(ingestor.pending) != 0 || len(ingestor.entries) != 1 {
		t.Fatalf("partial duplicate leaked records: pending=%d committed=%d", len(ingestor.pending), len(ingestor.entries))
	}
}

func TestObservationCommitOwnershipFailureCleansReservation(t *testing.T) {
	evidence := validEvidence()
	ingestor := NewObservationIngestor(guardFor(evidence), nil, time.Minute, 8)
	endpoint := DomainEvidence{RuntimeEpochID: evidence.RuntimeEpochID, CatalogRevision: evidence.CatalogRevision, SourceGeneration: evidence.SourceGeneration, Handle: evidence.Handle, Domain: DomainEndpoint, Outcome: OutcomeSuccess, AttemptID: evidence.AttemptID}
	service := endpoint
	service.Domain = DomainService
	_, _, reservation, err := ingestor.reserveMapped(evidence, []DomainEvidence{endpoint, service})
	if err != nil {
		t.Fatal(err)
	}
	ingestor.access.Lock()
	delete(ingestor.pending, reservation.records[0].key)
	ingestor.access.Unlock()
	if err := reservation.commit(); err == nil {
		t.Fatal("ownership loss was silently committed")
	}
	if len(ingestor.pending) != 0 {
		t.Fatalf("failed commit left pending records: %d", len(ingestor.pending))
	}
	disposition, _, retry, err := ingestor.reserveMapped(evidence, []DomainEvidence{endpoint, service})
	if err != nil || disposition != IngestAccepted || retry == nil {
		t.Fatalf("failed commit could not retry: disposition=%s err=%v", disposition, err)
	}
	retry.abort()
}

func TestRuntimeEpochGuardAcceptsRetiringRetainedHandleUntilLeaseRelease(t *testing.T) {
	manager := NewRuntimeManager()
	node := IdentityNode{NodeID: NodeID{61}, IdentityStable: true}
	first := prepareEpochForTest(t, manager, "observation-group", identitySnapshot(1, node))
	lease, err := manager.AcquireEpoch("observation-group", first.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	_ = prepareEpochForTest(t, manager, "observation-group", identitySnapshot(1, node))
	manager.RetireEpoch("observation-group", first.EpochID)
	evidence := validEvidence()
	evidence.RuntimeEpochID, evidence.CatalogRevision, evidence.SourceGeneration = first.EpochID, first.Revision, 1
	evidence.Handle = first.Handles[node.NodeID]
	ingestor := NewObservationIngestor(RuntimeEpochObservationGuard{Lease: lease}, nil, time.Minute, 8)
	if disposition, err := ingestor.Publish(evidence, &HealthObservationReducer{Store: NewHealthStore(time.Hour, 8)}); err != nil || disposition != IngestAccepted {
		t.Fatalf("retiring retained evidence rejected: disposition=%s err=%v", disposition, err)
	}
	lease.Release()
	evidence.AttemptID++
	if disposition, err := ingestor.Publish(evidence, &HealthObservationReducer{Store: NewHealthStore(time.Hour, 8)}); err != nil || disposition != IngestStale {
		t.Fatalf("released epoch lease accepted evidence: disposition=%s err=%v", disposition, err)
	}
}

func TestRuntimeEpochGuardRejectsSlotABA(t *testing.T) {
	manager := NewRuntimeManager()
	nodeID := NodeID{62}
	first := prepareEpochForTest(t, manager, "aba-group", identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	lease, err := manager.AcquireEpoch("aba-group", first.EpochID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	manager.access.Lock()
	manager.groups["aba-group"].identity.maxRetired = 1
	manager.access.Unlock()
	_ = prepareEpochForTest(t, manager, "aba-group", identitySnapshot(1))
	_ = prepareEpochForTest(t, manager, "aba-group", identitySnapshot(1, IdentityNode{NodeID: NodeID{63}, IdentityStable: true}))
	_ = prepareEpochForTest(t, manager, "aba-group", identitySnapshot(1, IdentityNode{NodeID: NodeID{64}, IdentityStable: true}))
	current := prepareEpochForTest(t, manager, "aba-group", identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	if current.Handles[nodeID].Slot == first.Handles[nodeID].Slot {
		t.Fatal("test did not evict old slot")
	}
	evidence := validEvidence()
	evidence.RuntimeEpochID, evidence.CatalogRevision, evidence.SourceGeneration = first.EpochID, first.Revision, 1
	evidence.Handle = first.Handles[nodeID]
	ingestor := NewObservationIngestor(RuntimeEpochObservationGuard{Lease: lease}, nil, time.Minute, 8)
	if disposition, err := ingestor.Publish(evidence, &HealthObservationReducer{Store: NewHealthStore(time.Hour, 8)}); err != nil || disposition != IngestStale {
		t.Fatalf("slot ABA evidence accepted: disposition=%s err=%v", disposition, err)
	}
}

func TestStaleEvidenceReleasesHalfOpenWithoutSettlement(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2000, 0)}
	store := NewHealthStoreWithClock(time.Hour, 8, clock, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	evidence := validEvidence()
	evidence.Source, evidence.Stage, evidence.ServiceID = SourceProbe, StageProxyTunnel, ""
	evidence.Handle = NodeHandle{NodeID: NodeID{65}, Slot: 8, Version: 1, BornRevision: 1}
	for range 3 {
		store.Observe(Observation{NodeID: evidence.Handle.NodeID, NodeSlot: evidence.Handle.Slot, NodeVersion: evidence.Handle.Version, Scope: DomainEndpoint, Outcome: OutcomeFailure, At: clock.Now()})
	}
	clock.Advance(time.Second)
	permit, allowed := store.TryAcquireDomainPermitHandle(evidence.Handle, DomainEndpoint, "", "", clock.Now())
	if !allowed {
		t.Fatal("half-open permit was not acquired")
	}
	staleGuard := guardFor(evidence)
	staleGuard.handle.Slot++
	ingestor := NewObservationIngestor(staleGuard, clock, time.Minute, 8)
	reducer := &HealthObservationReducer{Store: store, Settlement: AttemptPermitSettlement{Permit: permit}}
	if disposition, err := PublishSettledObservation(ingestor, evidence, reducer); err != nil || disposition != IngestStale {
		t.Fatalf("stale settlement result: disposition=%s err=%v", disposition, err)
	}
	second, allowed := store.TryAcquireDomainPermitHandle(evidence.Handle, DomainEndpoint, "", "", clock.Now())
	if !allowed {
		t.Fatal("stale evidence leaked half-open token")
	}
	second.ReleaseDeferred()
	status := store.EndpointHandle(evidence.Handle)
	if status.Successes != 0 || status.Failures != 3 {
		t.Fatalf("stale evidence settled breaker: %+v", status)
	}
}

func TestConfidenceEvidenceUpdatesQualityWithoutBreakerPollution(t *testing.T) {
	clock := &fakeClock{now: time.Unix(3000, 0)}
	store := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Second, MaxCooldown: time.Minute})
	evidence := validEvidence()
	evidence.Source, evidence.Stage, evidence.ServiceID = SourceProbe, StageProxyTunnel, ""
	evidence.Handle = NodeHandle{NodeID: NodeID{66}, Slot: 9, Version: 1, BornRevision: 1}
	evidence.Outcome, evidence.Failure, evidence.Confidence, evidence.At = OutcomeFailure, FailureTimeout, ConfidenceMedium, clock.Now()
	ingestor := NewObservationIngestor(guardFor(evidence), clock, time.Minute, 32)
	reducer := &HealthObservationReducer{Store: store}
	for attempt := AttemptID(1); attempt <= 3; attempt++ {
		evidence.AttemptID = attempt
		if _, err := ingestor.Publish(evidence, reducer); err != nil {
			t.Fatal(err)
		}
	}
	status := store.EndpointHandle(evidence.Handle)
	if status.NonBreakerFailures != 3 || status.Breaker != BreakerClosed || status.ConsecutiveFailures != 0 || status.EvidenceWeight == 0 {
		t.Fatalf("medium evidence was hidden or polluted breaker: %+v", status)
	}
	evidence.Confidence = ConfidenceHigh
	for attempt := AttemptID(4); attempt <= 6; attempt++ {
		evidence.AttemptID = attempt
		if _, err := ingestor.Publish(evidence, reducer); err != nil {
			t.Fatal(err)
		}
	}
	status = store.EndpointHandle(evidence.Handle)
	if status.Breaker != BreakerOpen || status.Failures != 3 {
		t.Fatalf("high evidence did not open breaker: %+v", status)
	}
	clock.Advance(status.Backoff)
	permit, allowed := store.TryAcquireDomainPermitHandle(evidence.Handle, DomainEndpoint, "", "", clock.Now())
	if !allowed {
		t.Fatal("high confidence recovery permit unavailable")
	}
	evidence.AttemptID, evidence.Outcome, evidence.Failure, evidence.At = 7, OutcomeSuccess, FailureNone, clock.Now()
	settled := &HealthObservationReducer{Store: store, Settlement: AttemptPermitSettlement{Permit: permit}}
	if disposition, err := PublishSettledObservation(ingestor, evidence, settled); err != nil || disposition != IngestAccepted {
		t.Fatalf("recovery settlement failed: %s %v", disposition, err)
	}
	if status = store.EndpointHandle(evidence.Handle); status.Breaker != BreakerHalfOpen || status.Successes != 1 || status.RecoverySuccesses != 1 {
		t.Fatalf("first high evidence did not enter recovery confirmation: %+v", status)
	}
	permit, allowed = store.TryAcquireDomainPermitHandle(evidence.Handle, DomainEndpoint, "", "", clock.Now())
	if !allowed {
		t.Fatal("second high confidence recovery permit unavailable")
	}
	evidence.AttemptID = 8
	settled = &HealthObservationReducer{Store: store, Settlement: AttemptPermitSettlement{Permit: permit}}
	if disposition, err := PublishSettledObservation(ingestor, evidence, settled); err != nil || disposition != IngestAccepted {
		t.Fatalf("second recovery settlement failed: %s %v", disposition, err)
	}
	if status = store.EndpointHandle(evidence.Handle); status.Breaker != BreakerClosed || status.Successes != 2 || status.RecoverySuccesses != 0 {
		t.Fatalf("second high evidence did not close half-open: %+v", status)
	}
}
