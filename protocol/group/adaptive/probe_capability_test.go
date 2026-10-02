package adaptive

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testProbeTarget(t testing.TB, name string, generation uint64, capability ProbeCapability, now time.Time) ProbeTarget {
	t.Helper()
	var byteRange *ProbeByteRange
	if capability == ProbeCapabilityRange {
		byteRange = &ProbeByteRange{Start: 0, End: 15}
	}
	target, err := NewProbeTarget("https://"+name+".example.test/media?sig=secret-"+name, generation, capability, now.Add(-time.Minute), now.Add(time.Hour), byteRange, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestProbeTargetSnapshotIsRedactedImmutableAndMonotonic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target := testProbeTarget(t, "range", 1, ProbeCapabilityRange, now)
	target, _ = target.WithRedirectHosts("cdn-secret.example.test")
	snapshot, err := NewProbeTargetSnapshot("trusted-test", "youtube", 1, now.Add(-time.Minute), now.Add(time.Hour), []ProbeTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%+v %#v", snapshot, snapshot)
	if strings.Contains(formatted, "secret-range") || strings.Contains(formatted, "?sig=") || strings.Contains(formatted, "range.example.test") || strings.Contains(formatted, "cdn-secret.example.test") {
		t.Fatalf("signed URL leaked through formatting: %s", formatted)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), "secret-range") || strings.Contains(string(encoded), "?sig=") || strings.Contains(string(encoded), "range.example.test") || strings.Contains(string(encoded), "cdn-secret.example.test") {
		t.Fatalf("signed URL leaked through JSON: %s err=%v", encoded, err)
	}
	descriptors := snapshot.Targets()
	descriptors[0].Range.End = 999
	if snapshot.Targets()[0].Range.End != 15 {
		t.Fatal("target descriptor mutation escaped deep copy")
	}
	execution, err := snapshot.executionTargets(now)
	if err != nil || !strings.Contains(execution[0].executionURL(), "secret-range") {
		t.Fatal("private execution URL was not preserved")
	}
	if execution[0].executionHost() != "range.example.test" || snapshot.Targets()[0].Host == "range.example.test" {
		t.Fatal("execution host was lost or canonical host was not redacted")
	}
	if redirects := execution[0].executionRedirectHosts(); len(redirects) != 1 || redirects[0] != "cdn-secret.example.test" || snapshot.Targets()[0].RedirectHosts[0] == redirects[0] {
		t.Fatal("redirect host redaction/deep copy failed")
	}

	catalog := NewProbeTargetCatalog(1, "trusted-test")
	if err = catalog.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = catalog.Publish(snapshot); !errorsIs(err, ErrProbeTargetRollback) {
		t.Fatalf("target generation rollback accepted: %v", err)
	}
	copySnapshot, err := catalog.Snapshot(context.Background(), "youtube")
	if err != nil {
		t.Fatal(err)
	}
	copySnapshot.targets[0].Range.End = 777
	again, _ := catalog.Snapshot(context.Background(), "youtube")
	if again.targets[0].Range.End != 15 {
		t.Fatal("catalog snapshot mutation escaped deep copy")
	}
	otherTarget := testProbeTarget(t, "other", 1, ProbeCapabilityHTTP, now)
	other, _ := NewProbeTargetSnapshot("trusted-test", "other", 1, now.Add(-time.Minute), now.Add(time.Hour), []ProbeTarget{otherTarget})
	if err = catalog.Publish(other); !errorsIs(err, ErrProbeTargetBackpressure) {
		t.Fatalf("bounded target catalog accepted a new service: %v", err)
	}
	clockAfterExpiry := now.Add(2 * time.Hour)
	if _, err = snapshot.executionTargets(clockAfterExpiry); !errorsIs(err, ErrProbeTargetExpired) {
		t.Fatalf("expired signed targets remained executable: %v", err)
	}
	nearTarget, _ := NewProbeTarget("https://near.example.test/media?token=near-secret", 2, ProbeCapabilityHTTP, now.Add(-time.Minute), now.Add(20*time.Second), nil, nil)
	nearSnapshot, _ := NewProbeTargetSnapshot("trusted-test", "near", 2, now.Add(-time.Minute), now.Add(20*time.Second), []ProbeTarget{nearTarget})
	if _, err = nearSnapshot.executionTargets(now); !errorsIs(err, ErrProbeTargetExpired) {
		t.Fatalf("near-expiry signed target remained executable: %v", err)
	}
	untrustedTarget := testProbeTarget(t, "untrusted", 2, ProbeCapabilityHTTP, now)
	untrusted, _ := NewProbeTargetSnapshot("unknown-source", "youtube", 2, now.Add(-time.Minute), now.Add(time.Hour), []ProbeTarget{untrustedTarget})
	if err = catalog.Publish(untrusted); !errorsIs(err, ErrProbeTargetUntrusted) {
		t.Fatalf("untrusted target source was accepted: %v", err)
	}
}

func errorsIs(err, target error) bool {
	return err != nil && (err == target || strings.Contains(err.Error(), target.Error()))
}

func TestSealedProbeCapabilitiesRejectedAtConstruct(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, capability := range []ProbeCapability{ProbeCapabilityAuthHTTP, ProbeCapabilityWebWAF} {
		_, err := NewProbeTarget("https://sealed.example.test/", 1, capability, now.Add(-time.Minute), now.Add(time.Hour), nil, nil)
		if err == nil {
			t.Fatalf("expected sealed capability %q to be rejected", capability)
		}
		if !strings.Contains(err.Error(), "sealed") {
			t.Fatalf("unexpected sealed rejection error for %q: %v", capability, err)
		}
	}
}

func TestClassifyProbeResultMatrix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rangeTarget := testProbeTarget(t, "range", 1, ProbeCapabilityRange, now)
	httpTarget := testProbeTarget(t, "http", 1, ProbeCapabilityHTTP, now)
	tlsTarget := testProbeTarget(t, "tls", 1, ProbeCapabilityTLS, now)
	endpointTarget := testProbeTarget(t, "endpoint", 1, ProbeCapabilityEndpoint, now)
	validRange := ProbeRawResult{TLSHandshakeOK: true, StatusCode: http.StatusPartialContent, ContentRange: "bytes 0-15/100", ContentType: "video/mp4", BytesRead: 16, PayloadPrefix: []byte{0, 1, 2}}
	tests := []struct {
		name    string
		target  ProbeTarget
		raw     ProbeRawResult
		at      time.Time
		class   ProbeSampleClass
		failure FailureClass
	}{
		{"range_success", rangeTarget, validRange, now, ProbeSampleSuccess, FailureNone},
		{"range_wrong_content_range", rangeTarget, mutateRaw(validRange, func(r *ProbeRawResult) { r.ContentRange = "bytes 1-15/100" }), now, ProbeSampleTargetFault, FailureProtocol},
		{"range_ignored_200", rangeTarget, mutateRaw(validRange, func(r *ProbeRawResult) { r.StatusCode = http.StatusOK }), now, ProbeSampleTargetFault, FailureProtocol},
		{"range_empty", rangeTarget, mutateRaw(validRange, func(r *ProbeRawResult) { r.BytesRead = 0 }), now, ProbeSampleNodeFailure, FailureNoPayload},
		{"range_html", rangeTarget, mutateRaw(validRange, func(r *ProbeRawResult) { r.ContentType = "text/html"; r.PayloadPrefix = []byte("<html>error") }), now, ProbeSampleNodeFailure, FailureProtocol},
		{"http_403", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 403}, now, ProbeSampleBlocked, FailureHTTPBlock},
		{"http_451", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 451}, now, ProbeSampleBlocked, FailureHTTPBlock},
		{"http_404", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 404}, now, ProbeSampleTargetFault, FailureProtocol},
		{"http_410", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 410}, now, ProbeSampleTargetFault, FailureProtocol},
		{"http_429", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 429}, now, ProbeSampleTargetFault, FailureProtocol},
		{"http_503", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 503}, now, ProbeSampleTargetFault, FailureProtocol},
		{"tls_failure", tlsTarget, ProbeRawResult{}, now, ProbeSampleNodeFailure, FailureTLS},
		{"tls_success", tlsTarget, ProbeRawResult{TLSHandshakeOK: true}, now, ProbeSampleSuccess, FailureNone},
		{"endpoint_success", endpointTarget, ProbeRawResult{EndpointHandshakeOK: true}, now, ProbeSampleSuccess, FailureNone},
		{"endpoint_empty", endpointTarget, ProbeRawResult{}, now, ProbeSampleNodeFailure, FailureProtocol},
		{"timeout", httpTarget, ProbeRawResult{TimedOut: true}, now, ProbeSampleNodeFailure, FailureTimeout},
		{"canceled", httpTarget, ProbeRawResult{Canceled: true}, now, ProbeSampleDeferred, FailureCanceled},
		{"redirect_policy", httpTarget, ProbeRawResult{TargetPolicyErr: true}, now, ProbeSampleTargetFault, FailureProtocol},
		{"expired_signed_url", httpTarget, ProbeRawResult{TLSHandshakeOK: true, StatusCode: 200, BytesRead: 1}, now.Add(2 * time.Hour), ProbeSampleTargetFault, FailureProtocol},
		{"near_expiry_signed_url", func() ProbeTarget { target := httpTarget; target.ExpiresAt = now.Add(20 * time.Second); return target }(), ProbeRawResult{TLSHandshakeOK: true, StatusCode: 200, BytesRead: 1}, now, ProbeSampleTargetFault, FailureProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classification := ClassifyProbeResult(test.target, test.raw, test.at)
			if classification.Class != test.class || classification.Failure != test.failure {
				t.Fatalf("unexpected classification: %+v", classification)
			}
		})
	}

	digest := sha256.Sum256([]byte("expected"))
	digestTarget := rangeTarget
	digestTarget.ExpectedDigest = digest
	digestTarget.HasDigest = true
	wrongDigest := validRange
	wrongDigest.HasDigest = true
	wrongDigest.Digest = sha256.Sum256([]byte("wrong"))
	if got := ClassifyProbeResult(digestTarget, wrongDigest, now); got.Class != ProbeSampleNodeFailure {
		t.Fatalf("payload digest mismatch accepted: %+v", got)
	}
}

func mutateRaw(source ProbeRawResult, mutate func(*ProbeRawResult)) ProbeRawResult {
	cloned := source
	cloned.PayloadPrefix = append([]byte(nil), source.PayloadPrefix...)
	mutate(&cloned)
	return cloned
}

func testRunSpec(t testing.TB, runID ProbeSuiteRunID, now time.Time, class ProbeSuiteClass) (ProbeRunSpec, []NodeHandle, []ProbeTargetDescriptor) {
	t.Helper()
	nodes := []NodeHandle{
		{NodeID: NodeID{1}, Slot: 1, Version: 1, BornRevision: 1},
		{NodeID: NodeID{2}, Slot: 2, Version: 1, BornRevision: 1},
		{NodeID: NodeID{3}, Slot: 3, Version: 1, BornRevision: 1},
	}
	targets := make([]ProbeTargetDescriptor, 3)
	capability := ProbeCapabilityRange
	if class == ProbeSuiteEndpointRecovery {
		capability = ProbeCapabilityEndpoint
	}
	for index, name := range []string{"a", "b", "c"} {
		targets[index] = testProbeTarget(t, name, 7, capability, now).Descriptor()
	}
	service := "youtube"
	source := SourceHTTP
	if class == ProbeSuiteEndpointRecovery {
		service = ""
		source = SourceProbe
	}
	return ProbeRunSpec{
		RunID: runID, Class: class, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: service, Source: source, TargetGeneration: 7, Nodes: nodes, Targets: targets, Quorum: 2, CommonModeMinNodes: 3, Deadline: now.Add(time.Minute),
	}, nodes, targets
}

func sampleFor(spec ProbeRunSpec, handle NodeHandle, target ProbeTargetDescriptor, class ProbeSampleClass, failure FailureClass, now time.Time) ProbeSample {
	return ProbeSample{
		RunID: spec.RunID, Suite: spec.Class, RuntimeEpochID: spec.RuntimeEpochID, CatalogRevision: spec.CatalogRevision, SourceGeneration: spec.SourceGeneration,
		Handle: handle, TargetID: target.ID, TargetGeneration: spec.TargetGeneration, ServiceID: spec.ServiceID, Capability: target.Capability, Class: class, Failure: failure, At: now,
	}
}

func verdictFor(t *testing.T, result ProbeRunResult, handle NodeHandle) ProbeVerdict {
	t.Helper()
	for _, verdict := range result.Verdicts {
		if verdict.Handle == handle {
			return verdict
		}
	}
	t.Fatal("node verdict not found")
	return ProbeVerdict{}
}

func TestProbeAggregatorQuorumAndFailureDomainIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	for _, test := range []struct {
		name    string
		class   ProbeSuiteClass
		samples ProbeSampleClass
		failure FailureClass
		outcome ObservationOutcome
		domain  FailureDomain
	}{
		{"service_success", ProbeSuiteServiceCapability, ProbeSampleSuccess, FailureNone, OutcomeSuccess, DomainService},
		{"service_blocked", ProbeSuiteServiceCapability, ProbeSampleBlocked, FailureHTTPBlock, OutcomeBlocked, DomainService},
		{"service_tls_failure", ProbeSuiteServiceCapability, ProbeSampleNodeFailure, FailureTLS, OutcomeFailure, DomainService},
		{"endpoint_success", ProbeSuiteEndpointRecovery, ProbeSampleSuccess, FailureNone, OutcomeSuccess, DomainEndpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil)
			spec, nodes, targets := testRunSpec(t, 1, now, test.class)
			if _, err := aggregator.Begin(spec); err != nil {
				t.Fatal(err)
			}
			for _, target := range targets[:2] {
				if disposition, err := aggregator.Ingest(sampleFor(spec, nodes[0], target, test.samples, test.failure, now)); err != nil || disposition != ProbeAggregateAccepted {
					t.Fatalf("ingest failed: disposition=%s err=%v", disposition, err)
				}
			}
			result, err := aggregator.Complete(spec.RunID)
			if err != nil {
				t.Fatal(err)
			}
			verdict := verdictFor(t, result, nodes[0])
			if !verdict.Authoritative || verdict.Outcome != test.outcome || verdict.Domain != test.domain || verdict.Support != 2 {
				t.Fatalf("unexpected quorum verdict: %+v", verdict)
			}
			if test.class == ProbeSuiteEndpointRecovery && verdict.ServiceID != "" || test.class == ProbeSuiteServiceCapability && verdict.ServiceID != "youtube" {
				t.Fatalf("failure domain leaked across suite: %+v", verdict)
			}
		})
	}
}

func TestProbeSuiteRejectsCrossDomainCapabilities(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, &fakeClock{now: now}, nil)
	endpoint, _, _ := testRunSpec(t, 30, now, ProbeSuiteEndpointRecovery)
	endpoint.Targets[0] = testProbeTarget(t, "service-in-endpoint", 7, ProbeCapabilityTLS, now).Descriptor()
	if _, err := aggregator.Begin(endpoint); err == nil {
		t.Fatal("TLS target entered endpoint recovery suite")
	}
	service, _, _ := testRunSpec(t, 31, now, ProbeSuiteServiceCapability)
	service.Targets[0] = testProbeTarget(t, "endpoint-in-service", 7, ProbeCapabilityEndpoint, now).Descriptor()
	if _, err := aggregator.Begin(service); err == nil {
		t.Fatal("endpoint target entered service capability suite")
	}
}

func TestProbeAggregatorSuppressesCommonModeTargetFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, &fakeClock{now: now}, nil)
	spec, nodes, targets := testRunSpec(t, 2, now, ProbeSuiteServiceCapability)
	if _, err := aggregator.Begin(spec); err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if _, err := aggregator.Ingest(sampleFor(spec, node, targets[0], ProbeSampleBlocked, FailureHTTPBlock, now)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := aggregator.Complete(spec.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].TargetID != targets[0].ID || result.Incidents[0].Nodes != 3 {
		t.Fatalf("common-mode incident missing: %+v", result.Incidents)
	}
	for _, node := range nodes {
		verdict := verdictFor(t, result, node)
		if verdict.Authoritative || verdict.Outcome != OutcomeDeferred {
			t.Fatalf("common target failure opened node verdict: %+v", verdict)
		}
	}
}

func TestProbeAggregatorKeepsMinorityFailuresInLargePool(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, &fakeClock{now: now}, nil)
	target := testProbeTarget(t, "large-pool", 7, ProbeCapabilityHTTP, now).Descriptor()
	nodes := make([]NodeHandle, 16)
	for index := range nodes {
		nodes[index] = NodeHandle{NodeID: NodeID{byte(index + 1)}, Slot: uint64(index + 1), Version: 1, BornRevision: 1}
	}
	spec := ProbeRunSpec{
		RunID: 20, Class: ProbeSuiteServiceCapability, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: "chatgpt", Source: SourceHTTP, TargetGeneration: 7, Nodes: nodes, Targets: []ProbeTargetDescriptor{target},
		Quorum: 1, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	}
	if _, err := aggregator.Begin(spec); err != nil {
		t.Fatal(err)
	}
	for index, node := range nodes {
		class, failure := ProbeSampleSuccess, FailureNone
		if index < 2 {
			class, failure = ProbeSampleBlocked, FailureHTTPBlock
		}
		if _, err := aggregator.Ingest(sampleFor(spec, node, target, class, failure, now)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := aggregator.Complete(spec.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Incidents) != 0 {
		t.Fatalf("minority failures suppressed the target: %+v", result.Incidents)
	}
	for index, node := range nodes {
		verdict := verdictFor(t, result, node)
		expected := OutcomeSuccess
		if index < 2 {
			expected = OutcomeBlocked
		}
		if !verdict.Authoritative || verdict.Outcome != expected {
			t.Fatalf("unexpected node %d verdict: %+v", index, verdict)
		}
	}
}

type rejectingProbeSampleGuard struct{}

func (rejectingProbeSampleGuard) ValidateProbeSample(ProbeSample) bool { return false }

func TestProbeAggregatorDedupStaleBackpressureAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	config := ProbeAggregatorConfig{MaxPendingRuns: 1, MaxCommittedRuns: 1, MaxSamplesPerRun: 9, Retention: time.Minute}
	aggregator := NewProbeAggregator(config, clock, nil)
	spec1, nodes, targets := testRunSpec(t, 10, now, ProbeSuiteServiceCapability)
	if disposition, err := aggregator.Begin(spec1); err != nil || disposition != ProbeAggregateAccepted {
		t.Fatalf("begin failed: %s %v", disposition, err)
	}
	spec2 := spec1
	spec2.RunID = 11
	if disposition, err := aggregator.Begin(spec2); disposition != ProbeAggregateBackpressure || !errorsIs(err, ErrProbeRunBackpressure) {
		t.Fatalf("pending run was evicted: %s %v", disposition, err)
	}
	sample := sampleFor(spec1, nodes[0], targets[0], ProbeSampleSuccess, FailureNone, now)
	if disposition, err := aggregator.Ingest(sample); err != nil || disposition != ProbeAggregateAccepted {
		t.Fatalf("sample not accepted: %s %v", disposition, err)
	}
	if disposition, err := aggregator.Ingest(sample); err != nil || disposition != ProbeAggregateDuplicate {
		t.Fatalf("duplicate sample reduced twice: %s %v", disposition, err)
	}
	stale := sample
	stale.Handle.Slot++
	if disposition, err := aggregator.Ingest(stale); disposition != ProbeAggregateStale || !errorsIs(err, ErrProbeSampleIdentity) {
		t.Fatalf("slot-stale sample accepted: %s %v", disposition, err)
	}
	early := sample
	early.TargetID = targets[1].ID
	early.At = now.Add(-time.Nanosecond)
	if disposition, err := aggregator.Ingest(early); disposition != ProbeAggregateStale || !errorsIs(err, ErrProbeSampleIdentity) {
		t.Fatalf("pre-begin sample accepted: %s %v", disposition, err)
	}
	for name, mutate := range map[string]func(*ProbeSample){
		"revision":   func(sample *ProbeSample) { sample.CatalogRevision++ },
		"generation": func(sample *ProbeSample) { sample.SourceGeneration++ },
		"target_gen": func(sample *ProbeSample) { sample.TargetGeneration++ },
		"suite":      func(sample *ProbeSample) { sample.Suite = ProbeSuiteEndpointRecovery },
		"service":    func(sample *ProbeSample) { sample.ServiceID = "other" },
		"capability": func(sample *ProbeSample) { sample.Capability = ProbeCapabilityTLS },
	} {
		t.Run("stale_"+name, func(t *testing.T) {
			candidate := sample
			candidate.TargetID = targets[2].ID
			mutate(&candidate)
			if disposition, err := aggregator.Ingest(candidate); disposition != ProbeAggregateStale || !errorsIs(err, ErrProbeSampleIdentity) {
				t.Fatalf("identity mismatch accepted: %s %v", disposition, err)
			}
		})
	}
	if _, err := aggregator.Complete(spec1.RunID); err != nil {
		t.Fatal(err)
	}
	if disposition, err := aggregator.Ingest(sample); err != nil || disposition != ProbeAggregateLate {
		t.Fatalf("late sample was not rejected: %s %v", disposition, err)
	}
	if disposition, err := aggregator.Begin(spec2); err != nil || disposition != ProbeAggregateAccepted {
		t.Fatalf("capacity not released after commit: %s %v", disposition, err)
	}
	if _, err := aggregator.Complete(spec2.RunID); err != nil {
		t.Fatal(err)
	}
	if _, loaded := aggregator.Result(spec1.RunID); loaded {
		t.Fatal("committed O(1) capacity did not evict oldest result")
	}

	expiring := spec1
	expiring.RunID = 12
	expiring.Deadline = now.Add(time.Second)
	if _, err := aggregator.Begin(expiring); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	if pending, _ := aggregator.Stats(); pending != 0 {
		t.Fatalf("deadline heap did not complete expired run: pending=%d", pending)
	}
	if result, loaded := aggregator.Result(expiring.RunID); !loaded || verdictFor(t, result, nodes[0]).Authoritative {
		t.Fatal("expired insufficient-quorum run did not become deferred")
	}

	guarded := NewProbeAggregator(ProbeAggregatorConfig{}, clock, rejectingProbeSampleGuard{})
	guardedSpec := spec1
	guardedSpec.RunID = 13
	guardedSpec.Deadline = clock.Now().Add(time.Minute)
	if _, err := guarded.Begin(guardedSpec); err != nil {
		t.Fatal(err)
	}
	guardedSample := sampleFor(guardedSpec, nodes[0], targets[0], ProbeSampleSuccess, FailureNone, clock.Now())
	if disposition, err := guarded.Ingest(guardedSample); disposition != ProbeAggregateStale || !errorsIs(err, ErrProbeSampleIdentity) {
		t.Fatalf("guard-rejected sample accepted: %s %v", disposition, err)
	}
}

type collectingProbeObservationSink struct{ evidence []ObservationEvidence }

func (s *collectingProbeObservationSink) PublishProbeObservation(_ context.Context, evidence ObservationEvidence) (IngestDisposition, error) {
	s.evidence = append(s.evidence, evidence)
	return IngestAccepted, nil
}

func TestProbeVerdictsOnlyPublishThroughObservationContract(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, &fakeClock{now: now}, nil)
	spec, nodes, targets := testRunSpec(t, 20, now, ProbeSuiteServiceCapability)
	if _, err := aggregator.Begin(spec); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets[:2] {
		if _, err := aggregator.Ingest(sampleFor(spec, nodes[0], target, ProbeSampleBlocked, FailureHTTPBlock, now)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := aggregator.Complete(spec.RunID)
	if err != nil {
		t.Fatal(err)
	}
	sink := new(collectingProbeObservationSink)
	if err = PublishProbeRunResult(context.Background(), result, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.evidence) != 1 {
		t.Fatalf("deferred verdict escaped to observation sink: %d", len(sink.evidence))
	}
	evidence := sink.evidence[0]
	if evidence.RuntimeEpochID != spec.RuntimeEpochID || evidence.CatalogRevision != spec.CatalogRevision || evidence.SourceGeneration != spec.SourceGeneration || evidence.Handle != nodes[0] || evidence.Stage != StageServiceApplication || evidence.Source != SourceHTTP || evidence.Outcome != OutcomeBlocked || evidence.Failure != FailureHTTPBlock || evidence.Confidence != ConfidenceAuthoritative {
		t.Fatalf("probe verdict lost observation identity: %+v", evidence)
	}
	if _, err = verdictFor(t, ProbeRunResult{Verdicts: []ProbeVerdict{{Handle: nodes[1]}}}, nodes[1]).Observation(now); err == nil {
		t.Fatal("non-authoritative verdict converted to observation")
	}
}

func BenchmarkProbeAggregator100kBoundedChurn(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{MaxPendingRuns: 1, MaxCommittedRuns: 64, MaxSamplesPerRun: 1, Retention: time.Hour}, clock, nil)
	node := NodeHandle{NodeID: NodeID{1}, Slot: 1, Version: 1, BornRevision: 1}
	target := testProbeTarget(b, "benchmark", 1, ProbeCapabilityEndpoint, now).Descriptor()
	b.ReportAllocs()
	for iteration := 0; iteration < b.N; iteration++ {
		for index := 1; index <= 100_000; index++ {
			runID := ProbeSuiteRunID(iteration*100_000 + index)
			spec := ProbeRunSpec{RunID: runID, Class: ProbeSuiteEndpointRecovery, RuntimeEpochID: 1, CatalogRevision: 1, SourceGeneration: 1, Source: SourceProbe, TargetGeneration: 1, Nodes: []NodeHandle{node}, Targets: []ProbeTargetDescriptor{target}, Quorum: 1, CommonModeMinNodes: 2, Deadline: now.Add(30 * time.Minute)}
			if _, err := aggregator.Begin(spec); err != nil {
				b.Fatal(err)
			}
			if _, err := aggregator.Ingest(sampleFor(spec, node, target, ProbeSampleSuccess, FailureNone, now)); err != nil {
				b.Fatal(err)
			}
			if _, err := aggregator.Complete(spec.RunID); err != nil {
				b.Fatal(err)
			}
		}
	}
	pending, committed := aggregator.Stats()
	if pending != 0 || committed > 64 || aggregator.deadlines.Len() != 0 {
		b.Fatalf("aggregator escaped bounds: pending=%d committed=%d deadlines=%d", pending, committed, aggregator.deadlines.Len())
	}
}
