package adaptive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type signedTargetFetcherFunc func(context.Context) (*SignedProbeTargetManifest, error)

func (f signedTargetFetcherFunc) FetchSignedProbeTargets(ctx context.Context) (*SignedProbeTargetManifest, error) {
	return f(ctx)
}

func youtubeTargetSnapshot(t testing.TB, now time.Time, generation uint64) *ProbeTargetSnapshot {
	t.Helper()
	targets := make([]ProbeTarget, 0, 2)
	for _, name := range []string{"video-a", "video-b"} {
		target, err := NewProbeTarget(
			"https://"+name+".googlevideo.example.test/videoplayback?expire=secret&sig=private-"+name,
			generation, ProbeCapabilityRange, now.Add(-time.Minute), now.Add(10*time.Minute),
			&ProbeByteRange{Start: 0, End: 15}, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	snapshot, err := NewProbeTargetSnapshot(
		youtubeTargetSourceID, youtubeProbeServiceID, generation,
		now.Add(-time.Minute), now.Add(10*time.Minute), targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func signedYouTubeManifest(t testing.TB, snapshot *ProbeTargetSnapshot, keyID string, privateKey ed25519.PrivateKey, sourceID string) *SignedProbeTargetManifest {
	t.Helper()
	wire := signedProbeManifestWire{
		SourceID: sourceID, ServiceID: snapshot.ServiceID, Generation: snapshot.Generation,
		IssuedAt: snapshot.IssuedAt.Unix(), ExpiresAt: snapshot.ExpiresAt.Unix(), Targets: make([]signedProbeTargetWire, len(snapshot.targets)),
	}
	for index, target := range snapshot.targets {
		encoded := signedProbeTargetWire{URL: target.executionURL(), Capability: target.Capability, RedirectHosts: target.executionRedirectHosts()}
		if target.Range != nil {
			start, end := target.Range.Start, target.Range.End
			encoded.RangeStart, encoded.RangeEnd = &start, &end
		}
		if target.HasDigest {
			encoded.ExpectedDigest = hex.EncodeToString(target.ExpectedDigest[:])
		}
		wire.Targets[index] = encoded
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewSignedProbeTargetManifest(keyID, payload, ed25519.Sign(privateKey, payload))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func newYouTubeProvider(t testing.TB, clock Clock, snapshot *ProbeTargetSnapshot) *TrustedYouTubeTargetProvider {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := signedYouTubeManifest(t, snapshot, "test-key", privateKey, youtubeTargetSourceID)
	provider, err := NewTrustedYouTubeTargetProvider(clock, signedTargetFetcherFunc(func(context.Context) (*SignedProbeTargetManifest, error) {
		return manifest, nil
	}), map[string]ed25519.PublicKey{"test-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestTrustedYouTubeTargetProviderRefreshIsDynamicAtomicAndRedacted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var access sync.Mutex
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 1), "key-a", privateKey, youtubeTargetSourceID)
	provider, err := NewTrustedYouTubeTargetProvider(&fakeClock{now: now}, signedTargetFetcherFunc(func(context.Context) (*SignedProbeTargetManifest, error) {
		access.Lock()
		defer access.Unlock()
		return current, nil
	}), map[string]ed25519.PublicKey{"key-a": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil || first.Generation != 1 {
		t.Fatalf("initial dynamic target snapshot missing: generation=%d err=%v", first.Generation, err)
	}
	encodedManifest, _ := json.Marshal(current)
	formatted := fmt.Sprintf("%+v %#v %s", provider, first, encodedManifest)
	if strings.Contains(formatted, "videoplayback") || strings.Contains(formatted, "googlevideo.example.test") || strings.Contains(formatted, "private-video") || strings.Contains(formatted, "?expire=") {
		t.Fatalf("signed target leaked through provider state: %s", formatted)
	}

	access.Lock()
	current = signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 2), "key-a", privateKey, youtubeTargetSourceID)
	access.Unlock()
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, _ := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if second.Generation != 2 {
		t.Fatalf("dynamic generation did not advance: %d", second.Generation)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatalf("identical signed target generation was not idempotent: %v", err)
	}
	conflicting := youtubeTargetSnapshot(t, now, 2)
	conflictingTarget, targetErr := NewProbeTarget(
		"https://different.googlevideo.example.test/videoplayback?token=conflict", 2, ProbeCapabilityRange,
		now.Add(-time.Minute), now.Add(10*time.Minute), &ProbeByteRange{Start: 0, End: 15}, nil,
	)
	if targetErr != nil {
		t.Fatal(targetErr)
	}
	conflicting.targets[0] = conflictingTarget
	access.Lock()
	current = signedYouTubeManifest(t, conflicting, "key-a", privateKey, youtubeTargetSourceID)
	access.Unlock()
	if err = provider.Refresh(context.Background()); !errors.Is(err, ErrProbeTargetUntrusted) {
		t.Fatalf("same generation with different signed content was accepted: %v", err)
	}

	untrusted := signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 3), "key-a", privateKey, "caller-supplied")
	access.Lock()
	current = untrusted
	access.Unlock()
	if err = provider.Refresh(context.Background()); !errorsIs(err, ErrProbeTargetUntrusted) {
		t.Fatalf("untrusted target source crossed provider boundary: %v", err)
	}
	retained, _ := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if retained.Generation != 2 {
		t.Fatalf("failed refresh changed active target snapshot: %d", retained.Generation)
	}
}

func TestTrustedYouTubeTargetProviderAuthenticatesManifestAndRotatesKeys(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := map[string]ed25519.PublicKey{"key-a": publicA, "key-b": publicB}
	current := signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 1), "key-a", privateA, youtubeTargetSourceID)
	provider, err := NewTrustedYouTubeTargetProvider(clock, signedTargetFetcherFunc(func(context.Context) (*SignedProbeTargetManifest, error) {
		return current, nil
	}), keyring)
	if err != nil {
		t.Fatal(err)
	}
	for index := range publicA {
		publicA[index] = 0
	}
	delete(keyring, "key-b")
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatalf("provider did not deep-copy its trust roots: %v", err)
	}

	original := current
	tampered := *original
	tampered.payload = &redactedProbeURL{value: original.payload.value + " "}
	current = &tampered
	if err = provider.Refresh(context.Background()); !errors.Is(err, ErrProbeTargetUntrusted) {
		t.Fatalf("tampered payload was not rejected: %v", err)
	}
	retained, _ := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if retained.Generation != 1 {
		t.Fatalf("tampered refresh changed active generation: %d", retained.Generation)
	}

	unknownPublic, unknownPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(unknownPublic) == 0 {
		t.Fatal(err)
	}
	current = signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 2), "unknown-key", unknownPrivate, youtubeTargetSourceID)
	if err = provider.Refresh(context.Background()); !errors.Is(err, ErrProbeTargetUntrusted) {
		t.Fatalf("unknown signing key was accepted: %v", err)
	}

	current = signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 2), "key-b", privateB, youtubeTargetSourceID)
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatalf("configured rotation key was rejected: %v", err)
	}
	rotated, _ := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if rotated.Generation != 2 {
		t.Fatalf("rotation manifest did not publish: %d", rotated.Generation)
	}
	current = signedYouTubeManifest(t, youtubeTargetSnapshot(t, now.Add(-20*time.Minute), 3), "key-b", privateB, youtubeTargetSourceID)
	if err = provider.Refresh(context.Background()); !errors.Is(err, ErrProbeTargetExpired) {
		t.Fatalf("expired signed manifest was accepted: %v", err)
	}
	retained, _ = provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if retained.Generation != 2 {
		t.Fatalf("expired refresh changed active generation: %d", retained.Generation)
	}

	current = nil
	fetchErrorProvider, err := NewTrustedYouTubeTargetProvider(clock, signedTargetFetcherFunc(func(context.Context) (*SignedProbeTargetManifest, error) {
		return nil, errors.New("https://secret.example/videoplayback?token=must-not-leak")
	}), map[string]ed25519.PublicKey{"key-b": publicB})
	if err != nil {
		t.Fatal(err)
	}
	if err = fetchErrorProvider.Refresh(context.Background()); !errors.Is(err, ErrProbeTargetFetch) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token") {
		t.Fatalf("fetch failure leaked private target data: %v", err)
	}
}

func TestCapabilityProbeSuiteUsesSingleSchedulerAggregatorAndObservationSink(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	snapshot := youtubeTargetSnapshot(t, now, 1)
	provider := newYouTubeProvider(t, clock, snapshot)
	var err error
	handle := NodeHandle{NodeID: NodeID{1}, Slot: 2, Version: 3, BornRevision: 1}
	health := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	health.Observe(Observation{
		NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
		Scope: DomainService, Service: youtubeProbeServiceID, Outcome: OutcomeFailure, At: now.Add(-time.Second),
	})
	var checkedHalfOpen sync.Once
	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(_ context.Context, _ N.Dialer, target ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(request *http.Request) (*http.Response, error) {
			checkedHalfOpen.Do(func() {
				if competing, allowed := health.TryAcquireDomainPermitHandle(handle, DomainService, "", youtubeProbeServiceID, now); allowed {
					competing.ReleaseDeferred()
					t.Error("capability suite did not own the single half-open permit")
				}
			})
			if request.URL.String() != target.executionURL() {
				t.Fatal("scheduler task did not bind its private target")
			}
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				TLS:        &tls.ConnectionState{},
				Header: http.Header{
					"Content-Range": []string{"bytes 0-15/100"},
					"Content-Type":  []string{"video/mp4"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte("0123456789abcdef"))),
			}, nil
		}}, nil
	}
	scheduler := NewProbeScheduler(context.Background(), 2, 16)
	defer scheduler.Close()
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil)
	guard := staticObservationGuard{epochID: 11, revision: 12, sourceGeneration: 13, handle: handle}
	ingestor := NewObservationIngestor(nil, clock, time.Minute, 16)
	collected := new(collectingEvidenceReducer)
	reducer := &HealthObservationReducer{Store: health, BeforeReduce: collected.Reduce}
	sink, err := NewIngestingProbeObservationSink(ingestor, guard, reducer)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &countingCapabilitySessionFactory{session: sink}
	suite, err := NewCapabilityProbeSuite(clock, scheduler, provider, runner, aggregator, sessions)
	if err != nil {
		t.Fatal(err)
	}
	result, err := suite.Run(context.Background(), CapabilitySuiteRequest{
		RunID: 41, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: youtubeProbeServiceID, Nodes: []CapabilitySuiteNode{{Handle: handle, Dialer: newTestOutbound("suite")}},
		Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Verdicts) != 1 || !result.Verdicts[0].Authoritative || result.Verdicts[0].Outcome != OutcomeSuccess || result.Verdicts[0].Domain != DomainService {
		t.Fatalf("unexpected suite verdict: %+v", result)
	}
	if len(collected.evidence) != 1 {
		t.Fatalf("suite bypassed or failed ingestor/reducer: evidence=%d", len(collected.evidence))
	}
	evidence := collected.evidence[0]
	if evidence.Handle != handle || evidence.RuntimeEpochID != 11 || evidence.CatalogRevision != 12 || evidence.SourceGeneration != 13 || evidence.ServiceID != youtubeProbeServiceID || evidence.Stage != StageServiceApplication {
		t.Fatalf("observation identity/domain changed across suite: %+v", evidence)
	}
	_, _, completed := scheduler.Stats()
	if completed != 2 {
		t.Fatalf("targets bypassed the single scheduler: completed=%d", completed)
	}
	if status := health.StatusHandle(handle, DomainService, "", youtubeProbeServiceID); status.Health != HealthDegraded || status.Breaker != BreakerHalfOpen || !status.HalfOpen || status.RecoverySuccesses != 1 {
		t.Fatalf("authoritative suite verdict did not enter recovery confirmation: %+v", status)
	}
	if opened, closed := sessions.stats(); opened != 1 || closed != 1 {
		t.Fatalf("accepted suite did not own exactly one observation session: opened=%d closed=%d", opened, closed)
	}
	if _, err = suite.Run(context.Background(), CapabilitySuiteRequest{
		RunID: 41, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: youtubeProbeServiceID, Nodes: []CapabilitySuiteNode{{Handle: handle, Dialer: newTestOutbound("duplicate")}},
		Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	}); err == nil {
		t.Fatal("duplicate RunID submitted scheduler tasks")
	}
	_, _, completedAfterDuplicate := scheduler.Stats()
	if completedAfterDuplicate != completed {
		t.Fatalf("duplicate RunID executed new tasks: before=%d after=%d", completed, completedAfterDuplicate)
	}
	if opened, closed := sessions.stats(); opened != 1 || closed != 1 {
		t.Fatalf("duplicate RunID opened an observation session: opened=%d closed=%d", opened, closed)
	}
}

func TestCapabilityProbeSuiteCommonModeReleasesHalfOpenPermits(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	snapshot := youtubeTargetSnapshot(t, now, 1)
	provider := newYouTubeProvider(t, clock, snapshot)
	var err error
	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(_ context.Context, _ N.Dialer, _ ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden, TLS: &tls.ConnectionState{},
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("blocked")),
			}, nil
		}}, nil
	}
	scheduler := NewProbeScheduler(context.Background(), 4, 16)
	defer scheduler.Close()
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil)
	handles := []NodeHandle{
		{NodeID: NodeID{31}, Slot: 1, Version: 1, BornRevision: 1},
		{NodeID: NodeID{32}, Slot: 2, Version: 1, BornRevision: 1},
	}
	health := NewHealthStoreWithClock(time.Hour, 32, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	for _, handle := range handles {
		health.Observe(Observation{
			NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
			Scope: DomainService, Service: youtubeProbeServiceID, Outcome: OutcomeFailure, At: now.Add(-time.Second),
		})
	}
	ingestor := NewObservationIngestor(nil, clock, time.Minute, 16)
	guard := staticObservationGuard{epochID: 11, revision: 12, sourceGeneration: 13, handle: handles[0]}
	sink, err := NewIngestingProbeObservationSink(ingestor, guard, &HealthObservationReducer{Store: health})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &countingCapabilitySessionFactory{session: sink}
	suite, err := NewCapabilityProbeSuite(clock, scheduler, provider, runner, aggregator, sessions)
	if err != nil {
		t.Fatal(err)
	}
	result, err := suite.Run(context.Background(), CapabilitySuiteRequest{
		RunID: 42, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: youtubeProbeServiceID,
		Nodes: []CapabilitySuiteNode{
			{Handle: handles[0], Dialer: newTestOutbound("common-a")},
			{Handle: handles[1], Dialer: newTestOutbound("common-b")},
		},
		Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Incidents) != 2 {
		t.Fatalf("cross-node target failures were not isolated as common-mode: %+v", result)
	}
	for _, verdict := range result.Verdicts {
		if verdict.Authoritative {
			t.Fatalf("common-mode failure produced node verdict: %+v", verdict)
		}
	}
	for _, handle := range handles {
		status := health.StatusHandle(handle, DomainService, "", youtubeProbeServiceID)
		if status.Breaker == BreakerClosed || status.HalfOpen {
			t.Fatalf("deferred common-mode verdict leaked half-open permit: handle=%+v status=%+v", handle, status)
		}
	}
}

func TestCapabilityProbeSuiteReducerFailureRollsBackAndReleasesPermit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	snapshot := youtubeTargetSnapshot(t, now, 1)
	provider := newYouTubeProvider(t, clock, snapshot)
	var err error
	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(_ context.Context, _ N.Dialer, _ ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPartialContent, TLS: &tls.ConnectionState{},
				Header: http.Header{"Content-Range": []string{"bytes 0-15/100"}, "Content-Type": []string{"video/mp4"}},
				Body:   io.NopCloser(strings.NewReader("0123456789abcdef")),
			}, nil
		}}, nil
	}
	scheduler := NewProbeScheduler(context.Background(), 2, 16)
	defer scheduler.Close()
	handle := NodeHandle{NodeID: NodeID{41}, Slot: 1, Version: 1, BornRevision: 1}
	health := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	health.Observe(Observation{
		NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
		Scope: DomainService, Service: youtubeProbeServiceID, Outcome: OutcomeFailure, At: now.Add(-time.Second),
	})
	ingestor := NewObservationIngestor(nil, clock, time.Minute, 16)
	guard := staticObservationGuard{epochID: 11, revision: 12, sourceGeneration: 13, handle: handle}
	reducer := &HealthObservationReducer{
		Store: health,
		BeforeReduce: func(ObservationEvidence, []DomainEvidence) error {
			return errors.New("injected reducer failure")
		},
	}
	sink, err := NewIngestingProbeObservationSink(ingestor, guard, reducer)
	if err != nil {
		t.Fatal(err)
	}
	suite, err := NewCapabilityProbeSuite(clock, scheduler, provider, runner, NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil), sink)
	if err != nil {
		t.Fatal(err)
	}
	_, err = suite.Run(context.Background(), CapabilitySuiteRequest{
		RunID: 43, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: youtubeProbeServiceID, Nodes: []CapabilitySuiteNode{{Handle: handle, Dialer: newTestOutbound("reducer-failure")}},
		Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	})
	if err == nil {
		t.Fatal("reducer failure was hidden")
	}
	status := health.StatusHandle(handle, DomainService, "", youtubeProbeServiceID)
	if status.Breaker == BreakerClosed || status.HalfOpen {
		t.Fatalf("reducer failure leaked or incorrectly settled half-open permit: %+v", status)
	}
	ingestor.access.Lock()
	pending := len(ingestor.pending)
	ingestor.access.Unlock()
	if pending != 0 {
		t.Fatalf("reducer failure retained transactional dedup reservations: %d", pending)
	}
}

func TestCapabilityProbeSuiteCancellationAbortsAndReleasesPermit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	snapshot := youtubeTargetSnapshot(t, now, 1)
	provider := newYouTubeProvider(t, clock, snapshot)
	var err error

	requestStarted := make(chan struct{})
	var startedOnce sync.Once
	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(_ context.Context, _ N.Dialer, _ ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(request *http.Request) (*http.Response, error) {
			startedOnce.Do(func() { close(requestStarted) })
			<-request.Context().Done()
			return nil, request.Context().Err()
		}}, nil
	}
	scheduler := NewProbeScheduler(context.Background(), 1, 8)
	defer scheduler.Close()
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil)
	handle := NodeHandle{NodeID: NodeID{51}, Slot: 1, Version: 1, BornRevision: 1}
	health := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	health.Observe(Observation{
		NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version,
		Scope: DomainService, Service: youtubeProbeServiceID, Outcome: OutcomeFailure, At: now.Add(-time.Second),
	})
	ingestor := NewObservationIngestor(nil, clock, time.Minute, 16)
	guard := staticObservationGuard{epochID: 11, revision: 12, sourceGeneration: 13, handle: handle}
	sink, err := NewIngestingProbeObservationSink(ingestor, guard, &HealthObservationReducer{Store: health})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &countingCapabilitySessionFactory{session: sink}
	suite, err := NewCapabilityProbeSuite(clock, scheduler, provider, runner, aggregator, sessions)
	if err != nil {
		t.Fatal(err)
	}

	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		_, runErr := suite.Run(runContext, CapabilitySuiteRequest{
			RunID: 44, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
			ServiceID: youtubeProbeServiceID, Nodes: []CapabilitySuiteNode{{Handle: handle, Dialer: newTestOutbound("cancel")}},
			Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
		})
		runDone <- runErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("capability request did not start")
	}
	cancelRun()
	select {
	case runErr := <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("canceled suite returned %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled capability suite did not return")
	}
	status := health.StatusHandle(handle, DomainService, "", youtubeProbeServiceID)
	if status.Breaker == BreakerClosed || status.HalfOpen {
		t.Fatalf("canceled suite leaked or settled half-open permit: %+v", status)
	}
	if pending, committed := aggregator.Stats(); pending != 0 || committed != 0 {
		t.Fatalf("canceled suite retained aggregate state: pending=%d committed=%d", pending, committed)
	}
	if opened, closed := sessions.stats(); opened != 1 || closed != 1 {
		t.Fatalf("canceled suite leaked its observation session: opened=%d closed=%d", opened, closed)
	}

	continued := make(chan struct{})
	submission := scheduler.Submit(ProbeTask{
		Key: ProbeKey{RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13, NodeID: NodeID{52}, NodeSlot: 2, NodeVersion: 1, Suite: "after-cancel", Target: "ready"},
		Run: func(context.Context) ProbeResult {
			close(continued)
			return ProbeResult{Outcome: OutcomeSuccess}
		},
	})
	if submission.Status != ProbeAccepted {
		t.Fatalf("scheduler did not accept work after suite cancellation: %+v", submission)
	}
	waitContext, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if _, err = submission.Future.Await(waitContext); err != nil {
		t.Fatalf("scheduler did not finish work after suite cancellation: %v", err)
	}
	select {
	case <-continued:
	default:
		t.Fatal("post-cancellation scheduler task was not executed")
	}
}

func TestCapabilityProbeSuitePartialSubmissionRollsBackWithoutObservation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	snapshot := youtubeTargetSnapshot(t, now, 1)
	provider := newYouTubeProvider(t, clock, snapshot)
	var err error

	blockerStarted := make(chan struct{})
	unblock := make(chan struct{})
	scheduler := NewProbeScheduler(context.Background(), 1, 2)
	defer scheduler.Close()
	blocker := scheduler.Submit(ProbeTask{
		Key:     ProbeKey{RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13, NodeID: NodeID{61}, NodeSlot: 1, NodeVersion: 1, Suite: "occupy-worker", Target: "block"},
		Timeout: time.Minute,
		Run: func(context.Context) ProbeResult {
			close(blockerStarted)
			<-unblock
			return ProbeResult{Outcome: OutcomeSuccess}
		},
	})
	if blocker.Status != ProbeAccepted {
		t.Fatalf("worker blocker was not accepted: %+v", blocker)
	}
	select {
	case <-blockerStarted:
	case <-time.After(time.Second):
		t.Fatal("worker blocker did not start")
	}
	filler := scheduler.Submit(ProbeTask{
		Key:   ProbeKey{RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13, NodeID: NodeID{62}, NodeSlot: 2, NodeVersion: 1, Suite: "occupy-queue", Target: "later"},
		DueAt: time.Now().Add(time.Hour), Timeout: time.Minute,
		Run: func(context.Context) ProbeResult { return ProbeResult{Outcome: OutcomeSuccess} },
	})
	if filler.Status != ProbeAccepted {
		t.Fatalf("queue filler was not accepted: %+v", filler)
	}

	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		t.Fatal("partially submitted suite task reached the runner")
		return nil, errors.New("unexpected runner execution")
	}
	aggregator := NewProbeAggregator(ProbeAggregatorConfig{}, clock, nil)
	handle := NodeHandle{NodeID: NodeID{63}, Slot: 3, Version: 1, BornRevision: 1}
	health := NewHealthStoreWithClock(time.Hour, 16, clock, BreakerConfig{})
	ingestor := NewObservationIngestor(nil, clock, time.Minute, 16)
	collected := new(collectingEvidenceReducer)
	guard := staticObservationGuard{epochID: 11, revision: 12, sourceGeneration: 13, handle: handle}
	sink, err := NewIngestingProbeObservationSink(ingestor, guard, &HealthObservationReducer{Store: health, BeforeReduce: collected.Reduce})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &countingCapabilitySessionFactory{session: sink}
	suite, err := NewCapabilityProbeSuite(clock, scheduler, provider, runner, aggregator, sessions)
	if err != nil {
		t.Fatal(err)
	}
	_, err = suite.Run(context.Background(), CapabilitySuiteRequest{
		RunID: 45, RuntimeEpochID: 11, CatalogRevision: 12, SourceGeneration: 13,
		ServiceID: youtubeProbeServiceID, Nodes: []CapabilitySuiteNode{{Handle: handle, Dialer: newTestOutbound("backpressure")}},
		Quorum: 2, CommonModeMinNodes: 2, Deadline: now.Add(time.Minute),
	})
	if !errors.Is(err, ErrProbeQueueFull) {
		t.Fatalf("partial submission did not report deterministic queue backpressure: %v", err)
	}
	if pending, committed := aggregator.Stats(); pending != 0 || committed != 0 {
		t.Fatalf("partial submission retained aggregate state: pending=%d committed=%d", pending, committed)
	}
	if len(collected.evidence) != 0 {
		t.Fatalf("partial submission produced health evidence: %d", len(collected.evidence))
	}
	status := health.StatusHandle(handle, DomainService, "", youtubeProbeServiceID)
	if status.HalfOpen {
		t.Fatalf("partial submission leaked a service permit: %+v", status)
	}
	if opened, closed := sessions.stats(); opened != 1 || closed != 1 {
		t.Fatalf("partial submission leaked its observation session: opened=%d closed=%d", opened, closed)
	}

	filler.Future.Cancel()
	close(unblock)
	waitContext, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if _, err = blocker.Future.Await(waitContext); err != nil {
		t.Fatalf("worker blocker did not drain: %v", err)
	}
}

func TestRuntimeCapabilityObservationFactoryPinsOnlyRunLifetime(t *testing.T) {
	manager := NewRuntimeManager()
	health := NewHealthStore(time.Hour, 16)
	prepared, err := manager.PrepareEpoch("capability-group", health, NewSessionLeaseManager(16), new(ControlState), identitySnapshot(1, IdentityNode{NodeID: NodeID{71}}))
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewRuntimeCapabilityObservationFactory(manager, "capability-group", NewObservationIngestor(nil, nil, time.Minute, 16), health, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := factory.OpenCapabilityObservation(CapabilityObservationIdentity{
		RuntimeEpochID: identity.EpochID, CatalogRevision: identity.Revision, SourceGeneration: identity.SourceGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.RetireEpoch("capability-group", identity.EpochID)
	manager.access.RLock()
	retained := manager.groups["capability-group"].epochs[identity.EpochID]
	manager.access.RUnlock()
	if retained == nil || retained.lifecycle != EpochRetiring || retained.refCount != 1 {
		t.Fatalf("run session did not retain the retiring epoch: %+v", retained)
	}
	if _, err = factory.OpenCapabilityObservation(CapabilityObservationIdentity{
		RuntimeEpochID: identity.EpochID, CatalogRevision: identity.Revision, SourceGeneration: identity.SourceGeneration,
	}); err == nil {
		t.Fatal("retiring epoch admitted a new capability run")
	}
	session.Close()
	session.Close()
	manager.access.RLock()
	state := manager.groups["capability-group"]
	stillRetained := false
	if state != nil {
		_, stillRetained = state.epochs[identity.EpochID]
	}
	manager.access.RUnlock()
	if stillRetained {
		t.Fatal("closed run session pinned the retired epoch")
	}
	if _, err = factory.OpenCapabilityObservation(CapabilityObservationIdentity{}); err == nil {
		t.Fatal("incomplete capability identity opened a session")
	}
}

type countingCapabilitySessionFactory struct {
	access  sync.Mutex
	session CapabilityObservationSession
	opened  int
	closed  int
}

func (f *countingCapabilitySessionFactory) OpenCapabilityObservation(CapabilityObservationIdentity) (CapabilityObservationSession, error) {
	f.access.Lock()
	f.opened++
	f.access.Unlock()
	return &countingCapabilitySession{CapabilityObservationSession: f.session, factory: f}, nil
}

func (f *countingCapabilitySessionFactory) stats() (opened, closed int) {
	f.access.Lock()
	opened, closed = f.opened, f.closed
	f.access.Unlock()
	return
}

type countingCapabilitySession struct {
	CapabilityObservationSession
	factory *countingCapabilitySessionFactory
	once    sync.Once
}

func (s *countingCapabilitySession) Close() {
	s.once.Do(func() {
		s.factory.access.Lock()
		s.factory.closed++
		s.factory.access.Unlock()
	})
}

type collectingEvidenceReducer struct {
	evidence []ObservationEvidence
}

func (r *collectingEvidenceReducer) Reduce(evidence ObservationEvidence, _ []DomainEvidence) error {
	r.evidence = append(r.evidence, evidence)
	return nil
}
