package adaptive

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func TestAdaptivePoolCapabilityLifecycleUsesOwnedSchedulerAndObservationPipeline(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "capability-lifecycle")
	pool.postStarted = true
	pool.probeCoverage = time.Hour
	pool.probeTimeout = time.Second
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) { return 1, nil }

	now := time.Now()
	provider := newYouTubeProvider(t, realClock{}, youtubeTargetSnapshot(t, now, 1))
	runner := NewCapabilityProbeRunner(realClock{})
	runner.httpClientFactory = func(_ context.Context, _ N.Dialer, _ ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPartialContent, TLS: &tls.ConnectionState{},
				Header: http.Header{"Content-Range": []string{"bytes 0-15/100"}, "Content-Type": []string{"video/mp4"}},
				Body:   io.NopCloser(bytes.NewReader([]byte("0123456789abcdef"))),
			}, nil
		}}, nil
	}
	pool.capabilityProvider = provider
	pool.capabilityRunner = runner
	pool.capabilityRefresh = time.Hour
	pool.capabilityTimeout = time.Second
	pool.capabilityQuorum = 2
	pool.capabilityCommonModeMin = 2

	if err := pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	pool.OnRuntimeEpochPublishCommit()
	deadline := time.Now().Add(2 * time.Second)
	for {
		status := pool.AdaptiveStatus()
		if status.CapabilityCyclesCompleted == 1 && !status.CapabilityRunning {
			if !status.CapabilityEnabled || status.CapabilityTargetGeneration != 1 || status.CapabilityInitFailures != 0 || status.CapabilityRefreshFailures != 0 || status.CapabilityViewFailures != 0 || status.CapabilitySuiteFailures != 0 {
				t.Fatalf("unexpected capability lifecycle status: %+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("capability lifecycle did not complete: %+v", status)
		}
		time.Sleep(time.Millisecond)
	}
	if len(pool.capabilityControllers) == 0 || pool.scheduler == nil {
		t.Fatal("published capability runtime was not assembled")
	}
	_, _, completed := pool.scheduler.Stats()
	if completed < 3 {
		t.Fatalf("capability targets did not share the owned scheduler: completed=%d", completed)
	}
	snapshot := pool.catalog.load()
	service := pool.health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", youtubeProbeServiceID)
	if service.Health != HealthHealthy || service.Breaker != BreakerClosed || service.HalfOpen {
		t.Fatalf("capability verdict did not traverse ingestor/reducer: %+v", service)
	}
	if err := pool.TriggerAdaptiveCapabilityProbe(context.Background()); err != nil {
		t.Fatalf("manual capability trigger failed: %v", err)
	}
	if status := pool.AdaptiveStatus(); status.CapabilityCyclesCompleted != 2 {
		t.Fatalf("manual capability trigger did not reuse controller: %+v", status)
	}

	pool.OnRuntimeEpochRetire()
	if len(pool.capabilityControllers) != 0 || pool.scheduler != nil {
		t.Fatal("retired pool retained capability controller or scheduler")
	}
}

func TestAdaptivePoolCapabilityLifecycleIsDisabledWithoutProvider(t *testing.T) {
	pool := preparedLifecyclePool(t, NewRuntimeManager(), "capability-disabled")
	pool.postStarted = true
	pool.probeCoverage = time.Hour
	pool.probeTimeout = time.Second
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) { return 1, nil }
	if err := pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	pool.OnRuntimeEpochPublishCommit()
	defer pool.OnRuntimeEpochRetire()
	if len(pool.capabilityControllers) != 0 {
		t.Fatal("default pool started capability controller without a trusted provider")
	}
	status := pool.AdaptiveStatus()
	if status.CapabilityEnabled || status.CapabilityCyclesStarted != 0 || status.CapabilityInitFailures != 0 {
		t.Fatalf("disabled capability runtime exposed activity: %+v", status)
	}
	if err := pool.TriggerAdaptiveCapabilityProbe(context.Background()); !errors.Is(err, adapter.ErrAdaptiveCapabilityUnavailable) {
		t.Fatalf("disabled capability trigger returned %v", err)
	}
}

func TestAdaptivePoolAIServiceControllersShareSchedulerAndIsolateEvidence(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "capability-ai-lifecycle")
	pool.postStarted = true
	pool.probeCoverage = time.Hour
	pool.probeTimeout = time.Second
	pool.probeRunner = func(context.Context, string, N.Dialer) (uint16, error) { return 1, nil }

	// AI service TLS provider is sealed — lifecycle must not wire it.
	if _, err := NewBuiltinAIServiceTLSTargetProvider(nil); err == nil {
		t.Fatal("expected sealed builtin AI service provider to be rejected")
	}
	// Exercise shared scheduler lifecycle with the non-AI YouTube TLS provider.
	provider, err := NewBuiltinYouTubeTLSTargetProvider(nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewCapabilityProbeRunner(nil)
	runner.tlsProbe = func(context.Context, N.Dialer, ProbeTarget) ProbeRawResult {
		return ProbeRawResult{TLSHandshakeOK: true}
	}
	pool.capabilityProvider = provider
	pool.capabilityServiceIDs = provider.ServiceIDs()
	pool.capabilityRunner = runner
	pool.capabilityRefresh = time.Hour
	pool.capabilityTimeout = time.Second
	pool.capabilityQuorum = 1
	pool.capabilityCommonModeMin = 2

	if err = pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	pool.OnRuntimeEpochPublishCommit()
	defer pool.OnRuntimeEpochRetire()
	wantServices := len(provider.ServiceIDs())
	if wantServices == 0 {
		t.Fatal("youtube provider returned no service IDs")
	}
	deadline := time.Now().Add(2 * time.Second)
	for pool.AdaptiveStatus().CapabilityCyclesCompleted < uint64(wantServices) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status := pool.AdaptiveStatus()
	if status.CapabilityCyclesCompleted != uint64(wantServices) || len(pool.capabilityControllers) != wantServices || status.CapabilityInitFailures != 0 || status.CapabilitySuiteFailures != 0 {
		t.Fatalf("capability runtime did not complete: status=%+v controllers=%d want=%d", status, len(pool.capabilityControllers), wantServices)
	}
	snapshot := pool.catalog.load()
	for _, serviceID := range provider.ServiceIDs() {
		service := pool.health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", serviceID)
		if service.Health != HealthHealthy {
			t.Fatalf("service %s did not receive isolated healthy evidence: %+v", serviceID, service)
		}
	}
}
