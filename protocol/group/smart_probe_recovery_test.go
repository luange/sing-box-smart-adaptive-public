package group

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSmartProbeRetriesAccumulateFailuresAndRecoverOnlyOnSuccess(t *testing.T) {
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	for attempt := 1; attempt <= 3; attempt++ {
		_, err, fresh := registry.runProbeMode(context.Background(), "endpoint", "key", time.Second, time.Minute, true,
			func(context.Context) (uint16, error) { return 0, errors.New("unreachable") })
		if err == nil || !fresh {
			t.Fatal("failed probe was not recorded")
		}
		if got := registry.entries["key"].result.failures; got != uint8(attempt) {
			t.Fatalf("retry %d reset failure evidence: %d", attempt, got)
		}
	}
	if !registry.dead("key") {
		t.Fatal("three failed probes did not isolate endpoint")
	}
	registry.access.Lock()
	registry.entries["key"].result.nextProbeAt = time.Now().Add(-time.Second)
	registry.access.Unlock()
	if !registry.dead("key") {
		t.Fatal("probe cadence expiry admitted endpoint without recovery evidence")
	}
	_, err, _ := registry.runProbeMode(context.Background(), "endpoint", "key", time.Second, time.Minute, true,
		func(context.Context) (uint16, error) {
			if !registry.dead("key") {
				t.Error("recovery owner discarded failure evidence")
			}
			return 10, nil
		})
	if err != nil || registry.dead("key") || registry.entries["key"].result.failures != 0 {
		t.Fatal("successful recovery did not reset breaker")
	}
}

func TestSmartFailedEndpointStaysIsolatedDuringRecoveryProbe(t *testing.T) {
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	entry := &smartProbeEntry{inflight: true, result: smartProbeResult{
		failures: 3, nextProbeAt: time.Now().Add(-time.Second),
	}}
	registry.entries["failed"] = entry
	if !registry.dead("failed") {
		t.Fatal("starting recovery admitted a failed endpoint before its result")
	}
	registry.access.Lock()
	entry.inflight = false
	entry.result = smartProbeResult{success: true, nextProbeAt: time.Now().Add(time.Minute)}
	registry.access.Unlock()
	if registry.dead("failed") {
		t.Fatal("confirmed recovery did not release endpoint")
	}
}
