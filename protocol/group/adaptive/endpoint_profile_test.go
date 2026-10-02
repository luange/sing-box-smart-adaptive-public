package adaptive

import (
	"testing"
	"time"
)

func TestEndpointProfileTracksAreSerializedAndDeduplicated(t *testing.T) {
	registry := NewEndpointProfileRegistry()
	endpoint := NodeID{1}
	if !registry.TryAcquire(endpoint, TrackTCP4) {
		t.Fatal("first TCP probe rejected")
	}
	if registry.TryAcquire(endpoint, TrackTCP4) {
		t.Fatal("duplicate TCP probe admitted")
	}
	if registry.TryAcquire(endpoint, TrackDNSUDP4) {
		t.Fatal("same endpoint must not run a second track concurrently")
	}
	registry.Release(endpoint, TrackTCP4)
	if !registry.TryAcquire(endpoint, TrackDNSUDP4) {
		t.Fatal("endpoint was not released")
	}
	registry.Release(endpoint, TrackDNSUDP4)
}

func TestEndpointProfileRegistryBoundsRetiredProfiles(t *testing.T) {
	registry := NewEndpointProfileRegistryWithBounds(time.Hour, 2)
	now := time.Unix(1_700_000_000, 0)
	for index := byte(1); index <= 3; index++ {
		registry.Record(NodeID{index}, TrackTCP4, true, time.Millisecond, now.Add(time.Duration(index)*time.Second))
	}
	registry.mu.Lock()
	count := len(registry.profiles)
	registry.mu.Unlock()
	if count > 2 {
		t.Fatalf("profile registry exceeded bound: %d", count)
	}
	registry.Record(NodeID{9}, TrackTCP4, true, 0, now.Add(2*time.Hour))
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, profile := range registry.profiles {
		if profile.UpdatedAt.Before(now.Add(time.Hour)) {
			t.Fatalf("expired profile retained: %+v", profile)
		}
	}
}

func TestEndpointProfileCadence(t *testing.T) {
	registry := NewEndpointProfileRegistry()
	endpoint := NodeID{2}
	now := time.Unix(1_700_000_000, 0)
	registry.Record(endpoint, TrackTCP4, true, 10*time.Millisecond, now)
	profile, ok := registry.Snapshot(endpoint, TrackTCP4)
	if !ok || profile.NextProbeAt.Sub(now) != 5*time.Minute {
		t.Fatalf("first success cadence: %+v", profile)
	}
	registry.Record(endpoint, TrackTCP4, true, 9*time.Millisecond, now)
	profile, _ = registry.Snapshot(endpoint, TrackTCP4)
	if profile.NextProbeAt.Sub(now) != 15*time.Minute {
		t.Fatalf("second success cadence: %+v", profile)
	}
	registry.Record(endpoint, TrackTCP4, false, 0, now)
	profile, _ = registry.Snapshot(endpoint, TrackTCP4)
	if profile.NextProbeAt.Sub(now) != 30*time.Second || profile.Successes != 0 {
		t.Fatalf("first failure cadence: %+v", profile)
	}
}
