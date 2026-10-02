package adaptive

import (
	"context"
	"sync"
	"time"
)

type EndpointProbeTrack string

const (
	TrackTCP4     EndpointProbeTrack = "tcp4"
	TrackTCP6     EndpointProbeTrack = "tcp6"
	TrackDNSUDP4  EndpointProbeTrack = "dns_udp4"
	TrackDNSUDP6  EndpointProbeTrack = "dns_udp6"
	TrackDataUDP4 EndpointProbeTrack = "data_udp4"
	TrackDataUDP6 EndpointProbeTrack = "data_udp6"
)

type endpointProbeKey struct {
	endpoint NodeID
	track    EndpointProbeTrack
}

type EndpointTrackProfile struct {
	Healthy     bool
	Delay       time.Duration
	UpdatedAt   time.Time
	Successes   uint8
	Failures    uint8
	NextProbeAt time.Time
}

// EndpointProfileRegistry deduplicates in-flight probes across Smart and
// AdaptivePool consumers. Health evidence remains in each pool's HealthStore;
// this registry only owns endpoint-level probe admission and cadence state.
type EndpointProfileRegistry struct {
	mu sync.Mutex
	// Admission is serialized per endpoint, not per track. Running TCP and
	// DNS probes against the same server concurrently adds load without
	// producing independent endpoint evidence during catalog churn.
	active     map[NodeID]chan struct{}
	profiles   map[endpointProbeKey]EndpointTrackProfile
	retention  time.Duration
	maxEntries int
}

var globalEndpointProfiles = NewEndpointProfileRegistry()

func NewEndpointProfileRegistry() *EndpointProfileRegistry {
	return NewEndpointProfileRegistryWithBounds(time.Hour, 8192)
}

func NewEndpointProfileRegistryWithBounds(retention time.Duration, maxEntries int) *EndpointProfileRegistry {
	if retention <= 0 {
		retention = time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 8192
	}
	return &EndpointProfileRegistry{
		active:     make(map[NodeID]chan struct{}),
		profiles:   make(map[endpointProbeKey]EndpointTrackProfile),
		retention:  retention,
		maxEntries: maxEntries,
	}
}

func (r *EndpointProfileRegistry) TryAcquire(endpointID NodeID, track EndpointProbeTrack) bool {
	if r == nil || endpointID == (NodeID{}) {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.active[endpointID]; ok {
		return false
	}
	r.active[endpointID] = make(chan struct{})
	return true
}

func (r *EndpointProfileRegistry) Acquire(ctx context.Context, endpointID NodeID, track EndpointProbeTrack) bool {
	if r == nil || endpointID == (NodeID{}) {
		return true
	}
	for {
		r.mu.Lock()
		done := r.active[endpointID]
		if done == nil {
			r.active[endpointID] = make(chan struct{})
			r.mu.Unlock()
			return true
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-done:
		}
	}
}

func (r *EndpointProfileRegistry) Release(endpointID NodeID, track EndpointProbeTrack) {
	if r == nil || endpointID == (NodeID{}) {
		return
	}
	r.mu.Lock()
	if done := r.active[endpointID]; done != nil {
		delete(r.active, endpointID)
		close(done)
	}
	r.mu.Unlock()
}

func (r *EndpointProfileRegistry) Record(endpointID NodeID, track EndpointProbeTrack, success bool, delay time.Duration, now time.Time) {
	if r == nil || endpointID == (NodeID{}) {
		return
	}
	key := endpointProbeKey{endpoint: endpointID, track: track}
	r.mu.Lock()
	r.pruneLocked(now)
	profile := r.profiles[key]
	profile.Healthy, profile.Delay, profile.UpdatedAt = success, delay, now
	if success {
		profile.Successes = min(profile.Successes+1, uint8(3))
		profile.Failures = 0
		profile.NextProbeAt = now.Add(smartProfileCadence(true, profile.Successes))
	} else {
		profile.Failures = min(profile.Failures+1, uint8(3))
		profile.Successes = 0
		profile.NextProbeAt = now.Add(smartProfileCadence(false, profile.Failures))
	}
	r.profiles[key] = profile
	r.mu.Unlock()
}

func (r *EndpointProfileRegistry) pruneLocked(now time.Time) {
	for key, profile := range r.profiles {
		if !profile.UpdatedAt.IsZero() && now.Sub(profile.UpdatedAt) > r.retention {
			delete(r.profiles, key)
		}
	}
	for len(r.profiles) >= r.maxEntries {
		var oldestKey endpointProbeKey
		var oldest time.Time
		found := false
		for key, profile := range r.profiles {
			if _, active := r.active[key.endpoint]; active {
				continue
			}
			if !found || profile.UpdatedAt.Before(oldest) {
				oldestKey, oldest, found = key, profile.UpdatedAt, true
			}
		}
		if !found {
			return
		}
		delete(r.profiles, oldestKey)
	}
}

func smartProfileCadence(success bool, streak uint8) time.Duration {
	if success {
		switch streak {
		case 0, 1:
			return 5 * time.Minute
		case 2:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	switch streak {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 5 * time.Minute
	}
}

func (r *EndpointProfileRegistry) Snapshot(endpointID NodeID, track EndpointProbeTrack) (EndpointTrackProfile, bool) {
	if r == nil {
		return EndpointTrackProfile{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.profiles[endpointProbeKey{endpoint: endpointID, track: track}]
	return p, ok
}
