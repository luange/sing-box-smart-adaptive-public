package group

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

const smartProbeRegistryLimit = 8192

var errSharedSmartProbeFailed = errors.New("shared smart probe failed")
var errSharedSmartProbeDeferred = errors.New("shared smart probe deferred")

type smartProbeResult struct {
	delay       uint16
	success     bool
	completedAt time.Time
	nextProbeAt time.Time
	successes   uint8
	failures    uint8
	deferred    bool
}

type smartProbeEntry struct {
	result   smartProbeResult
	inflight bool
	done     chan struct{}
}

type smartProbeRegistry struct {
	ctx     context.Context
	cancel  context.CancelFunc
	access  sync.Mutex
	entries map[string]*smartProbeEntry
	// active serializes different probe tracks for the same endpoint. The
	// result cache remains track-specific, but TCP and UDP must not create
	// simultaneous upstream health traffic for one physical node.
	active          map[string]chan struct{}
	probe           func(context.Context, string, adapter.Outbound) (uint16, error)
	slots           chan struct{}
	activeGroups    atomic.Uint32
	completedProbes atomic.Uint64
}

func (r *smartProbeRegistry) startupDelay() time.Duration {
	if r == nil {
		return 0
	}
	order := r.activeGroups.Add(1) - 1
	return time.Duration(min(order, uint32(4))) * 15 * time.Second
}

type smartProbeRegistryReference struct {
	registry *smartProbeRegistry
	refs     int
}

var smartProbeRegistries struct {
	sync.Mutex
	byProcess map[<-chan struct{}]*smartProbeRegistryReference
}

func acquireSmartProbeRegistry(ctx context.Context) (*smartProbeRegistry, func()) {
	processKey := ctx.Done()
	if processKey == nil {
		registry := newSmartProbeRegistry(ctx)
		return registry, registry.close
	}
	smartProbeRegistries.Lock()
	if smartProbeRegistries.byProcess == nil {
		smartProbeRegistries.byProcess = make(map[<-chan struct{}]*smartProbeRegistryReference)
	}
	reference := smartProbeRegistries.byProcess[processKey]
	if reference == nil {
		reference = &smartProbeRegistryReference{registry: newSmartProbeRegistry(ctx)}
		smartProbeRegistries.byProcess[processKey] = reference
	}
	reference.refs++
	registry := reference.registry
	smartProbeRegistries.Unlock()
	var once sync.Once
	return registry, func() {
		once.Do(func() {
			registry.activeGroups.Add(^uint32(0))
			smartProbeRegistries.Lock()
			current := smartProbeRegistries.byProcess[processKey]
			if current == reference {
				current.refs--
				if current.refs == 0 {
					delete(smartProbeRegistries.byProcess, processKey)
					current.registry.close()
				}
			}
			smartProbeRegistries.Unlock()
		})
	}
}

func newSmartProbeRegistry(parent context.Context) *smartProbeRegistry {
	ctx, cancel := context.WithCancel(parent)
	return &smartProbeRegistry{
		ctx:     ctx,
		cancel:  cancel,
		entries: make(map[string]*smartProbeEntry),
		active:  make(map[string]chan struct{}),
		slots:   make(chan struct{}, 4),
		probe: func(ctx context.Context, link string, outbound adapter.Outbound) (uint16, error) {
			return urltest.URLTest(ctx, link, outbound)
		},
	}
}

func smartProbeKey(identity, probeURL string, timeout time.Duration) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(identity))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(probeURL))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(timeout.String()))
	return hex.EncodeToString(digest.Sum(nil))
}

// failed reports a recent shared probe failure for a candidate. Probe
// outcomes are process-wide, so every Smart group avoids the same failed node
// until the shared TTL expires instead of rediscovering the failure itself.
func (r *smartProbeRegistry) failed(key string, ttl time.Duration) bool {
	if r == nil || key == "" {
		return false
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	if entry == nil || entry.inflight || entry.result.success || entry.result.nextProbeAt.IsZero() {
		return false
	}
	now := time.Now()
	if ttl > 0 && now.Sub(entry.result.completedAt) > ttl {
		return false
	}
	return now.Before(entry.result.nextProbeAt)
}

func (r *smartProbeRegistry) dead(key string) bool {
	if r == nil || key == "" {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	if entry == nil || entry.result.success || entry.result.failures < 3 {
		return false
	}
	// Starting a recovery probe is not recovery evidence. Keep a previously
	// failed endpoint isolated while the probe is in flight; otherwise every
	// periodic retry briefly admits the dead node to ordinary traffic.
	if entry.inflight {
		return true
	}
	// The cadence deadline admits another probe, not ordinary traffic. The
	// registry owner independently checks nextProbeAt, and all-open recovery
	// uses a bounded forced probe. Only positive evidence clears this gate.
	return true
}

func smartProbeCadence(success bool, successes, failures uint8) time.Duration {
	if success {
		switch successes {
		case 0, 1:
			return 5 * time.Minute
		case 2:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	switch failures {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 5 * time.Minute
	}
}

func (r *smartProbeRegistry) run(ctx context.Context, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error) {
	delay, err, _ := r.runWithMetaForEndpoint(ctx, key, key, probeURL, timeout, ttl, candidate)
	return delay, err
}

// runWithMeta is the normal URLTest path with an observation freshness bit.
// A cached result is useful for answering a caller, but it is not a new
// network sample and must not reset a local breaker or inflate confidence.
// A waiter joined to an in-flight probe receives fresh=true because that
// probe completed during this call and may be recorded once by its group.
func (r *smartProbeRegistry) runWithMeta(ctx context.Context, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error, bool) {
	return r.runWithMetaForEndpoint(ctx, key, key, probeURL, timeout, ttl, candidate)
}

func (r *smartProbeRegistry) runWithMetaForEndpoint(ctx context.Context, endpointKey, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error, bool) {
	if r == nil {
		return 0, errSharedSmartProbeFailed, false
	}
	return r.runProbeMode(ctx, endpointKey, key, timeout, ttl, false, func(probeCtx context.Context) (uint16, error) {
		return r.probe(probeCtx, probeURL, candidate)
	})
}

// runRecovery performs one bounded half-open trial when every candidate in a
// Smart context is currently open. It bypasses the normal cadence cache, but
// still shares the per-endpoint single-flight lock and admission slots.
func (r *smartProbeRegistry) runRecovery(ctx context.Context, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, key, key, timeout, ttl, true, probe)
	return delay, err
}

func (r *smartProbeRegistry) runRecoveryForEndpoint(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, endpointKey, key, timeout, ttl, true, probe)
	return delay, err
}

// runProbe is the shared single-flight admission path for every probe kind.
// URLTest and UDP reachability use the same endpoint key, so aliases and
// multiple Smart groups cannot open duplicate probes for one endpoint.
func (r *smartProbeRegistry) runProbe(ctx context.Context, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, key, key, timeout, ttl, false, probe)
	return delay, err
}

func (r *smartProbeRegistry) runProbeForEndpoint(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, endpointKey, key, timeout, ttl, false, probe)
	return delay, err
}

func (r *smartProbeRegistry) runProbeMode(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, force bool, probe func(context.Context) (uint16, error)) (uint16, error, bool) {
	if r == nil || probe == nil {
		return 0, errSharedSmartProbeFailed, false
	}
	if ctx.Err() != nil {
		return 0, ctx.Err(), false
	}
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err(), false
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	r.access.Lock()
	if r.active == nil {
		r.active = make(map[string]chan struct{})
	}
	entry := r.entries[key]
	if entry != nil && entry.inflight {
		done := entry.done
		r.access.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err(), false
		case <-r.ctx.Done():
			return 0, r.ctx.Err(), false
		case <-done:
		}
		r.access.Lock()
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil, !result.deferred
		}
		if !force && result.deferred {
			return 0, errSharedSmartProbeDeferred, false
		}
		if !force {
			return 0, errSharedSmartProbeFailed, !result.deferred
		}
		// A forced recovery caller is allowed to become the next owner after
		// the previous single-flight attempt completes. Re-enter the admission
		// path so it claims the endpoint lock together with the entry. Claiming
		// only the entry here would let a different track probe the same endpoint
		// concurrently during the recovery attempt.
		r.access.Lock()
		if current := r.entries[key]; current == entry && !current.inflight {
			r.access.Unlock()
			return r.runProbeMode(ctx, endpointKey, key, timeout, ttl, force, probe)
		}
		r.access.Unlock()
		return 0, errSharedSmartProbeFailed, false
	}
	if entry != nil && !force && now.Before(entry.result.nextProbeAt) {
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil, false
		}
		if result.deferred {
			return 0, errSharedSmartProbeDeferred, false
		}
		return 0, errSharedSmartProbeFailed, false
	}
	if endpointKey != "" {
		if done := r.active[endpointKey]; done != nil {
			r.access.Unlock()
			select {
			case <-ctx.Done():
				return 0, ctx.Err(), false
			case <-r.ctx.Done():
				return 0, r.ctx.Err(), false
			case <-done:
			}
			return r.runProbeMode(ctx, endpointKey, key, timeout, ttl, force, probe)
		}
		r.active[endpointKey] = make(chan struct{})
	}
	if entry == nil && len(r.entries) >= smartProbeRegistryLimit {
		r.pruneLocked(now)
		if len(r.entries) >= smartProbeRegistryLimit {
			if endpointKey != "" {
				done := r.active[endpointKey]
				delete(r.active, endpointKey)
				close(done)
			}
			r.access.Unlock()
			// Do not bypass the registry when every slot is occupied. An
			// unregistered probe would defeat both endpoint single-flight and the
			// global admission bound precisely during the churn it is meant to
			// contain. The caller can retry on the next scheduled cycle.
			return 0, errSharedSmartProbeDeferred, false
		}
	}
	// A new single-flight owner must inherit the last completed evidence.
	// Replacing it with zeroes resets the consecutive failure counter on every
	// retry, making the three-failure breaker unreachable.
	var previousResult smartProbeResult
	if entry != nil {
		previousResult = entry.result
	}
	entry = &smartProbeEntry{inflight: true, done: make(chan struct{}), result: previousResult}
	r.entries[key] = entry
	r.access.Unlock()

	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		r.access.Lock()
		entry.result = previousResult
		entry.result.deferred = true
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		if endpointKey != "" {
			done := r.active[endpointKey]
			delete(r.active, endpointKey)
			close(done)
		}
		r.access.Unlock()
		return 0, errSharedSmartProbeDeferred, false
	case <-r.ctx.Done():
		r.access.Lock()
		entry.result = previousResult
		entry.result.deferred = true
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		if endpointKey != "" {
			done := r.active[endpointKey]
			delete(r.active, endpointKey)
			close(done)
		}
		r.access.Unlock()
		return 0, errSharedSmartProbeDeferred, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	delay, err := probe(probeCtx)
	cancel()
	// Release the admission slot immediately — never block peers behind GC.
	<-r.slots
	r.completedProbes.Add(1)
	// Let the runtime GC on its own schedule. Forced STW after probes hurt
	// gateway latency and HA close under multi-smart catalogs.
	completedAt := time.Now()
	r.access.Lock()
	previous := entry.result
	var successes, failures uint8
	if err == nil {
		successes = min(previous.successes+1, uint8(3))
	} else {
		failures = min(previous.failures+1, uint8(3))
	}
	result := smartProbeResult{
		delay: delay, success: err == nil, completedAt: completedAt,
		nextProbeAt: completedAt.Add(smartProbeCadence(err == nil, successes, failures)),
		successes:   successes, failures: failures,
	}
	entry.result = result
	entry.inflight = false
	close(entry.done)
	entry.done = nil
	if endpointKey != "" {
		done := r.active[endpointKey]
		delete(r.active, endpointKey)
		close(done)
	}
	r.access.Unlock()
	if err != nil {
		return 0, errSharedSmartProbeFailed, true
	}
	return delay, nil, true
}

func (r *smartProbeRegistry) pruneLocked(now time.Time) {
	for key, entry := range r.entries {
		if !entry.inflight && now.Sub(entry.result.completedAt) > time.Hour {
			delete(r.entries, key)
		}
	}
	for len(r.entries) >= smartProbeRegistryLimit {
		var oldestKey string
		var oldest time.Time
		for key, entry := range r.entries {
			if entry.inflight {
				continue
			}
			if oldestKey == "" || entry.result.completedAt.Before(oldest) {
				oldestKey = key
				oldest = entry.result.completedAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(r.entries, oldestKey)
	}
}

func (r *smartProbeRegistry) close() {
	r.cancel()
	r.access.Lock()
	clear(r.entries)
	r.entries = make(map[string]*smartProbeEntry)
	r.access.Unlock()
}
