//go:build smart_zig && cgo

package group

/*
#cgo CFLAGS: -I${SRCDIR}/../../smart-engine/include
#cgo LDFLAGS: -L${SRCDIR}/../../smart-engine/zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

import (
	"sync"
	"time"
)

type smartPolicyBackendConfig struct {
	Exploration          float64
	SwitchMargin         float64
	SwitchConfirm        int
	SwitchConfirmWindow  int64
	SwitchCooldown       int64
	SiteStickiness       int64
	SwitchMinImprovement int64
	SelectionMode        uint8
	MinSamples           int
}

type zigSmartPolicyBackend struct {
	config C.smart_engine_config
	shards [smartPolicyShardCount]zigSmartPolicyShard
}

const smartPolicyShardCount = 16

type zigSmartPolicyShard struct {
	access          sync.Mutex
	engines         map[string]*zigSmartPolicyEngine
	candidateBuffer []C.smart_candidate
}

type zigSmartPolicyEngine struct {
	engine  *C.smart_engine
	lastUse time.Time
}

func newSmartPolicyBackend(config smartPolicyBackendConfig) smartPolicyBackend {
	cfg := C.smart_engine_config{
		exploration:               C.double(config.Exploration),
		switch_margin:             C.double(config.SwitchMargin),
		switch_confirm_samples:    C.uint32_t(config.SwitchConfirm),
		switch_confirm_ms:         C.uint64_t(maxInt64(config.SwitchConfirmWindow)),
		switch_cooldown_ms:        C.uint64_t(maxInt64(config.SwitchCooldown)),
		selection_mode:            C.uint8_t(config.SelectionMode),
		site_stickiness_ms:        C.uint64_t(maxInt64(config.SiteStickiness)),
		switch_min_improvement_ms: C.uint64_t(maxInt64(config.SwitchMinImprovement)),
		min_samples:               C.uint32_t(smartPolicyMinSamples(config.MinSamples)),
	}
	if C.smart_engine_abi_version() != 6 {
		return nil
	}
	backend := &zigSmartPolicyBackend{config: cfg}
	for index := range backend.shards {
		backend.shards[index].engines = make(map[string]*zigSmartPolicyEngine)
	}
	return backend
}

func smartPolicyMinSamples(value int) uint32 {
	if value <= 0 {
		return 3
	}
	if uint64(value) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

// Release builds that carry the Zig backend must not silently fall back to the
// duplicate Go policy state machine. A missing/incompatible library is a build
// or packaging error and is rejected during Smart construction.
func smartPolicyBackendRequired() bool { return true }

func smartPolicyBackendName() string { return "zig" }

func maxInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func smartMillis(now time.Time) uint64 {
	if now.IsZero() {
		now = time.Now()
	}
	return uint64(maxInt64(now.UnixMilli()))
}

func (b *zigSmartPolicyBackend) Choose(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) smartPolicyDecision {
	if b == nil || key == "" || len(candidates) == 0 || len(candidates) > 8192 {
		return smartPolicyDecision{Score: 100, Reason: 3}
	}
	shard := b.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	engine := b.engineForLocked(shard, key, now)
	if engine == nil {
		return smartPolicyDecision{Score: 100, Reason: 3}
	}
	if cap(shard.candidateBuffer) < len(candidates) {
		shard.candidateBuffer = make([]C.smart_candidate, len(candidates))
	} else {
		shard.candidateBuffer = shard.candidateBuffer[:len(candidates)]
	}
	// Choose is a batch ABI call. The shard lock makes this scratch buffer safe
	// to reuse across all contexts in the shard while allowing other shards to
	// rank concurrently. It also avoids retaining one large candidate slice per
	// policy context.
	converted := shard.candidateBuffer
	for i, candidate := range candidates {
		converted[i] = C.smart_candidate{
			id: C.uint64_t(candidate.ID), reliability: C.double(candidate.Reliability),
			connect_ms: C.double(candidate.ConnectMS), first_byte_ms: C.double(candidate.FirstByteMS),
			jitter_ms: C.double(candidate.JitterMS), throughput_bps: C.double(candidate.Throughput),
			samples: C.double(candidate.Samples), weight: C.double(candidate.Weight), candidate_order: C.double(candidate.CandidateOrder),
			state: C.uint8_t(candidate.State), eligible: C.uint8_t(boolByte(candidate.Eligible)),
		}
	}
	profileID := C.uint8_t(0)
	if profile == smartProfileBulk {
		profileID = 1
	} else if profile == smartProfileUDP {
		profileID = 2
	}
	decision := C.smart_engine_choose_profile(engine.engine, &converted[0], C.uintptr_t(len(converted)), C.uint64_t(smartMillis(now)), profileID)
	return smartPolicyDecision{SelectedID: uint64(decision.selected_id), Score: float64(decision.score), Switched: decision.switched != 0, Reason: uint8(decision.reason)}
}

func (b *zigSmartPolicyBackend) shardFor(key string) *zigSmartPolicyShard {
	index := smartPolicyID(key) & (smartPolicyShardCount - 1)
	return &b.shards[index]
}

func (b *zigSmartPolicyBackend) engineForLocked(shard *zigSmartPolicyShard, key string, now time.Time) *zigSmartPolicyEngine {
	if current := shard.engines[key]; current != nil {
		current.lastUse = now
		return current
	}
	// Keep context sharding bounded. Each policy engine owns a fixed 4096-slot
	// observation table, so unbounded site/network churn would defeat the
	// memory bound even though every individual engine is bounded.
	const maxContextsPerShard = 4
	if len(shard.engines) >= maxContextsPerShard {
		var oldestKey string
		var oldest time.Time
		for candidateKey, candidate := range shard.engines {
			if oldestKey == "" || candidate.lastUse.Before(oldest) {
				oldestKey, oldest = candidateKey, candidate.lastUse
			}
		}
		if evicted := shard.engines[oldestKey]; evicted != nil {
			C.smart_engine_destroy(evicted.engine)
			delete(shard.engines, oldestKey)
		}
	}
	config := b.config
	// The engine is keyed by the full network/site/transport context. Feeding
	// the same canonical hash into the policy kernel gives balanced mode a
	// stable rendezvous choice without retaining the unbounded string key in
	// the Zig state.
	config.affinity_seed = C.uint64_t(smartPolicyID(key))
	engine := C.smart_engine_create(config)
	if engine == nil {
		return nil
	}
	state := &zigSmartPolicyEngine{engine: engine, lastUse: now}
	shard.engines[key] = state
	return state
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func (b *zigSmartPolicyBackend) Observe(key string, id uint64, success bool, elapsed time.Duration, now time.Time) {
	if b == nil || key == "" || id == 0 {
		return
	}
	shard := b.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	engine := b.engineForLocked(shard, key, now)
	if engine == nil {
		return
	}
	ms := float64(elapsed) / float64(time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	C.smart_engine_observe(engine.engine, C.uint64_t(id), C.uint8_t(boolByte(success)), C.double(ms), C.uint64_t(smartMillis(now)))
}

func (b *zigSmartPolicyBackend) SetSelected(key string, id uint64, now time.Time) {
	if b == nil || key == "" || id == 0 {
		return
	}
	shard := b.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	engine := b.engineForLocked(shard, key, now)
	if engine != nil {
		C.smart_engine_set_selected(engine.engine, C.uint64_t(id), C.uint64_t(smartMillis(now)))
	}
}

func (b *zigSmartPolicyBackend) AdoptSelected(key string, id uint64, now time.Time) {
	if b == nil || key == "" || id == 0 {
		return
	}
	shard := b.shardFor(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	engine := b.engineForLocked(shard, key, now)
	if engine != nil {
		C.smart_engine_adopt_selected(engine.engine, C.uint64_t(id), C.uint64_t(smartMillis(now)))
	}
}

func (b *zigSmartPolicyBackend) Prune(ids []uint64) {
	if b == nil {
		return
	}
	var keep []C.uint64_t
	if len(ids) > 0 {
		keep = make([]C.uint64_t, len(ids))
		for index, id := range ids {
			keep[index] = C.uint64_t(id)
		}
	}
	for index := range b.shards {
		shard := &b.shards[index]
		shard.access.Lock()
		for _, engine := range shard.engines {
			if len(keep) == 0 {
				C.smart_engine_prune(engine.engine, nil, 0)
			} else {
				C.smart_engine_prune(engine.engine, &keep[0], C.uintptr_t(len(keep)))
			}
		}
		shard.access.Unlock()
	}
}

func (b *zigSmartPolicyBackend) Reset() {
	if b != nil {
		for index := range b.shards {
			shard := &b.shards[index]
			shard.access.Lock()
			for _, engine := range shard.engines {
				C.smart_engine_reset(engine.engine)
			}
			shard.access.Unlock()
		}
	}
}

func (b *zigSmartPolicyBackend) Close() {
	if b != nil {
		for index := range b.shards {
			shard := &b.shards[index]
			shard.access.Lock()
			for key, engine := range shard.engines {
				C.smart_engine_destroy(engine.engine)
				delete(shard.engines, key)
			}
			shard.access.Unlock()
		}
	}
}
