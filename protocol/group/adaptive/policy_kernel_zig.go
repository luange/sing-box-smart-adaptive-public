//go:build smart_zig && cgo

package adaptive

/*
#cgo CFLAGS: -I${SRCDIR}/../../../smart-engine/include
#cgo LDFLAGS: -L${SRCDIR}/../../../smart-engine/zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

import (
	"sync"
	"time"
)

const adaptiveKernelMaxContexts = 128

type zigAdaptivePolicyKernel struct {
	access         sync.Mutex
	config         C.adaptive_engine_config
	engines        map[string]*C.adaptive_engine
	candidateCache []C.adaptive_candidate
}

func newAdaptivePolicyKernel() policyKernel {
	if C.adaptive_engine_abi_version() != 2 {
		return nil
	}
	return &zigAdaptivePolicyKernel{
		config:  C.adaptive_engine_config{switch_margin: C.double(0.15), switch_cooldown_ms: C.uint64_t(120000)},
		engines: make(map[string]*C.adaptive_engine),
	}
}

func (k *zigAdaptivePolicyKernel) Configure(margin float64, cooldown time.Duration, manualFailure string) {
	if k == nil {
		return
	}
	if margin < 0 {
		margin = 0.15
	}
	if margin > 0.95 {
		margin = 0.95
	}
	if cooldown < 0 {
		cooldown = 0
	}
	k.access.Lock()
	k.config.switch_margin = C.double(margin)
	k.config.switch_cooldown_ms = C.uint64_t(cooldown / time.Millisecond)
	if manualFailure == "fail_closed" {
		k.config.manual_failure = 1
	} else {
		k.config.manual_failure = 0
	}
	for _, engine := range k.engines {
		C.adaptive_engine_configure(engine, k.config)
	}
	k.access.Unlock()
}

func (k *zigAdaptivePolicyKernel) Choose(key string, candidates []policyKernelCandidate, mode PolicyMode, now time.Time) policyKernelDecision {
	if k == nil || key == "" || len(candidates) == 0 || len(candidates) > 8192 {
		return policyKernelDecision{}
	}
	k.access.Lock()
	defer k.access.Unlock()
	engine := k.engineLocked(key)
	if engine == nil {
		return policyKernelDecision{}
	}
	if cap(k.candidateCache) < len(candidates) {
		k.candidateCache = make([]C.adaptive_candidate, len(candidates))
	} else {
		k.candidateCache = k.candidateCache[:len(candidates)]
	}
	for index, candidate := range candidates {
		k.candidateCache[index] = C.adaptive_candidate{
			id: C.uint64_t(candidate.ID), sort_key_hi: C.uint64_t(candidate.SortKeyHi), sort_key_lo: C.uint64_t(candidate.SortKeyLo), health_priority: C.int32_t(candidate.HealthPriority),
			weighted_delay_ms: C.double(candidate.WeightedDelayMS), throughput_bps: C.double(candidate.ThroughputBPS),
			throughput_samples: C.double(candidate.ThroughputSamples), supported: C.uint8_t(boolByte(candidate.Supported)),
			eligible: C.uint8_t(boolByte(candidate.Eligible)), pinned: C.uint8_t(boolByte(candidate.Pinned)),
			leased: C.uint8_t(boolByte(candidate.Leased)),
		}
	}
	k.config.mode = C.uint8_t(policyKernelMode(mode))
	C.adaptive_engine_configure(engine, k.config)
	decision := C.adaptive_engine_choose(engine, &k.candidateCache[0], C.uintptr_t(len(k.candidateCache)), C.uint64_t(kernelNowMS(now)))
	return policyKernelDecision{SelectedID: uint64(decision.selected_id), Switched: decision.switched != 0, Reason: uint8(decision.reason)}
}

func (k *zigAdaptivePolicyKernel) SetBulkSequence(key string, sequence uint64) {
	if k == nil || key == "" {
		return
	}
	k.access.Lock()
	defer k.access.Unlock()
	if engine := k.engineLocked(key); engine != nil {
		C.adaptive_engine_set_bulk_sequence(engine, C.uint64_t(sequence))
	}
}

func (k *zigAdaptivePolicyKernel) Remember(key string, id NodeID, now time.Time, cooldown time.Duration) {
	if k == nil || key == "" || id == (NodeID{}) {
		return
	}
	k.access.Lock()
	defer k.access.Unlock()
	engine := k.engineLocked(key)
	if engine == nil {
		return
	}
	C.adaptive_engine_remember(engine, C.uint64_t(kernelCandidateID(id)), C.uint64_t(kernelNowMS(now)), C.uint64_t(maxDurationMS(cooldown)))
}

func (k *zigAdaptivePolicyKernel) Forget(key string) {
	if k == nil || key == "" {
		return
	}
	k.access.Lock()
	defer k.access.Unlock()
	if engine := k.engines[key]; engine != nil {
		C.adaptive_engine_forget(engine)
	}
}

func (k *zigAdaptivePolicyKernel) engineLocked(key string) *C.adaptive_engine {
	if engine := k.engines[key]; engine != nil {
		return engine
	}
	if len(k.engines) >= adaptiveKernelMaxContexts {
		// The map is intentionally bounded. Context churn must not make the
		// portable kernel a new source of process-lifetime memory growth.
		for oldKey, oldEngine := range k.engines {
			C.adaptive_engine_destroy(oldEngine)
			delete(k.engines, oldKey)
			break
		}
	}
	engine := C.adaptive_engine_create(k.config)
	if engine == nil {
		return nil
	}
	k.engines[key] = engine
	return engine
}

func (k *zigAdaptivePolicyKernel) Reset() {
	if k == nil {
		return
	}
	k.access.Lock()
	for key, engine := range k.engines {
		C.adaptive_engine_destroy(engine)
		delete(k.engines, key)
	}
	k.access.Unlock()
}

func (k *zigAdaptivePolicyKernel) Close() {
	if k == nil {
		return
	}
	k.access.Lock()
	for key, engine := range k.engines {
		C.adaptive_engine_destroy(engine)
		delete(k.engines, key)
	}
	k.access.Unlock()
}

func kernelNowMS(now time.Time) int64 {
	if now.IsZero() {
		now = time.Now()
	}
	return now.UnixMilli()
}

func maxDurationMS(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64(value / time.Millisecond)
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
