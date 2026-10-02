//go:build smart_zig && cgo

package conformance

/*
#cgo CFLAGS: -I${SRCDIR}/../include
#cgo LDFLAGS: -L${SRCDIR}/../zig-out/lib -lsmart_engine -lm
#include "smart_engine.h"
*/
import "C"

type zigEngine struct {
	ptr *C.smart_engine
}

func newZigEngine(config Config) *zigEngine {
	cfg := C.smart_engine_config{
		exploration: C.double(config.Exploration), switch_margin: C.double(config.SwitchMargin),
		switch_confirm_samples: C.uint32_t(config.SwitchConfirmSamples), switch_confirm_ms: C.uint64_t(config.SwitchConfirmMS),
		switch_cooldown_ms: C.uint64_t(config.SwitchCooldownMS),
		min_samples:        C.uint32_t(config.MinSamples),
	}
	return &zigEngine{ptr: C.smart_engine_create(cfg)}
}

func (e *zigEngine) close() {
	if e != nil && e.ptr != nil {
		C.smart_engine_destroy(e.ptr)
		e.ptr = nil
	}
}

func (e *zigEngine) choose(candidates []Candidate, now uint64) Decision {
	candidatesC := make([]C.smart_candidate, len(candidates))
	for i, value := range candidates {
		candidatesC[i] = C.smart_candidate{
			id: C.uint64_t(value.ID), reliability: C.double(value.Reliability), connect_ms: C.double(value.ConnectMS),
			first_byte_ms: C.double(value.FirstByteMS), jitter_ms: C.double(value.JitterMS), throughput_bps: C.double(value.ThroughputBPS),
			samples: C.double(value.Samples), weight: C.double(value.Weight), candidate_order: C.double(value.CandidateOrder), state: C.uint8_t(value.State), eligible: C.uint8_t(value.Eligible),
		}
	}
	if e == nil || e.ptr == nil || len(candidatesC) == 0 {
		return Decision{Score: 100, Reason: 3}
	}
	got := C.smart_engine_choose(e.ptr, &candidatesC[0], C.uintptr_t(len(candidatesC)), C.uint64_t(now))
	return Decision{SelectedID: uint64(got.selected_id), Score: float64(got.score), Switched: uint8(got.switched), Reason: uint8(got.reason)}
}

func (e *zigEngine) setSelected(id, now uint64) {
	if e == nil || e.ptr == nil || id == 0 {
		return
	}
	C.smart_engine_set_selected(e.ptr, C.uint64_t(id), C.uint64_t(now))
}
