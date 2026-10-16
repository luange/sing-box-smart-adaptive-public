#ifndef SMART_ENGINE_H
#define SMART_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_ENGINE_ABI_VERSION 2u

/* Host-neutral AdaptivePool decision kernel.  The host still owns health
 * evidence, Provider refresh, dialing, leases and persistence; this ABI owns
 * candidate ordering and sticky/failover state only. */
typedef struct adaptive_engine adaptive_engine;
typedef struct {
    uint64_t id;
    uint64_t sort_key_hi;
    uint64_t sort_key_lo;
    int32_t health_priority;
    double weighted_delay_ms;
    double throughput_bps;
    double throughput_samples;
    uint8_t supported;
    uint8_t eligible;
    uint8_t pinned;
    uint8_t leased;
} adaptive_candidate;

typedef struct {
    double switch_margin;
    uint64_t switch_cooldown_ms;
    uint8_t mode;
    uint8_t manual_failure;
} adaptive_engine_config;

/* Adaptive kernel reason codes (adaptive_decision.reason). */
enum {
    ADAPTIVE_REASON_RANKED = 0,
    ADAPTIVE_REASON_RETAINED = 1,
    ADAPTIVE_REASON_LEASE = 2,
    ADAPTIVE_REASON_MANUAL = 3,
    ADAPTIVE_REASON_FALLBACK = 4,
    ADAPTIVE_REASON_NO_CANDIDATE = 5,
    ADAPTIVE_REASON_BULK_SPREAD = 6,
    ADAPTIVE_REASON_BULK_THROUGHPUT = 7,
    ADAPTIVE_REASON_COOLDOWN = 8,
};

typedef struct {
    uint64_t selected_id;
    uint8_t switched;
    uint8_t reason;
    double score;
} adaptive_decision;

uint32_t adaptive_engine_abi_version(void);
adaptive_engine *adaptive_engine_create(adaptive_engine_config config);
void adaptive_engine_configure(adaptive_engine *engine, adaptive_engine_config config);
void adaptive_engine_destroy(adaptive_engine *engine);
adaptive_decision adaptive_engine_choose(adaptive_engine *engine, const adaptive_candidate *candidates, uintptr_t count, uint64_t now_ms);
void adaptive_engine_set_bulk_sequence(adaptive_engine *engine, uint64_t sequence);
void adaptive_engine_remember(adaptive_engine *engine, uint64_t id, uint64_t now_ms, uint64_t cooldown_ms);
void adaptive_engine_forget(adaptive_engine *engine);

#ifdef __cplusplus
}
#endif

#endif
