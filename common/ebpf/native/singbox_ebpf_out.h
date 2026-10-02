// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_OUT_H
#define SING_BOX_EBPF_OUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Router-scale defaults: 8k pairs/flows. Override via config max_pairs/max_entries. */
#define SB_SPLICE_MAX_ENTRIES 8192U

/* ── Module A: flow verdict offload (OUT-A) ─────────────────────────── */
#define SB_OUT_VERDICT_DIRECT 1U
#define SB_OUT_VERDICT_MAX_ENTRIES 8192U

struct sb_out_verdict_key {
	uint8_t family;
	uint8_t protocol;
	uint16_t port; /* host order; exact match only (no wildcard lookup as of rc45) */
	uint8_t addr[16]; /* network-order bytes */
	uint32_t reserved;
}; /* 24 */
/* Destination-level granularity only (no UID/netns). See framework F-3 / A3. */

struct sb_out_verdict_value {
	uint8_t verdict;
	uint8_t reserved[3];
	uint32_t generation; /* must match control.generation */
	uint64_t expire_ns; /* bpf_ktime_get_ns() / CLOCK_MONOTONIC base — never wall clock */
}; /* 16 */

struct sb_out_verdict_control {
	uint32_t generation;
	uint32_t enabled;
}; /* 8 */

/* Kernel-side counters (ARRAY of u64). Read from Go VerdictStats (A2). */
enum sb_out_verdict_stat_index {
	SB_OUT_VERDICT_STAT_HITS = 0,
	SB_OUT_VERDICT_STAT_EXPIRED,
	SB_OUT_VERDICT_STAT_GEN_MISMATCH,
	SB_OUT_VERDICT_STAT_COUNT,
};

_Static_assert(sizeof(struct sb_out_verdict_key) == 24U, "unexpected sb_out_verdict_key ABI");
_Static_assert(sizeof(struct sb_out_verdict_value) == 16U, "unexpected sb_out_verdict_value ABI");
_Static_assert(sizeof(struct sb_out_verdict_control) == 8U, "unexpected sb_out_verdict_control ABI");

/* ── Module C: self-listen port registry (OUT-C.1) ──────────────────── */
/* key = host-order u16 listen port, value = u8 marker.
 * Consumed by emit_self_listen_redirect_bypass: if dport is registered AND
 * destination is inside the redirect token prefix, bypass capture (anti
 * double-redirect when ProtectFunc cookie miss). Loopback is already bypassed
 * by emit_ipv4_destination_bypass. */
#define SB_OUT_SELF_LISTEN_MAX_ENTRIES 64U

enum sb_splice_stat_index {
	SB_SPLICE_STAT_PAIRS_CREATED = 0,
	SB_SPLICE_STAT_PAIRS_RELEASED,
	SB_SPLICE_STAT_REDIRECTS,
	SB_SPLICE_STAT_REDIRECT_FAILURES,
	SB_SPLICE_STAT_PEER_MISSES,
	SB_SPLICE_STAT_PASSTHROUGH,
	SB_SPLICE_STAT_COUNT,
};

#define SB_SPLICE_CTRL_FLAG_ACCOUNTING (1U << 0)

/* Ports stored host-order on both sides (ABI iron law). */
struct sb_splice_key {
	uint8_t family; /* AF_INET=2 / AF_INET6=10 */
	uint8_t protocol; /* IPPROTO_TCP=6 */
	uint16_t local_port;
	uint16_t remote_port;
	uint16_t reserved;
	uint8_t local_addr[16];
	uint8_t remote_addr[16];
}; /* 40: 1+1+2+2+2+16+16 with natural alignment */

struct sb_splice_control {
	uint32_t enabled;
	uint32_t flags;
}; /* 8 */

struct sb_splice_runtime {
	int sock_map_fd;
	int peer_map_fd;
	int bytes_map_fd;
	int stats_map_fd;
	int control_map_fd;
	int events_map_fd;
	int parser_prog_fd;
	int verdict_prog_fd;
	int sockops_prog_fd;
	uint32_t attached_programs;
};

_Static_assert(sizeof(struct sb_splice_key) == 40U, "unexpected sb_splice_key ABI");
_Static_assert(sizeof(struct sb_splice_control) == 8U, "unexpected sb_splice_control ABI");

int sb_ebpf_splice_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t max_entries,
	bool enable_accounting,
	struct sb_splice_runtime *runtime);
int sb_ebpf_splice_attach(struct sb_splice_runtime *runtime);
int sb_ebpf_splice_close(struct sb_splice_runtime *runtime);

#endif
