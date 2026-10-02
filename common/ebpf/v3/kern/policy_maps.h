// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_V3_POLICY_MAPS_H
#define SING_BOX_EBPF_V3_POLICY_MAPS_H

#include "abi.h"

#include <linux/bpf.h>

#include "../../native/btf_map.h"

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

#define SB_V3_MAP SB_BTF_MAP

/* Active bank selected via v3_control.active_bank; both banks always present. */
SB_V3_MAP(v3_control, BPF_MAP_TYPE_ARRAY, __u32, struct sb_v3_control, 1U, 0U);

SB_V3_MAP(v3_policy4_bank0, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm4_key, struct sb_v3_policy_value,
	  SB_V3_DEFAULT_POLICY_LPM, BPF_F_NO_PREALLOC);
SB_V3_MAP(v3_policy4_bank1, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm4_key, struct sb_v3_policy_value,
	  SB_V3_DEFAULT_POLICY_LPM, BPF_F_NO_PREALLOC);
SB_V3_MAP(v3_policy6_bank0, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm6_key, struct sb_v3_policy_value,
	  SB_V3_DEFAULT_POLICY_LPM, BPF_F_NO_PREALLOC);
SB_V3_MAP(v3_policy6_bank1, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm6_key, struct sb_v3_policy_value,
	  SB_V3_DEFAULT_POLICY_LPM, BPF_F_NO_PREALLOC);

/* Learned DNS/direct promotions are independent from static policy banks.
 * Their value carries expiry and generation, so a stale learned row can be
 * ignored without mutating the authoritative static snapshot. */
SB_V3_MAP(v3_dynamic_direct4, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm4_key,
	  struct sb_v3_dynamic_direct_value, SB_V3_DEFAULT_DYNAMIC_DIRECT_ENTRIES, BPF_F_NO_PREALLOC);
SB_V3_MAP(v3_dynamic_direct6, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm6_key,
	  struct sb_v3_dynamic_direct_value, SB_V3_DEFAULT_DYNAMIC_DIRECT_ENTRIES, BPF_F_NO_PREALLOC);

SB_V3_MAP(v3_host4, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm4_key, __u8,
	  1024U, BPF_F_NO_PREALLOC);
SB_V3_MAP(v3_host6, BPF_MAP_TYPE_LPM_TRIE, struct sb_v3_lpm6_key, __u8,
	  1024U, BPF_F_NO_PREALLOC);

SB_V3_MAP(v3_flow_verdict, BPF_MAP_TYPE_LRU_HASH, struct sb_v3_flow_key, struct sb_v3_flow_value,
	  SB_V3_DEFAULT_FLOW_ENTRIES, 0U);
SB_V3_MAP(v3_dns_ip_hint, BPF_MAP_TYPE_LRU_HASH, struct sb_v3_dns_ip_key, struct sb_v3_dns_ip_value,
	  SB_V3_DEFAULT_DNS_HINTS, 0U);

SB_V3_MAP(v3_source_mac, BPF_MAP_TYPE_HASH, struct sb_v3_mac_key, struct sb_v3_source_policy_value,
	  SB_V3_MAX_SOURCE_POLICY, 0U);

SB_V3_MAP(v3_dns_observe, BPF_MAP_TYPE_LRU_HASH, struct sb_v3_dns_obs_key,
	  struct sb_v3_dns_obs_value, SB_V3_MAX_DNS_OBSERVATIONS, 0U);
SB_V3_MAP(v3_dns_scratch, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct sb_v3_dns_scratch, 1U, 0U);

SB_V3_MAP(v3_redirect, BPF_MAP_TYPE_LRU_HASH, struct sb_v3_redirect_key, struct sb_v3_redirect_value,
	  SB_V3_DEFAULT_FLOW_ENTRIES, 0U);

SB_V3_MAP(v3_listener_sockets, BPF_MAP_TYPE_SOCKMAP, __u32, __u64, SB_V3_LISTENER_COUNT, 0U);

/* Counters are write-hot on every packet. Keep policy truth in shared maps,
 * but put one complete telemetry vector in a PERCPU array. This avoids both
 * cross-CPU cache contention and a second map lookup for byte accounting. */
SB_V3_MAP(v3_stats, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, struct sb_v3_stats_value, 1U, 0U);

/* Ringbuf deferred: first ship uses stats only (design §14 counters). */

#endif /* SING_BOX_EBPF_V3_POLICY_MAPS_H */
