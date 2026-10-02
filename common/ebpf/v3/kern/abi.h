// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// eBPF data-plane v3 ABI. Independent of dae; architecture only inspired by
// "TC classifies early, true DIRECT uses Linux L3 forwarding".

#ifndef SING_BOX_EBPF_V3_ABI_H
#define SING_BOX_EBPF_V3_ABI_H

#include <linux/types.h>

/* Bump only on incompatible layout changes. Hot take-over must refuse mismatch. */
#define SB_V3_ABI_VERSION 4U

#define SB_V3_AF_INET 2U
#define SB_V3_AF_INET6 10U

#define SB_V3_MAX_POLICY_LPM_ENTRIES 65536U
#define SB_V3_MAX_DYNAMIC_DIRECT_ENTRIES 32768U
#define SB_V3_MAX_PORT_RULES 4096U
#define SB_V3_MAX_SOURCE_POLICY 8192U
#define SB_V3_MAX_FLOW_ENTRIES 65536U
#define SB_V3_MAX_DNS_HINTS 32768U
#define SB_V3_MAX_DNS_OBSERVATIONS 4096U
#define SB_V3_DNS_OBSERVATION_NAME_MAX 128U
#define SB_V3_LISTENER_COUNT 4U
#define SB_V3_STATS_COUNT 32U
#define SB_V3_EVENT_RING_ENTRIES 4096U

/* Default capacities (clamped by config). */
#define SB_V3_DEFAULT_FLOW_ENTRIES 8192U
#define SB_V3_DEFAULT_DNS_HINTS 8192U
#define SB_V3_DEFAULT_POLICY_LPM 16384U
#define SB_V3_DEFAULT_DYNAMIC_DIRECT_ENTRIES 8192U

enum sb_v3_verdict {
	SB_V3_UNSEEN = 0,
	SB_V3_DIRECT = 1,
	SB_V3_PROXY = 2,
	SB_V3_BLOCK = 3,
	SB_V3_MUST_CONTROL = 4,
};

enum sb_v3_source {
	SB_V3_SRC_STATIC = 1,
	SB_V3_SRC_EXACT_FLOW = 2,
	SB_V3_SRC_DNS_WEAK = 3,
	SB_V3_SRC_FAKEIP = 4,
};

enum sb_v3_reason {
	SB_V3_REASON_NONE = 0,
	SB_V3_REASON_STATIC_DIRECT = 1,
	SB_V3_REASON_FLOW_DIRECT = 2,
	SB_V3_REASON_FAKEIP_DIRECT = 3,
	SB_V3_REASON_DNS_HINT_DIRECT = 4,
	SB_V3_REASON_POLICY_PROXY = 5,
	SB_V3_REASON_MAP_MISS_PROXY = 6,
	SB_V3_REASON_GENERATION_MISS_PROXY = 7,
	SB_V3_REASON_PARSE_FAIL_PROXY = 8,
	SB_V3_REASON_SOCKET_ASSIGN_OK = 9,
	SB_V3_REASON_SOCKET_ASSIGN_FAIL = 10,
	SB_V3_REASON_BLOCKED = 11,
	SB_V3_REASON_DNS_HINT_CONFLICT = 12,
	SB_V3_REASON_MAP_CAPACITY_REJECT = 13,
	SB_V3_REASON_SECURITY_BYPASS = 14,
	SB_V3_REASON_ESTABLISHED_BYPASS = 15,
	SB_V3_REASON_STATIC_PROXY = 16,
	SB_V3_REASON_STATIC_BLOCK = 17,
	SB_V3_REASON_MUST_CONTROL = 18,
	SB_V3_REASON_DNS_HIJACK_PROXY = 19,
	SB_V3_REASON_FLOW_PROXY = 20,
	SB_V3_REASON_FLOW_BLOCK = 21,
};

enum sb_v3_stat_index {
	SB_V3_STAT_STATIC_DIRECT = 0,
	SB_V3_STAT_FLOW_DIRECT,
	SB_V3_STAT_FAKEIP_DIRECT,
	SB_V3_STAT_DNS_HINT_DIRECT,
	SB_V3_STAT_POLICY_PROXY,
	SB_V3_STAT_MAP_MISS_PROXY,
	SB_V3_STAT_GENERATION_MISS_PROXY,
	SB_V3_STAT_PARSE_FAIL_PROXY,
	SB_V3_STAT_SOCKET_ASSIGN_SUCCESS,
	SB_V3_STAT_SOCKET_ASSIGN_FAILURE,
	SB_V3_STAT_BLOCKED,
	SB_V3_STAT_DNS_HINT_CONFLICT,
	SB_V3_STAT_MAP_CAPACITY_REJECT,
	SB_V3_STAT_SECURITY_BYPASS,
	SB_V3_STAT_ESTABLISHED_BYPASS,
	SB_V3_STAT_STATIC_PROXY,
	SB_V3_STAT_STATIC_BLOCK,
	SB_V3_STAT_MUST_CONTROL,
	SB_V3_STAT_DNS_HIJACK_PROXY,
	SB_V3_STAT_FLOW_PROXY,
	SB_V3_STAT_FLOW_BLOCK,
	SB_V3_STAT_BYTES_DIRECT,
	SB_V3_STAT_BYTES_PROXY,
	SB_V3_STAT_PACKETS_DIRECT,
	SB_V3_STAT_PACKETS_PROXY,
	SB_V3_STAT_RELOAD_GENERATION,
	SB_V3_STAT_MAC_SOURCE_DIRECT,
	SB_V3_STAT_MAC_SOURCE_BLOCK,
	SB_V3_STAT_MAC_SOURCE_PROXY,
	SB_V3_STAT_COUNT = SB_V3_STATS_COUNT,
};

/* One per-CPU value contains the complete counter vector.  Keeping the
 * vector together lets the packet path perform one map lookup for telemetry
 * even when an action records both a reason and a byte count. */
struct sb_v3_stats_value {
	__u64 values[SB_V3_STATS_COUNT];
};

_Static_assert(sizeof(struct sb_v3_stats_value) == (SB_V3_STATS_COUNT * sizeof(__u64)),
	       "sb_v3_stats_value size");

enum sb_v3_listener_key {
	SB_V3_LISTENER_TCP4 = 0,
	SB_V3_LISTENER_UDP4 = 1,
	SB_V3_LISTENER_TCP6 = 2,
	SB_V3_LISTENER_UDP6 = 3,
};

#define SB_V3_FLAG_IPV4 (1U << 0)
#define SB_V3_FLAG_IPV6 (1U << 1)
#define SB_V3_FLAG_TCP (1U << 2)
#define SB_V3_FLAG_UDP (1U << 3)
#define SB_V3_FLAG_DNS_HIJACK (1U << 4)
#define SB_V3_FLAG_DROP_UDP_443 (1U << 5) /* explicit only; default off */
#define SB_V3_FLAG_SOCKET_ASSIGN (1U << 6)
#define SB_V3_FLAG_STATIC_POLICY (1U << 7)
#define SB_V3_FLAG_EXACT_FLOW (1U << 8)
#define SB_V3_FLAG_DNS_HINT (1U << 9)
#define SB_V3_FLAG_FAKEIP (1U << 10)
#define SB_V3_FLAG_MAC_SOURCE (1U << 11)
#define SB_V3_FLAG_FAILURE_PROXY (1U << 12) /* failure_mode=proxy (default) */
#define SB_V3_FLAG_DNS_SNIFF (1U << 13) /* kernel plaintext DNS response sniffer */

/* XDP control is intentionally a separate ABI.  TC readers must not infer
 * AF_XDP state from the TC control block, and an XDP attach must be able to
 * fail closed without changing socket-assignment behaviour. */
#define SB_XDP_ABI_VERSION 1U
#define SB_XDP_MAX_QUEUES 64U
#define SB_XDP_CTRL_ENABLED (1U << 0)
#define SB_XDP_CTRL_ALLOW_MULTIBUFFER (1U << 1)

/* Confidence: higher means safer for kernel DIRECT. */
#define SB_V3_CONF_NONE 0U
#define SB_V3_CONF_WEAK 1U
#define SB_V3_CONF_STRONG 2U
#define SB_V3_CONF_AUTHORITATIVE 3U

struct sb_v3_control {
	__u32 abi_version;
	__u32 enabled;
	__u32 flags;
	__u32 active_bank; /* 0 or 1 */
	__u32 policy_generation;
	__u32 routing_mark;
	__u16 reserved0;
	__u16 reserved1;
	__u32 reserved2;
};

_Static_assert(sizeof(struct sb_v3_control) == 32U, "sb_v3_control size");

/* Compiled LPM value for destination CIDR (and optional protocol/port wildcard). */
struct sb_v3_policy_value {
	__u8 verdict; /* sb_v3_verdict */
	__u8 source;
	__u8 confidence;
	__u8 reserved0;
	__u16 reason_code;
	__u16 match_protocol; /* 0 = any; else IPPROTO_* */
	__u16 match_dport_min; /* host order; 0/0 = any */
	__u16 match_dport_max;
	__u32 policy_id;
	__u32 generation;
};

_Static_assert(sizeof(struct sb_v3_policy_value) == 20U, "sb_v3_policy_value size");

/* Learned DIRECT entries are deliberately a separate map from the static
 * policy snapshot.  They have an expiry and must never consume the static
 * rule bank's capacity or participate in its generation transaction. */
struct sb_v3_dynamic_direct_value {
	__u8 verdict; /* always SB_V3_DIRECT */
	__u8 source;
	__u8 confidence;
	__u8 reserved0;
	__u16 reason_code;
	__u16 match_protocol; /* 0 = any; else IPPROTO_* */
	__u16 match_dport_min;
	__u16 match_dport_max;
	__u32 policy_id;
	__u32 generation;
	__u64 expires_ns;
};

_Static_assert(sizeof(struct sb_v3_dynamic_direct_value) == 32U, "sb_v3_dynamic_direct_value size");

struct sb_v3_lpm4_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct sb_v3_lpm6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

_Static_assert(sizeof(struct sb_v3_lpm4_key) == 8U, "sb_v3_lpm4_key size");
_Static_assert(sizeof(struct sb_v3_lpm6_key) == 20U, "sb_v3_lpm6_key size");

/* Exact five-tuple flow verdict (both directions published from userspace). */
struct sb_v3_flow_key {
	__u8 family;
	__u8 protocol;
	__u8 direction; /* 0 forward client→server, 1 reverse */
	__u8 reserved0;
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

_Static_assert(sizeof(struct sb_v3_flow_key) == 40U, "sb_v3_flow_key size");

struct sb_v3_flow_value {
	__u8 verdict;
	__u8 source;
	__u8 confidence;
	__u8 reserved0;
	__u16 reason_code;
	__u16 reserved1;
	__u32 policy_id;
	__u32 generation;
	__u64 expires_ns;
};

_Static_assert(sizeof(struct sb_v3_flow_value) == 24U, "sb_v3_flow_value size");

/* DNS/FakeIP IP association cache. Conflict isolation is mandatory. */
struct sb_v3_dns_ip_key {
	__u8 family;
	__u8 reserved0;
	__u16 reserved1;
	__u8 addr[16];
};

_Static_assert(sizeof(struct sb_v3_dns_ip_key) == 20U, "sb_v3_dns_ip_key size");

struct sb_v3_dns_ip_value {
	__u32 direct_refs;
	__u32 proxy_refs;
	__u32 policy_id;
	__u32 generation;
	__u64 expires_ns;
	__u64 last_seen_ns;
	__u8 evidence; /* 1=fakeip auth, 2=dns strong, 3=dns weak */
	__u8 reserved0;
	__u16 reserved1;
	__u32 reserved2;
};

_Static_assert(sizeof(struct sb_v3_dns_ip_value) == 40U, "sb_v3_dns_ip_value size");

enum sb_v3_dns_evidence {
	SB_V3_DNS_EVIDENCE_NONE = 0,
	SB_V3_DNS_EVIDENCE_FAKEIP = 1,
	SB_V3_DNS_EVIDENCE_STRONG = 2,
	SB_V3_DNS_EVIDENCE_WEAK = 3,
};

/* Source policy: ifindex + MAC or source CIDR → policy id / verdict override. */
struct sb_v3_mac_key {
	__u8 addr[6];
	__u8 reserved[2];
	__u32 ifindex; /* 0 = any */
};

_Static_assert(sizeof(struct sb_v3_mac_key) == 12U, "sb_v3_mac_key size");

struct sb_v3_source_policy_value {
	__u8 verdict; /* UNSEEN = no override */
	__u8 source;
	__u8 confidence;
	__u8 reserved0;
	__u16 reason_code;
	__u16 reserved1;
	__u32 policy_id;
	__u32 generation;
};

_Static_assert(sizeof(struct sb_v3_source_policy_value) == 16U, "sb_v3_source_policy_value size");

/* Kernel-side plaintext DNS response observation (design §7.4): the TC
 * sniffer extracts qname + first A/AAAA from responses and parks them here;
 * userspace drains the map, applies full domain rules and publishes hints.
 * Covers clients with hardcoded DNS whose responses never transit the
 * sing-box DNS module. */
struct sb_v3_dns_obs_key {
	__u64 qname_hash;
	__u8 family;
	__u8 reserved0;
	__u16 reserved1;
	__u8 addr[16];
};

_Static_assert(sizeof(struct sb_v3_dns_obs_key) == 32U, "sb_v3_dns_obs_key size");

struct sb_v3_dns_obs_value {
	char qname[SB_V3_DNS_OBSERVATION_NAME_MAX]; /* lowercase, no trailing dot */
	__u32 ttl_seconds; /* RR TTL, capped by userspace policy before promotion */
	__u32 reserved0;
};

_Static_assert(sizeof(struct sb_v3_dns_obs_value) == 136U, "sb_v3_dns_obs_value size");

/* Per-CPU scratch for bounded DNS parsing. Stack-backed variable-offset
 * reads are rejected by older verifier versions; a per-CPU map value keeps
 * the same bounds without cross-CPU sharing or packet-path locking. */
struct sb_v3_dns_scratch_meta {
	__u32 next;
	__u32 reserved;
	__u64 qname_hash;
};

struct sb_v3_dns_scratch {
	__u8 bytes[SB_V3_DNS_OBSERVATION_NAME_MAX];
	__u8 qname[SB_V3_DNS_OBSERVATION_NAME_MAX];
	struct sb_v3_dns_scratch_meta meta;
	struct sb_v3_dns_obs_value observation;
};

/* Host-to-kernel snapshot row for v3_source_mac (design §7.3). */
struct sb_v3_mac_policy_entry {
	struct sb_v3_mac_key key;
	struct sb_v3_source_policy_value value;
};

_Static_assert(sizeof(struct sb_v3_mac_policy_entry) == 28U, "sb_v3_mac_policy_entry size");

/* Original destination retained for socket_assign handoff (userspace lookup). */
struct sb_v3_redirect_key {
	__u8 family;
	__u8 protocol;
	__u16 reserved0;
	__u16 client_port;
	__u16 dest_port;
	__u8 client_addr[16];
	__u8 dest_addr[16];
};

_Static_assert(sizeof(struct sb_v3_redirect_key) == 40U, "sb_v3_redirect_key size");

struct sb_v3_redirect_value {
	__u8 family;
	__u8 protocol;
	__u16 dest_port;
	__u32 ifindex;
	__u8 dest_addr[16];
	__u8 source_mac[6];
	__u8 reserved[2];
};

_Static_assert(sizeof(struct sb_v3_redirect_value) == 32U, "sb_v3_redirect_value size");

/* Parsed packet view used by TC (also mirrored in Go model tests). */
struct sb_v3_packet {
	__u8 family;
	__u8 protocol;
	__u8 fragmented;
	__u8 vlan_depth;
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
	__u8 smac[6];
	__u8 dmac[6];
	__u32 ifindex;
	__u32 mark;
	/* Offset from frame start to the L4 header (parser). Observational
	 * extensions (e.g. the DNS response sniffer) use it to reach the
	 * payload without re-walking the frame. */
	__u16 payload_offset;
	/* TCP flags from the first byte of the TCP flags field.  XDP uses this
	 * only to avoid redirecting established TCP; TC keeps the field purely
	 * observational and does not change its ABI-visible decisions. */
	__u8 tcp_flags;
	__u8 reserved3[1];
};

_Static_assert(sizeof(struct sb_v3_packet) == 64U, "sb_v3_packet size");
_Static_assert(__builtin_offsetof(struct sb_v3_packet, saddr) == 8U, "sb_v3_packet saddr offset");
_Static_assert(__builtin_offsetof(struct sb_v3_packet, daddr) == 24U, "sb_v3_packet daddr offset");
_Static_assert(__builtin_offsetof(struct sb_v3_packet, ifindex) == 52U, "sb_v3_packet ifindex offset");
_Static_assert(__builtin_offsetof(struct sb_v3_packet, payload_offset) == 60U, "sb_v3_packet payload offset");

struct sb_xdp_control {
	__u32 abi_version;
	__u32 flags;
	__u32 policy_generation;
	__u32 active_bank;
	__u32 queue_count;
	__u32 max_frame_size;
	__u32 reserved0;
	__u64 attached_since_ns;
};

_Static_assert(sizeof(struct sb_xdp_control) == 40U, "sb_xdp_control size");

struct sb_v3_event {
	__u32 reason_code;
	__u32 generation;
	__u8 verdict;
	__u8 family;
	__u8 protocol;
	__u8 reserved0;
	__u16 sport;
	__u16 dport;
	__u8 saddr_prefix[4]; /* truncated for privacy */
	__u8 daddr_prefix[4];
	__u64 timestamp_ns;
};

_Static_assert(sizeof(struct sb_v3_event) == 32U, "sb_v3_event size");

#endif /* SING_BOX_EBPF_V3_ABI_H */
