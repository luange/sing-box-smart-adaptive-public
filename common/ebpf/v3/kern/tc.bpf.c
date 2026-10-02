// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Single v3 TC object: ingress decision engine. Egress is not used: the
// socket_assign handoff covers the proxy return path and reverse traffic is
// left to the kernel stack (design §10).
// Maps are process-owned; do not pin across ABI versions.

#define SEC(name) __attribute__((section(name), used))

#include "parser.h"
#include "policy_maps.h"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#ifndef SB_V3_SOURCE_HASH
#define SB_V3_SOURCE_HASH "untracked"
#endif

const char sb_v3_source_hash[] SEC(".sb.source") = SB_V3_SOURCE_HASH;

#define SB_V3_DNS_SNIFF_MAX_BYTES 128U

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static long (*assign_socket)(struct __sk_buff *, void *, __u64) = (void *)BPF_FUNC_sk_assign;
static long (*release_socket)(void *) = (void *)BPF_FUNC_sk_release;
static struct bpf_sock *(*lookup_tcp)(void *, struct bpf_sock_tuple *, __u32, __u64, __u64) =
	(void *)BPF_FUNC_skc_lookup_tcp;
static __u64 (*monotonic_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __attribute__((always_inline)) struct sb_v3_stats_value *stats_lookup(void) {
	__u32 zero = 0;
	return map_lookup(&v3_stats, &zero);
}

static __attribute__((always_inline)) void count_stat(__u32 key) {
	struct sb_v3_stats_value *stats = stats_lookup();
	if (stats && key < SB_V3_STATS_COUNT)
		/* v3_stats is PERCPU: the pointer belongs to this CPU, so no atomic
		 * RMW is needed on the packet hot path. */
		stats->values[key] += 1;
}

static __attribute__((always_inline)) void count_proxy(__u32 reason, __u32 len) {
	struct sb_v3_stats_value *stats = stats_lookup();
	if (!stats)
		return;
	if (reason < SB_V3_STATS_COUNT)
		stats->values[reason] += 1;
	stats->values[SB_V3_STAT_PACKETS_PROXY] += 1;
	stats->values[SB_V3_STAT_BYTES_PROXY] += len;
}

static __attribute__((always_inline)) void count_direct(__u32 reason) {
	struct sb_v3_stats_value *stats = stats_lookup();
	if (!stats)
		return;
	if (reason < SB_V3_STATS_COUNT)
		stats->values[reason] += 1;
	stats->values[SB_V3_STAT_PACKETS_DIRECT] += 1;
}

static __attribute__((always_inline)) bool policy_port_match(const struct sb_v3_policy_value *policy,
							     const struct sb_v3_packet *packet) {
	if (policy->match_protocol != 0 && policy->match_protocol != packet->protocol)
		return false;
	if (policy->match_dport_min == 0 && policy->match_dport_max == 0)
		return true;
	return packet->dport >= policy->match_dport_min && packet->dport <= policy->match_dport_max;
}

/* ── Plaintext DNS response sniffer (design §7.4) ─────────────────────────
 * Gated by SB_V3_FLAG_DNS_SNIFF. Parses UDP responses from src port 53:
 * extracts the qname (lowercase, labels joined with dots, trailing dot
 * removed) and the first A/AAAA answer address, and parks the pair in
 * v3_dns_observe for the userspace drainer, which applies the full domain
 * rule set (regex included) and publishes direct hints. Never changes the
 * packet verdict. Bound-checked label walk; compression pointers are
 * followed at most twice per name with a hard tail limit. */

static __attribute__((noinline)) __u8 dns_byte(const __u8 *dns, __u32 index) {
	/* Callers perform semantic length checks first; masking also gives old
	 * verifiers a statically bounded map-value offset (0..127). */
	return dns[index & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)];
}

static __attribute__((noinline)) int dns_sniff_name(const __u8 *dns, __u32 dns_len,
									 __u32 cursor, __u8 *out,
									 struct sb_v3_dns_scratch_meta *meta) {
	__u32 p = cursor;
	int written = 0, hops = 0;
	bool jumped = false;
	__u64 hash = 1469598103934665603ULL;
	for (int steps = 0; steps < 32; steps++) {
		if (p >= dns_len || p >= SB_V3_DNS_SNIFF_MAX_BYTES)
			return -1;
		__u8 len = dns_byte(dns, p);
		if (len == 0) {
			if (!jumped && meta)
				meta->next = p + 1;
			if (out) {
				if (written >= SB_V3_DNS_SNIFF_MAX_BYTES)
					return -1;
				out[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = 0;
			}
			if (out && meta)
				meta->qname_hash = hash;
			return written > 0 ? written : -1;
		}
		if ((len & 0xc0) == 0xc0) { /* RFC 1035 compression pointer */
			if (hops >= 2 || p + 2 > dns_len || p + 2 > SB_V3_DNS_SNIFF_MAX_BYTES)
				return -1;
			__u16 off = (__u16)((len & 0x3f) << 8) | dns_byte(dns, p + 1);
			if (off >= dns_len || off >= p || off >= SB_V3_DNS_SNIFF_MAX_BYTES)
				return -1;
			if (!jumped && meta)
				meta->next = p + 2;
			p = off;
			jumped = true;
			hops++;
			continue;
		}
		if ((len & 0xc0) != 0 || len > 63U || p + 1 + len > dns_len ||
		    p + 1 + len > SB_V3_DNS_SNIFF_MAX_BYTES)
			return -1;
		if (out) {
			if (written != 0) {
				if (written + 1 >= SB_V3_DNS_SNIFF_MAX_BYTES)
					return -1;
				out[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = '.';
				written++;
				hash ^= '.';
				hash *= 1099511628211ULL;
			}
			if (written + len >= SB_V3_DNS_SNIFF_MAX_BYTES)
				return -1;
			for (int i = 0; i < len; i++) {
				__u8 c = dns_byte(dns, p + 1 + i);
				c = (c >= 'A' && c <= 'Z') ? c + 32 : c;
				out[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = c;
				written++;
				hash ^= c;
				hash *= 1099511628211ULL;
			}
		} else {
			/* The answer owner name is only skipped, not copied. */
			written += len + (written != 0 ? 1 : 0);
		}
		p += 1 + len;
	}
	return -1;
}

static __attribute__((noinline)) void dns_response_sniff(struct __sk_buff *skb, __u32 dns_offset,
								struct sb_v3_dns_scratch *scratch, __u32 dns_len) {
	const __u8 *dns = scratch->bytes;
	if (dns_len < 12 || dns_len > SB_V3_DNS_SNIFF_MAX_BYTES)
		return;
	__u16 flags = (__u16)(dns[2] << 8) | dns[3];
	if ((flags & 0x8000) == 0)
		return; /* not a response */
	if ((flags & 0x000f) != 0)
		return; /* error response */
	__u16 qdcount = (__u16)(dns[4] << 8) | dns[5];
	__u16 ancount = (__u16)(dns[6] << 8) | dns[7];
	/* Multiple-question replies need a full section walk to find the answer
	 * offset.  Reject them conservatively rather than interpreting the second
	 * question as an answer header; this path is advisory and fail-open. */
	if (qdcount != 1 || ancount == 0)
		return;

	/* Zero-fill so the fixed-size map copy below is verifier-safe and cannot
	 * expose uninitialised stack bytes when the name is shorter than 128. */
	struct sb_v3_dns_obs_value observation = {};
	__builtin_memset(&scratch->meta, 0, sizeof(scratch->meta));
	int qlen = dns_sniff_name(dns, dns_len, 12, scratch->qname, &scratch->meta);
	__u32 question_end = scratch->meta.next;
	if (qlen <= 0 || qlen >= sizeof(observation.qname) ||
	    question_end > SB_V3_DNS_SNIFF_MAX_BYTES - 4U ||
	    question_end > dns_len || dns_len - question_end < 4)
		return;
	/* skip to end of question section */
	__u16 qtype = (__u16)(dns_byte(dns, question_end) << 8) | dns_byte(dns, question_end + 1);
	__u16 qclass = (__u16)(dns_byte(dns, question_end + 2) << 8) | dns_byte(dns, question_end + 3);
	__u32 p = question_end + 4;

	if ((qtype != 1 && qtype != 28) || qclass != 1)
		return; /* want A/AAAA answers only */

	__u64 hash = scratch->meta.qname_hash;

	#pragma clang loop unroll(disable)
	/* A small bounded answer window avoids multiplying the DNS name walker
	 * across an adversarially large RR set. Four answers cover CNAME + a small
	 * A/AAAA chain while keeping verifier state below the kernel complexity cap. */
	for (int a = 0; a < 4; a++) {
		struct sb_v3_dns_scratch_meta record_meta = {};
		if (dns_sniff_name(dns, dns_len, p, 0, &record_meta) <= 0)
			return;
		p = record_meta.next;
		if (p > dns_len || dns_len - p < 10 || p + 10 > SB_V3_DNS_SNIFF_MAX_BYTES)
			return;
		__u16 rtype = (__u16)(dns_byte(dns, p) << 8) | dns_byte(dns, p + 1);
		__u16 rclass = (__u16)(dns_byte(dns, p + 2) << 8) | dns_byte(dns, p + 3);
		__u16 rdlen = (__u16)(dns_byte(dns, p + 8) << 8) | dns_byte(dns, p + 9);
		__u32 rdata = p + 10;
		if (rdata > dns_len || rdata > SB_V3_DNS_SNIFF_MAX_BYTES ||
		    rdlen > dns_len - rdata || rdlen > SB_V3_DNS_SNIFF_MAX_BYTES - rdata)
			return;
		if (rclass == 1 && rtype == qtype &&
		    ((rtype == 1 && rdlen == 4) || (rtype == 28 && rdlen == 16))) {
			__builtin_memcpy(observation.qname, scratch->qname, sizeof(observation.qname));
			struct sb_v3_dns_obs_key key = {};
			key.qname_hash = hash;
			key.family = rtype == 1 ? SB_V3_AF_INET : SB_V3_AF_INET6;
			if (rtype == 1) {
				if (sb_v3_load_skb_bytes(skb, dns_offset + rdata, key.addr, 4) != 0)
					return;
			} else {
				if (sb_v3_load_skb_bytes(skb, dns_offset + rdata, key.addr, 16) != 0)
					return;
			}
			/* RR fields are TYPE, CLASS, TTL, RDLENGTH. Preserve the authoritative
			 * TTL so userspace can cap the promotion lifetime to the answer's
			 * actual validity window instead of inventing a longer default. */
			observation.ttl_seconds = ((__u32)dns_byte(dns, p + 4) << 24) | ((__u32)dns_byte(dns, p + 5) << 16) |
				((__u32)dns_byte(dns, p + 6) << 8) | dns_byte(dns, p + 7);
			map_update(&v3_dns_observe, &key, &observation, BPF_ANY);
			return;
		}
		p = rdata + rdlen;
	}
}

/* Verifier-oriented DNS observation path. It handles one question and inspects
 * only the first answer RR. Names are decoded in a single flat bounded pass;
 * owner names are skipped without recursively following compression pointers.
 * Unsupported/truncated responses are simply not observed. */
static __attribute__((noinline)) __u8 dns_byte_bounded(const __u8 *dns, __u32 index) {
	return dns[index & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)];
}

static __attribute__((noinline)) int dns_question_bounded(
	const __u8 *dns, __u32 dns_len, struct sb_v3_dns_scratch *scratch,
	struct sb_v3_dns_scratch_meta *meta) {
	__u32 p = 12;
	__u32 written = 0;
	__u32 label_remaining = 0;
	bool need_dot = false;
	__u64 hash = 1469598103934665603ULL;

	__builtin_memset(meta, 0, sizeof(*meta));
#pragma clang loop unroll(disable)
	for (__u32 step = 0; step < 64U; step++) {
		if (p >= dns_len || p >= SB_V3_DNS_SNIFF_MAX_BYTES)
			return -1;
		__u8 c = dns_byte_bounded(dns, p++);
		if (label_remaining == 0) {
			if (c == 0) {
				if (written == 0 || written >= SB_V3_DNS_OBSERVATION_NAME_MAX)
					return -1;
				scratch->qname[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = 0;
				meta->next = p;
				meta->qname_hash = hash;
				return written;
			}
			if ((c & 0xc0) != 0 || c > 63U)
				return -1; /* question-section compression is not accepted */
			if (need_dot) {
				if (written + 1U >= SB_V3_DNS_OBSERVATION_NAME_MAX)
					return -1;
				scratch->qname[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = '.';
				written++;
				hash ^= '.';
				hash *= 1099511628211ULL;
			}
			if (written + c >= SB_V3_DNS_OBSERVATION_NAME_MAX)
				return -1;
			label_remaining = c;
			need_dot = true;
			continue;
		}
		c = (c >= 'A' && c <= 'Z') ? c + 32 : c;
		scratch->qname[written & (SB_V3_DNS_SNIFF_MAX_BYTES - 1U)] = c;
		written++;
		label_remaining--;
		hash ^= c;
		hash *= 1099511628211ULL;
	}
	return -1;
}

static __attribute__((noinline)) int dns_skip_owner_bounded(
	const __u8 *dns, __u32 dns_len, __u32 cursor, __u32 *next) {
	__u32 p = cursor;
#pragma clang loop unroll(disable)
	for (int labels = 0; labels < 8; labels++) {
		if (p >= dns_len || p >= SB_V3_DNS_SNIFF_MAX_BYTES)
			return -1;
		__u8 len = dns_byte_bounded(dns, p);
		if (len == 0) {
			*next = p + 1U;
			return 0;
		}
		if ((len & 0xc0) == 0xc0) {
			if (p + 2U > dns_len || p + 2U > SB_V3_DNS_SNIFF_MAX_BYTES)
				return -1;
			*next = p + 2U;
			return 0;
		}
		if ((len & 0xc0) != 0 || len > 63U || p + 1U + len > dns_len ||
		    p + 1U + len > SB_V3_DNS_SNIFF_MAX_BYTES)
			return -1;
		p += 1U + len;
	}
	return -1;
}

static __attribute__((noinline)) void dns_response_sniff_bounded(
	struct __sk_buff *skb, __u32 dns_offset, struct sb_v3_dns_scratch *scratch, __u32 dns_len) {
	const __u8 *dns = scratch->bytes;
	if (dns_len < 12U || dns_len > SB_V3_DNS_SNIFF_MAX_BYTES)
		return;
	__u16 flags = (__u16)(dns[2] << 8) | dns[3];
	if ((flags & 0x8000U) == 0 || (flags & 0x000fU) != 0)
		return;
	__u16 qdcount = (__u16)(dns[4] << 8) | dns[5];
	__u16 ancount = (__u16)(dns[6] << 8) | dns[7];
	if (qdcount != 1 || ancount == 0)
		return;

	struct sb_v3_dns_scratch_meta question = {};
	int qname_len = dns_question_bounded(dns, dns_len, scratch, &question);
	if (qname_len <= 0 || question.next > dns_len || dns_len - question.next < 4U ||
	    question.next > SB_V3_DNS_SNIFF_MAX_BYTES - 4U)
		return;
	__u16 qtype = (__u16)(dns_byte_bounded(dns, question.next) << 8) |
		dns_byte_bounded(dns, question.next + 1U);
	__u16 qclass = (__u16)(dns_byte_bounded(dns, question.next + 2U) << 8) |
		dns_byte_bounded(dns, question.next + 3U);
	if ((qtype != 1 && qtype != 28) || qclass != 1)
		return;

	__u32 p = question.next + 4U;
#pragma clang loop unroll(disable)
	for (int answer = 0; answer < 2; answer++) {
		if ((__u16)answer >= ancount)
			return;
		__u32 rr = 0;
		if (dns_skip_owner_bounded(dns, dns_len, p, &rr) != 0 || rr > dns_len ||
		    dns_len - rr < 10U || rr > SB_V3_DNS_SNIFF_MAX_BYTES - 10U)
			return;
		__u16 rtype = (__u16)(dns_byte_bounded(dns, rr) << 8) | dns_byte_bounded(dns, rr + 1U);
		__u16 rclass = (__u16)(dns_byte_bounded(dns, rr + 2U) << 8) | dns_byte_bounded(dns, rr + 3U);
		__u16 rdlen = (__u16)(dns_byte_bounded(dns, rr + 8U) << 8) | dns_byte_bounded(dns, rr + 9U);
		__u32 rdata = rr + 10U;
		if (rdata > dns_len || rdata > SB_V3_DNS_SNIFF_MAX_BYTES ||
		    rdlen > dns_len - rdata || rdlen > SB_V3_DNS_SNIFF_MAX_BYTES - rdata)
			return;
		if (rclass == 1 && rtype == qtype &&
		    ((rtype == 1 && rdlen == 4) || (rtype == 28 && rdlen == 16))) {
			struct sb_v3_dns_obs_value *observation = &scratch->observation;
			__builtin_memset(observation, 0, sizeof(*observation));
			__builtin_memcpy(observation->qname, scratch->qname, sizeof(observation->qname));
			observation->ttl_seconds = ((__u32)dns_byte_bounded(dns, rr + 4U) << 24) |
				((__u32)dns_byte_bounded(dns, rr + 5U) << 16) |
				((__u32)dns_byte_bounded(dns, rr + 6U) << 8) |
				dns_byte_bounded(dns, rr + 7U);
			struct sb_v3_dns_obs_key key = {};
			key.qname_hash = question.qname_hash;
			key.family = rtype == 1 ? SB_V3_AF_INET : SB_V3_AF_INET6;
			if (sb_v3_load_skb_bytes(skb, dns_offset + rdata, key.addr, rdlen) != 0)
				return;
			map_update(&v3_dns_observe, &key, observation, BPF_ANY);
			return;
		}
		p = rdata + rdlen;
	}
}

/* Source-MAC identity policy (design §7.3). The host publishes MAC-keyed
 * verdicts for LAN devices whose route rules are pure source-MAC matches.
 * An exact ifindex entry wins over the wildcard (ifindex 0 = any interface).
 * The map is small (SB_V3_MAX_SOURCE_POLICY) and only consulted when the
 * SB_V3_FLAG_MAC_SOURCE control flag is set, so the common path pays one
 * flag test. */
static __attribute__((always_inline)) const struct sb_v3_source_policy_value *
lookup_source_policy(const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_MAC_SOURCE))
		return 0;
	struct sb_v3_mac_key key = {};
	__builtin_memcpy(key.addr, packet->smac, 6);
	key.ifindex = packet->ifindex;
	const struct sb_v3_source_policy_value *policy = map_lookup(&v3_source_mac, &key);
	if (policy && policy->generation == control->policy_generation)
		return policy;
	key.ifindex = 0;
	policy = map_lookup(&v3_source_mac, &key);
	if (policy && policy->generation == control->policy_generation)
		return policy;
	return 0;
}

static __attribute__((always_inline)) const struct sb_v3_policy_value *lookup_static_policy(
	const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_STATIC_POLICY))
		return 0;
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy4_bank0, &key)
						 : map_lookup(&v3_policy4_bank1, &key);
		if (!policy || policy->generation != control->policy_generation)
			return 0;
		if (!policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy6_bank0, &key)
						 : map_lookup(&v3_policy6_bank1, &key);
		if (!policy || policy->generation != control->policy_generation)
			return 0;
		if (!policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	return 0;
}

/* Learned DIRECT promotions are consulted after authoritative static and
 * exact-flow verdicts. A static proxy/block rule or a more-specific flow
 * verdict therefore wins over a stale/generalized learned address, while a
 * valid dynamic DIRECT entry keeps its first-packet fast-path behaviour
 * without masquerading as static. */
static __attribute__((always_inline)) const struct sb_v3_dynamic_direct_value *lookup_dynamic_direct(
		const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		const struct sb_v3_dynamic_direct_value *value = map_lookup(&v3_dynamic_direct4, &key);
		if (!value || value->verdict != SB_V3_DIRECT || value->generation != control->policy_generation ||
		    value->expires_ns <= monotonic_ns() ||
		    (value->match_protocol != 0 && value->match_protocol != packet->protocol) ||
		    ((value->match_dport_min != 0 || value->match_dport_max != 0) &&
		     (packet->dport < value->match_dport_min || packet->dport > value->match_dport_max)))
			return 0;
		return value;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		const struct sb_v3_dynamic_direct_value *value = map_lookup(&v3_dynamic_direct6, &key);
		if (!value || value->verdict != SB_V3_DIRECT || value->generation != control->policy_generation ||
		    value->expires_ns <= monotonic_ns() ||
		    (value->match_protocol != 0 && value->match_protocol != packet->protocol) ||
		    ((value->match_dport_min != 0 || value->match_dport_max != 0) &&
		     (packet->dport < value->match_dport_min || packet->dport > value->match_dport_max)))
			return 0;
		return value;
	}
	return 0;
}

static __attribute__((always_inline)) bool host_address(const struct sb_v3_packet *packet) {
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		return map_lookup(&v3_host4, &key) != 0;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		return map_lookup(&v3_host6, &key) != 0;
	}
	return false;
}

static __attribute__((always_inline)) bool security_bypass(const struct sb_v3_packet *packet, int parse_rc) {
	if (parse_rc == 1)
		return true;
	if (packet->protocol == IPPROTO_ICMP || packet->protocol == IPPROTO_ICMPV6)
		return true;
	if (packet->protocol == IPPROTO_UDP && sb_v3_is_dhcp_ports(packet->sport, packet->dport))
		return true;
	if (packet->family == SB_V3_AF_INET) {
		if (sb_v3_ipv4_is_multicast(packet->daddr) || sb_v3_ipv4_is_broadcast_like(packet->daddr))
			return true;
	} else if (packet->family == SB_V3_AF_INET6) {
		if (sb_v3_ipv6_is_multicast(packet->daddr))
			return true;
	}
	if (host_address(packet))
		return true;
	return false;
}

static __attribute__((always_inline)) const struct sb_v3_flow_value *lookup_flow(
	const struct sb_v3_control *control, const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_EXACT_FLOW))
		return 0;
	/* Userspace publishes both directions with direction=0 and swapped
	 * 5-tuples so TC can key solely on the on-wire addresses/ports. */
	struct sb_v3_flow_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.direction = 0;
	key.sport = packet->sport;
	key.dport = packet->dport;
	__builtin_memcpy(key.saddr, packet->saddr, 16);
	__builtin_memcpy(key.daddr, packet->daddr, 16);
	struct sb_v3_flow_value *value = map_lookup(&v3_flow_verdict, &key);
	if (!value)
		return 0;
	if (value->generation != control->policy_generation) {
		count_stat(SB_V3_STAT_GENERATION_MISS_PROXY);
		return 0;
	}
	if (value->expires_ns <= monotonic_ns())
		return 0;
	return value;
}

static __attribute__((always_inline)) bool dns_hint_allows_direct(const struct sb_v3_control *control,
								  const struct sb_v3_packet *packet,
								  __u32 *reason_out) {
	if (!(control->flags & SB_V3_FLAG_DNS_HINT) && !(control->flags & SB_V3_FLAG_FAKEIP))
		return false;
	struct sb_v3_dns_ip_key key = {};
	key.family = packet->family;
	__builtin_memcpy(key.addr, packet->daddr, 16);
	struct sb_v3_dns_ip_value *hint = map_lookup(&v3_dns_ip_hint, &key);
	if (!hint)
		return false;
	if (hint->generation != control->policy_generation)
		return false;
	if (hint->expires_ns <= monotonic_ns())
		return false;
	if (hint->proxy_refs != 0) {
		count_stat(SB_V3_STAT_DNS_HINT_CONFLICT);
		return false;
	}
	if (hint->direct_refs == 0 || hint->evidence == SB_V3_DNS_EVIDENCE_WEAK)
		return false;
	if (hint->evidence == SB_V3_DNS_EVIDENCE_FAKEIP) {
		if (!(control->flags & SB_V3_FLAG_FAKEIP))
			return false;
		*reason_out = SB_V3_STAT_FAKEIP_DIRECT;
		return true;
	}
	if (hint->evidence == SB_V3_DNS_EVIDENCE_STRONG) {
		if (!(control->flags & SB_V3_FLAG_DNS_HINT))
			return false;
		*reason_out = SB_V3_STAT_DNS_HINT_DIRECT;
		return true;
	}
	return false;
}

static __attribute__((always_inline)) int listener_key_for(const struct sb_v3_packet *packet) {
	if (packet->family == SB_V3_AF_INET && packet->protocol == IPPROTO_TCP)
		return SB_V3_LISTENER_TCP4;
	if (packet->family == SB_V3_AF_INET && packet->protocol == IPPROTO_UDP)
		return SB_V3_LISTENER_UDP4;
	if (packet->family == SB_V3_AF_INET6 && packet->protocol == IPPROTO_TCP)
		return SB_V3_LISTENER_TCP6;
	if (packet->family == SB_V3_AF_INET6 && packet->protocol == IPPROTO_UDP)
		return SB_V3_LISTENER_UDP6;
	return -1;
}

static __attribute__((always_inline)) int remember_redirect(const struct sb_v3_packet *packet,
							    __u32 ifindex) {
	struct sb_v3_redirect_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.client_port = packet->sport;
	key.dest_port = packet->dport;
	__builtin_memcpy(key.client_addr, packet->saddr, 16);
	__builtin_memcpy(key.dest_addr, packet->daddr, 16);
	if (map_lookup(&v3_redirect, &key))
		return 0;
	struct sb_v3_redirect_value value = {};
	value.family = packet->family;
	value.protocol = packet->protocol;
	value.dest_port = packet->dport;
	value.ifindex = ifindex;
	__builtin_memcpy(value.dest_addr, packet->daddr, 16);
	__builtin_memcpy(value.source_mac, packet->smac, 6);
	return map_update(&v3_redirect, &key, &value, BPF_ANY);
}

static __attribute__((always_inline)) void forget_redirect(const struct sb_v3_packet *packet) {
	struct sb_v3_redirect_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.client_port = packet->sport;
	key.dest_port = packet->dport;
	__builtin_memcpy(key.client_addr, packet->saddr, 16);
	__builtin_memcpy(key.dest_addr, packet->daddr, 16);
	map_delete(&v3_redirect, &key);
}

static __attribute__((always_inline)) int assign_established(struct __sk_buff *skb,
							     const struct sb_v3_packet *packet) {
	if (packet->protocol != IPPROTO_TCP)
		return 0;
	struct bpf_sock_tuple tuple = {};
	__u32 tuple_size;
	if (packet->family == SB_V3_AF_INET) {
		__builtin_memcpy(&tuple.ipv4.saddr, packet->saddr, 4);
		__builtin_memcpy(&tuple.ipv4.daddr, packet->daddr, 4);
		tuple.ipv4.sport = __builtin_bswap16(packet->sport);
		tuple.ipv4.dport = __builtin_bswap16(packet->dport);
		tuple_size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.saddr, packet->saddr, 16);
		__builtin_memcpy(tuple.ipv6.daddr, packet->daddr, 16);
		tuple.ipv6.sport = __builtin_bswap16(packet->sport);
		tuple.ipv6.dport = __builtin_bswap16(packet->dport);
		tuple_size = sizeof(tuple.ipv6);
	}
	struct bpf_sock *socket = lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
	if (!socket)
		return 0;
	if (socket->state == BPF_TCP_LISTEN) {
		release_socket(socket);
		return 0;
	}
	long result = assign_socket(skb, socket, 0);
	release_socket(socket);
	return result == 0 ? 1 : -1;
}

/* Mark policy (match working v2 TC on Alpine):
 * - Never clear skb->mark (writing mark=0 after data/ctx use trips
 *   "dereference of modified ctx ptr ... disallowed").
 * - Only set mark after a successful sk_assign, like shared_network_v2.bpf.c.
 */
static __attribute__((always_inline)) int handoff_proxy(struct __sk_buff *skb,
							const struct sb_v3_control *control,
							const struct sb_v3_packet *packet,
							__u32 reason,
							__u32 ifindex,
							__u32 pkt_len) {
	/* One lookup records the reason, packet and byte counters together. */
	count_proxy(reason, pkt_len);

	if (!(control->flags & SB_V3_FLAG_SOCKET_ASSIGN))
		return TC_ACT_OK;

	if (remember_redirect(packet, ifindex) != 0)
		count_stat(SB_V3_STAT_MAP_CAPACITY_REJECT);

	int lkey = listener_key_for(packet);
	if (lkey < 0) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		return TC_ACT_OK;
	}
	__u32 key = (__u32)lkey;
	struct bpf_sock *listener = map_lookup(&v3_listener_sockets, &key);
	if (!listener) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		forget_redirect(packet);
		return TC_ACT_OK;
	}
	long result = assign_socket(skb, listener, 0);
	/* SOCKMAP lookup leaves a ref; always release (v2 pattern). */
	release_socket(listener);
	if (result != 0) {
		count_stat(SB_V3_STAT_SOCKET_ASSIGN_FAILURE);
		forget_redirect(packet);
		return TC_ACT_OK;
	}
	skb->mark = control->routing_mark;
	count_stat(SB_V3_STAT_SOCKET_ASSIGN_SUCCESS);
	return TC_ACT_OK;
}

static __attribute__((always_inline)) int action_direct(struct __sk_buff *skb, __u32 reason) {
	/* DIRECT: leave mark alone; Linux L3 forwards without PBR mark. */
	(void)skb;
	count_direct(reason);
	return TC_ACT_OK;
}

static __attribute__((always_inline)) int action_block(struct __sk_buff *skb) {
	(void)skb;
	count_stat(SB_V3_STAT_BLOCKED);
	return TC_ACT_SHOT;
}

SEC("classifier/ingress")
int sb_v3_ingress(struct __sk_buff *skb) {
	__u32 zero = 0;
	struct sb_v3_control *control = map_lookup(&v3_control, &zero);
	if (!control || !control->enabled || control->abi_version != SB_V3_ABI_VERSION)
		return TC_ACT_OK;

	/* Capture scalar metadata once from the original ctx before any pkt walk.
	 * Never stash a derived ctx pointer for later load (Alpine verifier). */
	__u32 ifindex = skb->ingress_ifindex;
	if (ifindex == 0)
		ifindex = skb->ifindex;
	__u32 pkt_len = skb->len;
	__u32 routing_mark = control->routing_mark;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct sb_v3_packet packet = {};
	int parse_rc = sb_v3_parse(skb, data, data_end, &packet);
	packet.ifindex = ifindex;

	if (parse_rc < 0) {
		count_stat(SB_V3_STAT_PARSE_FAIL_PROXY);
		/* No reliable five-tuple exists, so leave the frame to the kernel with
		 * no mark. Calling handoff_proxy here would manufacture a redirect key
		 * from zeroed fields and cannot select a listener safely. */
		return TC_ACT_OK;
	}

	/* DNS sniffing is advisory: only bounded source-port-53 UDP responses enter
	 * the parser, and parser/helper failures never alter the packet verdict. */
	if (parse_rc == 0 && !packet.fragmented &&
	    (control->flags & SB_V3_FLAG_DNS_SNIFF) != 0 &&
	    packet.protocol == IPPROTO_UDP && packet.sport == 53) {
		__u32 payload_offset = packet.payload_offset;
		struct udphdr udp_header = {};
		if (sb_v3_load_skb_bytes(skb, payload_offset, &udp_header, sizeof(udp_header)) == 0) {
			__u32 udp_len = __builtin_bswap16(udp_header.len);
			if (udp_len >= sizeof(udp_header)) {
				__u32 dns_len = udp_len - sizeof(udp_header);
				if (dns_len > SB_V3_DNS_SNIFF_MAX_BYTES)
					dns_len = SB_V3_DNS_SNIFF_MAX_BYTES;
				/* skb_load_bytes rejects a zero-length request on some verifier
				 * versions. Keep the helper length >=12; short DNS payloads are not
				 * passed to the parser below. */
				__u32 copy_len = dns_len;
				if (copy_len < 12U)
					copy_len = 12U;
				__u32 scratch_key = 0;
				struct sb_v3_dns_scratch *scratch = map_lookup(&v3_dns_scratch, &scratch_key);
				if (scratch &&
				    sb_v3_load_skb_bytes(skb, payload_offset + sizeof(udp_header),
						   scratch->bytes, copy_len) == 0 && dns_len >= 12U)
					dns_response_sniff_bounded(skb, payload_offset + sizeof(udp_header), scratch, dns_len);
			}
		}
	}

	/* DNS interception must precede host-address bypass.  PBR deployments send
	 * DNS to an address owned by this host (for example 10.20.30.1:53).  If
	 * host_address() runs first, those packets are passed to the local stack
	 * even though no userspace DNS socket is bound to port 53, so queries time
	 * out and never reach the configured DNS hijack path.  Only fully parsed
	 * TCP/UDP packets are eligible; DHCP, fragments and malformed packets keep
	 * their existing safety behavior. */
	if (parse_rc == 0 && (control->flags & SB_V3_FLAG_DNS_HIJACK) != 0 &&
	    (packet.protocol == IPPROTO_TCP || packet.protocol == IPPROTO_UDP) && packet.dport == 53)
		return handoff_proxy(skb, control, &packet, SB_V3_STAT_DNS_HIJACK_PROXY, ifindex, pkt_len);

	if (security_bypass(&packet, parse_rc)) {
		count_stat(SB_V3_STAT_SECURITY_BYPASS);
		return TC_ACT_OK;
	}

	/* IP fragments lack a reliable L4 5-tuple; never static/flow DIRECT them.
	 * handoff_proxy() records the reason itself — an explicit count_stat here
	 * would double-count PARSE_FAIL_PROXY for every fragmented packet. */
	if (packet.fragmented) {
		return handoff_proxy(skb, control, &packet, SB_V3_STAT_PARSE_FAIL_PROXY, ifindex, pkt_len);
	}

	if (packet.family == SB_V3_AF_INET && !(control->flags & SB_V3_FLAG_IPV4))
		return TC_ACT_OK;
	if (packet.family == SB_V3_AF_INET6 && !(control->flags & SB_V3_FLAG_IPV6))
		return TC_ACT_OK;
	if (packet.protocol == IPPROTO_TCP && !(control->flags & SB_V3_FLAG_TCP))
		return TC_ACT_OK;
	if (packet.protocol == IPPROTO_UDP && !(control->flags & SB_V3_FLAG_UDP))
		return TC_ACT_OK;
	if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	if ((control->flags & SB_V3_FLAG_DROP_UDP_443) != 0 && packet.protocol == IPPROTO_UDP &&
	    packet.dport == 443)
		return action_block(skb);

	/* Source identity overrides destination defaults: a MAC-keyed rule is
	 * strictly more specific about the client than any destination CIDR.
	 * Proxy/MustControl verdicts hand off exactly like the static path. */
	const struct sb_v3_source_policy_value *source_policy = lookup_source_policy(control, &packet);
	if (source_policy) {
		if (source_policy->verdict == SB_V3_DIRECT)
			return action_direct(skb, SB_V3_STAT_MAC_SOURCE_DIRECT);
		if (source_policy->verdict == SB_V3_BLOCK)
			return action_block(skb);
		if (source_policy->verdict == SB_V3_PROXY || source_policy->verdict == SB_V3_MUST_CONTROL)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_MAC_SOURCE_PROXY, ifindex, pkt_len);
	}

	const struct sb_v3_policy_value *static_policy = lookup_static_policy(control, &packet);
	if (static_policy) {
		if (static_policy->verdict == SB_V3_DIRECT)
			return action_direct(skb, SB_V3_STAT_STATIC_DIRECT);
		if (static_policy->verdict == SB_V3_BLOCK)
			return action_block(skb);
		if (static_policy->verdict == SB_V3_PROXY)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_STATIC_PROXY, ifindex, pkt_len);
		if (static_policy->verdict == SB_V3_MUST_CONTROL)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_MUST_CONTROL, ifindex, pkt_len);
	}

	const struct sb_v3_flow_value *flow = lookup_flow(control, &packet);
	if (flow) {
		if (flow->verdict == SB_V3_DIRECT)
			return action_direct(skb, SB_V3_STAT_FLOW_DIRECT);
		if (flow->verdict == SB_V3_BLOCK)
			return action_block(skb);
		if (flow->verdict == SB_V3_PROXY)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_FLOW_PROXY, ifindex, pkt_len);
		if (flow->verdict == SB_V3_MUST_CONTROL)
			return handoff_proxy(skb, control, &packet, SB_V3_STAT_MUST_CONTROL, ifindex, pkt_len);
	}

	const struct sb_v3_dynamic_direct_value *dynamic_direct = lookup_dynamic_direct(control, &packet);
	if (dynamic_direct && dynamic_direct->verdict == SB_V3_DIRECT)
		return action_direct(skb, dynamic_direct->reason_code != 0 ? dynamic_direct->reason_code : SB_V3_STAT_DNS_HINT_DIRECT);

	__u32 dns_reason = 0;
	if (dns_hint_allows_direct(control, &packet, &dns_reason))
		return action_direct(skb, dns_reason);

	/* Do not pay for skc_lookup_tcp when socket assignment was explicitly
	 * disabled.  This also keeps WriteControlV3's feature mask authoritative. */
	if ((control->flags & SB_V3_FLAG_SOCKET_ASSIGN) != 0 && assign_established(skb, &packet) > 0) {
		skb->mark = routing_mark;
		count_stat(SB_V3_STAT_ESTABLISHED_BYPASS);
		return TC_ACT_OK;
	}

	return handoff_proxy(skb, control, &packet, SB_V3_STAT_MAP_MISS_PROXY, ifindex, pkt_len);
}

char _license[] SEC("license") = "GPL";
