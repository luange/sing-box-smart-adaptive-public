// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Original XDP ingress accelerator for the v3 policy ABI.  This program is
// deliberately smaller than the TC hook: XDP can only make an L2 decision;
// it cannot assign a socket, set a TC packet mark, or consult conntrack.  Proxy and
// uncertain traffic therefore returns XDP_PASS and is handled by TC.

#define SEC(name) __attribute__((section(name), used))

#include "parser.h"
#include "xdp_policy_maps.h"

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#ifndef SB_XDP_SOURCE_HASH
#define SB_XDP_SOURCE_HASH "untracked"
#endif

const char sb_v3_xdp_source_hash[] SEC(".sb.source") = SB_XDP_SOURCE_HASH;

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_redirect)(void *, __u64, __u64) = (void *)BPF_FUNC_redirect_map;
static __u64 (*monotonic_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __attribute__((always_inline)) struct sb_v3_stats_value *stats_lookup(void) {
	__u32 zero = 0;
	return map_lookup(&v3_stats, &zero);
}

static __attribute__((always_inline)) void count_stat(__u32 key) {
	struct sb_v3_stats_value *stats = stats_lookup();
	if (stats && key < SB_V3_STATS_COUNT)
		/* v3_stats is PERCPU, so this increment is CPU-local. */
		stats->values[key] += 1;
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

static __attribute__((always_inline)) const struct sb_v3_policy_value *lookup_static_policy(
							const struct sb_v3_control *control,
							const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_STATIC_POLICY))
		return 0;
	if (packet->family == SB_V3_AF_INET) {
		struct sb_v3_lpm4_key key = {.prefixlen = 32U};
		__builtin_memcpy(key.addr, packet->daddr, 4);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy4_bank0, &key)
						     : map_lookup(&v3_policy4_bank1, &key);
		if (!policy || policy->generation != control->policy_generation || !policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	if (packet->family == SB_V3_AF_INET6) {
		struct sb_v3_lpm6_key key = {.prefixlen = 128U};
		__builtin_memcpy(key.addr, packet->daddr, 16);
		const struct sb_v3_policy_value *policy =
			control->active_bank == 0 ? map_lookup(&v3_policy6_bank0, &key)
						     : map_lookup(&v3_policy6_bank1, &key);
		if (!policy || policy->generation != control->policy_generation || !policy_port_match(policy, packet))
			return 0;
		return policy;
	}
	return 0;
}

static __attribute__((always_inline)) const struct sb_v3_flow_value *lookup_flow(
							const struct sb_v3_control *control,
							const struct sb_v3_packet *packet) {
	if (!(control->flags & SB_V3_FLAG_EXACT_FLOW))
		return 0;
	struct sb_v3_flow_key key = {};
	key.family = packet->family;
	key.protocol = packet->protocol;
	key.direction = 0;
	key.sport = packet->sport;
	key.dport = packet->dport;
	__builtin_memcpy(key.saddr, packet->saddr, 16);
	__builtin_memcpy(key.daddr, packet->daddr, 16);
	struct sb_v3_flow_value *value = map_lookup(&v3_flow_verdict, &key);
	if (!value || value->generation != control->policy_generation || value->expires_ns <= monotonic_ns())
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
	if (!hint || hint->generation != control->policy_generation || hint->expires_ns <= monotonic_ns())
		return false;
	if (hint->proxy_refs != 0 || hint->direct_refs == 0)
		return false;
	if (hint->evidence == SB_V3_DNS_EVIDENCE_FAKEIP && (control->flags & SB_V3_FLAG_FAKEIP)) {
		*reason_out = SB_V3_STAT_FAKEIP_DIRECT;
		return true;
	}
	if (hint->evidence == SB_V3_DNS_EVIDENCE_STRONG && (control->flags & SB_V3_FLAG_DNS_HINT)) {
		*reason_out = SB_V3_STAT_DNS_HINT_DIRECT;
		return true;
	}
	return false;
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
	if (packet->family == SB_V3_AF_INET &&
	    (sb_v3_ipv4_is_multicast(packet->daddr) || sb_v3_ipv4_is_broadcast_like(packet->daddr)))
		return true;
	if (packet->family == SB_V3_AF_INET6 && sb_v3_ipv6_is_multicast(packet->daddr))
		return true;
	return host_address(packet);
}

static __attribute__((always_inline)) bool tcp_first_packet(const struct sb_v3_packet *packet) {
	/* XDP has no socket state.  Only a clean SYN is safe to accelerate; ACK,
	 * RST, FIN and packets without a parsed flags byte stay in the kernel. */
	if (packet->protocol != IPPROTO_TCP)
		return true;
	return (packet->tcp_flags & 0x02U) != 0 && (packet->tcp_flags & 0x15U) == 0;
}

static __attribute__((always_inline)) int redirect_direct(struct xdp_md *ctx,
								 const struct sb_xdp_control *xdp,
								 __u32 reason) {
	__u32 queue = ctx->rx_queue_index;
	if (queue >= SB_XDP_MAX_QUEUES || queue >= xdp->queue_count)
		return XDP_PASS;
	count_direct(reason);
	/* XDP_PASS is the explicit map-miss action.  It keeps TC as the live
	 * fallback when UMEM is full or a queue has not been bound. */
	return (int)map_redirect(&v3_xsk_map, queue, XDP_PASS);
}

SEC("xdp")
int sb_v3_xdp_ingress(struct xdp_md *ctx) {
	__u32 zero = 0;
	struct sb_xdp_control *xdp = map_lookup(&v3_xdp_control, &zero);
	struct sb_v3_control *control = map_lookup(&v3_control, &zero);
	if (!xdp || !control || xdp->abi_version != SB_XDP_ABI_VERSION ||
	    (xdp->flags & SB_XDP_CTRL_ENABLED) == 0 || control->abi_version != SB_V3_ABI_VERSION ||
	    !control->enabled || xdp->policy_generation != control->policy_generation ||
	    xdp->active_bank != control->active_bank)
		return XDP_PASS;
	/* The one-descriptor parser is intentionally conservative.  A host that
	 * advertises scatter-gather support must not accidentally redirect a
	 * multi-buffer frame until the bounded segment walker is implemented. */
	if ((xdp->flags & SB_XDP_CTRL_ALLOW_MULTIBUFFER) != 0)
		return XDP_PASS;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct sb_v3_packet packet = {};
	int parse_rc = sb_v3_parse_xdp(data, data_end, &packet);
	if (parse_rc < 0 || parse_rc == 1 || security_bypass(&packet, parse_rc) || packet.fragmented)
		return XDP_PASS;
	if ((packet.family == SB_V3_AF_INET && !(control->flags & SB_V3_FLAG_IPV4)) ||
	    (packet.family == SB_V3_AF_INET6 && !(control->flags & SB_V3_FLAG_IPV6)) ||
	    (packet.protocol == IPPROTO_TCP && !(control->flags & SB_V3_FLAG_TCP)) ||
	    (packet.protocol == IPPROTO_UDP && !(control->flags & SB_V3_FLAG_UDP)) ||
	    (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP) ||
	    !tcp_first_packet(&packet))
		return XDP_PASS;

	const struct sb_v3_policy_value *static_policy = lookup_static_policy(control, &packet);
	if (static_policy) {
		if (static_policy->verdict == SB_V3_BLOCK)
			return XDP_DROP;
		if (static_policy->verdict == SB_V3_DIRECT)
			return redirect_direct(ctx, xdp, SB_V3_STAT_STATIC_DIRECT);
		return XDP_PASS;
	}
	const struct sb_v3_flow_value *flow = lookup_flow(control, &packet);
	if (flow) {
		if (flow->verdict == SB_V3_BLOCK)
			return XDP_DROP;
		if (flow->verdict == SB_V3_DIRECT)
			return redirect_direct(ctx, xdp, SB_V3_STAT_FLOW_DIRECT);
		return XDP_PASS;
	}
	__u32 dns_reason = 0;
	if (dns_hint_allows_direct(control, &packet, &dns_reason))
		return redirect_direct(ctx, xdp, dns_reason);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
