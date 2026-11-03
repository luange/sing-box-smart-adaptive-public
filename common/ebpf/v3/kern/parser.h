// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_EBPF_V3_PARSER_H
#define SING_BOX_EBPF_V3_PARSER_H

#include "abi.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

/* Direct packet-pointer bounds are not preserved when an L4 offset is stored
 * in sb_v3_packet and later reloaded. Use the skb helper for variable-offset
 * transport headers so the verifier, rather than a second pointer proof, owns
 * the bounds check. */
static long (*sb_v3_load_skb_bytes)(const struct __sk_buff *, __u32, void *, __u32) =
	(void *)BPF_FUNC_skb_load_bytes;

struct sb_v3_ipv6_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

static __attribute__((always_inline)) void sb_v3_copy4(__u8 out[16], __be32 value) {
	__builtin_memset(out, 0, 16);
	__builtin_memcpy(out, &value, 4);
}

/* Bounded L2/L3/L4 parse. Returns 0 on success, 1 for ARP, and -1 for an
 * unclassifiable/truncated frame. The classifier passes -1 unchanged with no
 * mark: there is no trustworthy five-tuple with which to perform socket
 * assignment, and malformed/non-IP frames must not be routed using zeroed
 * fields. */
static __attribute__((always_inline)) int sb_v3_parse(struct __sk_buff *skb, void *data, void *data_end,
							       struct sb_v3_packet *packet) {
	__builtin_memset(packet, 0, sizeof(*packet));
	struct ethhdr *ethernet = data;
	if ((void *)(ethernet + 1) > data_end)
		return -1;
	__builtin_memcpy(packet->smac, ethernet->h_source, 6);
	__builtin_memcpy(packet->dmac, ethernet->h_dest, 6);
	__u64 offset = sizeof(*ethernet);
	__be16 ether_type = ethernet->h_proto;

#pragma unroll
	for (int depth = 0; depth < 2; depth++) {
		if (ether_type != __builtin_bswap16(ETH_P_8021Q) &&
		    ether_type != __builtin_bswap16(ETH_P_8021AD))
			break;
		struct vlan_hdr {
			__be16 tci;
			__be16 proto;
		} *vlan = data + offset;
		if ((void *)(vlan + 1) > data_end)
			return -1;
		ether_type = vlan->proto;
		offset += sizeof(*vlan);
		packet->vlan_depth++;
	}

	/* Non-IP: ARP and friends handled as security bypass by caller via ethertype. */
	if (ether_type == __builtin_bswap16(ETH_P_ARP)) {
		packet->protocol = 0;
		return 1; /* special: L2-only security candidate */
	}

	__u64 transport_offset;
	if (ether_type == __builtin_bswap16(ETH_P_IP)) {
		struct iphdr *ip = data + offset;
		if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
			return -1;
		transport_offset = offset + ((__u64)ip->ihl * 4U);
		if (data + transport_offset > data_end)
			return -1;
		packet->family = SB_V3_AF_INET;
		packet->protocol = ip->protocol;
		packet->fragmented = (ip->frag_off & __builtin_bswap16(0x3fffU)) != 0;
		sb_v3_copy4(packet->saddr, ip->saddr);
		sb_v3_copy4(packet->daddr, ip->daddr);
	} else if (ether_type == __builtin_bswap16(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + offset;
		if ((void *)(ip6 + 1) > data_end)
			return -1;
		transport_offset = offset + sizeof(*ip6);
		packet->family = SB_V3_AF_INET6;
		packet->protocol = ip6->nexthdr;
		__builtin_memcpy(packet->saddr, &ip6->saddr, 16);
		__builtin_memcpy(packet->daddr, &ip6->daddr, 16);
#pragma unroll
		for (int extension = 0; extension < 3; extension++) {
			if (packet->protocol == IPPROTO_FRAGMENT) {
				struct sb_v3_ipv6_frag_hdr fragment = {};
				if (transport_offset > skb->len ||
				    sb_v3_load_skb_bytes(skb, (__u32)transport_offset, &fragment, sizeof(fragment)) != 0)
					return -1;
				packet->fragmented = 1;
				packet->protocol = fragment.nexthdr;
				transport_offset += sizeof(fragment);
				break;
			}
			if (packet->protocol != IPPROTO_HOPOPTS && packet->protocol != IPPROTO_ROUTING &&
			    packet->protocol != IPPROTO_DSTOPTS)
				break;
			struct ipv6_opt_hdr option = {};
			if (transport_offset > skb->len ||
			    sb_v3_load_skb_bytes(skb, (__u32)transport_offset, &option, sizeof(option)) != 0)
				return -1;
			__u64 option_length = ((__u64)option.hdrlen + 1U) * 8U;
			if (option_length < 8U || transport_offset + option_length > skb->len)
				return -1;
			packet->protocol = option.nexthdr;
			transport_offset += option_length;
		}
	} else {
		return -1;
	}
	/* The IPv6 extension walk may have advanced the transport header. Keep the
	 * final offset, not the pre-extension value, for observational parsers. */
	if (transport_offset > 0xffffU)
		return -1;
	packet->payload_offset = (__u16)transport_offset;

	if (packet->fragmented)
		return 0;
	if (packet->protocol == IPPROTO_TCP) {
		struct tcphdr tcp = {};
		if (sb_v3_load_skb_bytes(skb, (__u32)transport_offset, &tcp, sizeof(tcp)) != 0)
			return -1;
		packet->sport = __builtin_bswap16(tcp.source);
		packet->dport = __builtin_bswap16(tcp.dest);
		/* The flags byte is stable across endian/bitfield layouts and is
		 * sufficient for the XDP first-packet gate. */
		packet->tcp_flags = *((__u8 *)&tcp + 13U);
	} else if (packet->protocol == IPPROTO_UDP) {
		struct udphdr udp = {};
		if (sb_v3_load_skb_bytes(skb, (__u32)transport_offset, &udp, sizeof(udp)) != 0)
			return -1;
		packet->sport = __builtin_bswap16(udp.source);
		packet->dport = __builtin_bswap16(udp.dest);
	}
	return 0;
}

/* XDP has no __sk_buff context, so it keeps the packet-pointer parser whose
 * bounds are proved in the same function. TC uses sb_v3_parse() above and
 * skb_load_bytes for offsets that survive a scalar store/reload. */
static __attribute__((always_inline)) int sb_v3_parse_xdp(void *data, void *data_end,
								   struct sb_v3_packet *packet) {
	__builtin_memset(packet, 0, sizeof(*packet));
	struct ethhdr *ethernet = data;
	if ((void *)(ethernet + 1) > data_end)
		return -1;
	__builtin_memcpy(packet->smac, ethernet->h_source, 6);
	__builtin_memcpy(packet->dmac, ethernet->h_dest, 6);
	__u64 offset = sizeof(*ethernet);
	__be16 ether_type = ethernet->h_proto;
#pragma unroll
	for (int depth = 0; depth < 2; depth++) {
		if (ether_type != __builtin_bswap16(ETH_P_8021Q) &&
		    ether_type != __builtin_bswap16(ETH_P_8021AD))
			break;
		struct vlan_hdr { __be16 tci; __be16 proto; } *vlan = data + offset;
		if ((void *)(vlan + 1) > data_end)
			return -1;
		ether_type = vlan->proto;
		offset += sizeof(*vlan);
		packet->vlan_depth++;
	}
	if (ether_type == __builtin_bswap16(ETH_P_ARP)) {
		packet->protocol = 0;
		return 1;
	}
	__u64 transport_offset;
	if (ether_type == __builtin_bswap16(ETH_P_IP)) {
		struct iphdr *ip = data + offset;
		if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
			return -1;
		transport_offset = offset + ((__u64)ip->ihl * 4U);
		if (data + transport_offset > data_end)
			return -1;
		packet->family = SB_V3_AF_INET;
		packet->protocol = ip->protocol;
		packet->fragmented = (ip->frag_off & __builtin_bswap16(0x3fffU)) != 0;
		sb_v3_copy4(packet->saddr, ip->saddr);
		sb_v3_copy4(packet->daddr, ip->daddr);
	} else if (ether_type == __builtin_bswap16(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + offset;
		if ((void *)(ip6 + 1) > data_end)
			return -1;
		transport_offset = offset + sizeof(*ip6);
		packet->family = SB_V3_AF_INET6;
		packet->protocol = ip6->nexthdr;
		__builtin_memcpy(packet->saddr, &ip6->saddr, 16);
		__builtin_memcpy(packet->daddr, &ip6->daddr, 16);
#pragma unroll
		for (int extension = 0; extension < 3; extension++) {
			if (packet->protocol == IPPROTO_FRAGMENT) {
				struct sb_v3_ipv6_frag_hdr *fragment = data + transport_offset;
				if ((void *)(fragment + 1) > data_end)
					return -1;
				packet->fragmented = 1;
				packet->protocol = fragment->nexthdr;
				transport_offset += sizeof(*fragment);
				break;
			}
			if (packet->protocol != IPPROTO_HOPOPTS && packet->protocol != IPPROTO_ROUTING &&
			    packet->protocol != IPPROTO_DSTOPTS)
				break;
			struct ipv6_opt_hdr *option = data + transport_offset;
			if ((void *)(option + 1) > data_end)
				return -1;
			__u64 option_length = ((__u64)option->hdrlen + 1U) * 8U;
			if (option_length < 8U || data + transport_offset + option_length > data_end)
				return -1;
			packet->protocol = option->nexthdr;
			transport_offset += option_length;
		}
	} else {
		return -1;
	}
	if (transport_offset > 0xffffU)
		return -1;
	packet->payload_offset = (__u16)transport_offset;
	if (packet->fragmented)
		return 0;
	if (packet->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = data + transport_offset;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		packet->sport = __builtin_bswap16(tcp->source);
		packet->dport = __builtin_bswap16(tcp->dest);
		packet->tcp_flags = *((__u8 *)tcp + 13U);
	} else if (packet->protocol == IPPROTO_UDP) {
		struct udphdr *udp = data + transport_offset;
		if ((void *)(udp + 1) > data_end)
			return -1;
		packet->sport = __builtin_bswap16(udp->source);
		packet->dport = __builtin_bswap16(udp->dest);
	}
	return 0;
}

static __attribute__((always_inline)) bool sb_v3_ipv4_is_multicast(const __u8 addr[16]) {
	return (addr[0] & 0xf0U) == 0xe0U;
}

static __attribute__((always_inline)) bool sb_v3_ipv4_is_broadcast_like(const __u8 addr[16]) {
	return addr[0] == 255U && addr[1] == 255U && addr[2] == 255U && addr[3] == 255U;
}

static __attribute__((always_inline)) bool sb_v3_ipv6_is_multicast(const __u8 addr[16]) {
	return addr[0] == 0xffU;
}

static __attribute__((always_inline)) bool sb_v3_is_dhcp_ports(__u16 sport, __u16 dport) {
	return sport == 67 || sport == 68 || sport == 546 || sport == 547 ||
	       dport == 67 || dport == 68 || dport == 546 || dport == 547;
}

#endif /* SING_BOX_EBPF_V3_PARSER_H */
