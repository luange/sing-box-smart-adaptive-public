// Copyright 2026 sing-box data-plane v2 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_DATAPLANE_V2_PARSER_H
#define SING_BOX_DATAPLANE_V2_PARSER_H

#include "dataplane_v2.h"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SB_DP2_AF_INET 2U
#define SB_DP2_AF_INET6 10U

struct sb_dp2_ipv6_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

static __attribute__((always_inline)) void sb_dp2_copy4(__u8 out[16], __be32 value) {
    __builtin_memset(out, 0, 16);
    __builtin_memcpy(out, &value, 4);
}

static __attribute__((always_inline)) int sb_dp2_parse(void *data, void *data_end, struct sb_dp2_packet *packet) {
    struct ethhdr *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return -1;
    __u64 offset = sizeof(*ethernet);
    __be16 ether_type = ethernet->h_proto;

#pragma unroll
    for (int depth = 0; depth < 2; depth++) {
        if (ether_type != __builtin_bswap16(ETH_P_8021Q) &&
            ether_type != __builtin_bswap16(ETH_P_8021AD)) break;
        struct vlan_hdr { __be16 tci; __be16 proto; } *vlan = data + offset;
        if ((void *)(vlan + 1) > data_end) return -1;
        ether_type = vlan->proto;
        offset += sizeof(*vlan);
        packet->vlan_depth++;
    }

    __u64 transport_offset;
    if (ether_type == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *ip = data + offset;
        if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5) return -1;
        transport_offset = offset + ((__u64)ip->ihl * 4U);
        if (data + transport_offset > data_end) return -1;
        packet->family = SB_DP2_AF_INET;
        packet->protocol = ip->protocol;
        packet->fragmented = (ip->frag_off & __builtin_bswap16(0x3fffU)) != 0;
        sb_dp2_copy4(packet->source, ip->saddr);
        sb_dp2_copy4(packet->destination, ip->daddr);
    } else if (ether_type == __builtin_bswap16(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + offset;
        if ((void *)(ip6 + 1) > data_end) return -1;
        transport_offset = offset + sizeof(*ip6);
        packet->family = SB_DP2_AF_INET6;
        packet->protocol = ip6->nexthdr;
        __builtin_memcpy(packet->source, &ip6->saddr, 16);
        __builtin_memcpy(packet->destination, &ip6->daddr, 16);
#pragma unroll
        for (int extension = 0; extension < 3; extension++) {
            if (packet->protocol == IPPROTO_FRAGMENT) {
				struct sb_dp2_ipv6_frag_hdr *fragment = data + transport_offset;
                if ((void *)(fragment + 1) > data_end) return -1;
                packet->fragmented = 1;
                packet->protocol = fragment->nexthdr;
                transport_offset += sizeof(*fragment);
                break;
            }
            if (packet->protocol != IPPROTO_HOPOPTS && packet->protocol != IPPROTO_ROUTING &&
                packet->protocol != IPPROTO_DSTOPTS) break;
            struct ipv6_opt_hdr *option = data + transport_offset;
            if ((void *)(option + 1) > data_end) return -1;
            __u64 option_length = ((__u64)option->hdrlen + 1U) * 8U;
            if (option_length < 8U || data + transport_offset + option_length > data_end) return -1;
            packet->protocol = option->nexthdr;
            transport_offset += option_length;
        }
    } else {
        return -1;
    }

    if (packet->fragmented) return 0;
    if (packet->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + transport_offset;
        if ((void *)(tcp + 1) > data_end) return -1;
        packet->source_port = __builtin_bswap16(tcp->source);
        packet->destination_port = __builtin_bswap16(tcp->dest);
    } else if (packet->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + transport_offset;
        if ((void *)(udp + 1) > data_end) return -1;
        packet->source_port = __builtin_bswap16(udp->source);
        packet->destination_port = __builtin_bswap16(udp->dest);
    }
    return 0;
}

#endif
