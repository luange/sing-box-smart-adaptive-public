// Copyright 2026 sing-box data-plane v2 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dataplane_v2_parser.h"

#include "btf_map.h"
#include "shared_network.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))

#ifndef SB_SOURCE_HASH
#define SB_SOURCE_HASH "untracked"
#endif

const char sb_dp2_source_hash[] SEC(".sb.source") = SB_SOURCE_HASH;

struct sb_dp2_lpm4 { __u32 prefixlen; __u8 addr[4]; };
struct sb_dp2_lpm6 { __u32 prefixlen; __u8 addr[16]; };
struct sb_dp2_mac { __u8 addr[6]; __u8 reserved[2]; };

#define EXTERNAL_MAP SB_BTF_MAP

EXTERNAL_MAP(shared_control, BPF_MAP_TYPE_ARRAY, __u32, struct sb_shared_control, 1U, 0U);
/* TCP entries are consumed by accept. UDP entries remain readable for every
 * datagram in a flow and are bounded by LRU eviction. */
EXTERNAL_MAP(shared_redirect, BPF_MAP_TYPE_LRU_HASH, struct sb_shared_redirect_key,
             struct sb_shared_original_dst, SB_SHARED_NETWORK_MAP_ENTRIES, 0U);
/* Verdicts carry an expiry timestamp, but expiry alone does not release hash
 * slots. LRU keeps stale flow epochs from exhausting the bounded map. */
EXTERNAL_MAP(shared_flow_direct, BPF_MAP_TYPE_LRU_HASH, struct sb_shared_flow_key,
             struct sb_shared_flow_value, SB_SHARED_NETWORK_MAP_ENTRIES, 0U);
EXTERNAL_MAP(shared_listener_sockets, BPF_MAP_TYPE_SOCKMAP, __u32, __u64,
             SB_SHARED_LISTENER_COUNT, 0U);
EXTERNAL_MAP(shared_interface_mac, BPF_MAP_TYPE_HASH, struct sb_dp2_mac, __u32,
             SB_SHARED_NETWORK_INTERFACE_ENTRIES, 0U);
EXTERNAL_MAP(shared_stats, BPF_MAP_TYPE_ARRAY, __u32, __u64, SB_SHARED_STAT_COUNT, 0U);
EXTERNAL_MAP(shared_host_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_host_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_bypass_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_bypass_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_dns_direct_ipv4, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm4, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);
EXTERNAL_MAP(shared_dns_direct_ipv6, BPF_MAP_TYPE_LPM_TRIE, struct sb_dp2_lpm6, __u8,
             SB_SHARED_NETWORK_MAP_ENTRIES, BPF_F_NO_PREALLOC);

static void *(*map_lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static long (*assign_socket)(struct __sk_buff *, void *, __u64) = (void *)BPF_FUNC_sk_assign;
static long (*release_socket)(void *) = (void *)BPF_FUNC_sk_release;
static struct bpf_sock *(*lookup_tcp)(void *, struct bpf_sock_tuple *, __u32, __u64, __u64) =
    (void *)BPF_FUNC_skc_lookup_tcp;
static __u64 (*monotonic_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __attribute__((always_inline)) void count_stat(__u32 key) {
    __u64 *value = map_lookup(&shared_stats, &key);
    if (value) __sync_fetch_and_add(value, 1);
}

static __attribute__((always_inline)) bool lpm4_has(void *map, const __u8 address[16]) {
    struct sb_dp2_lpm4 key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, address, 4);
    return map_lookup(map, &key) != 0;
}

static __attribute__((always_inline)) bool lpm6_has(void *map, const __u8 address[16]) {
    struct sb_dp2_lpm6 key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, address, 16);
    return map_lookup(map, &key) != 0;
}

static __attribute__((always_inline)) bool destination_bypass(const struct sb_dp2_packet *packet) {
    if (packet->family == SB_DP2_AF_INET) {
        if (lpm4_has(&shared_host_ipv4, packet->destination) ||
            lpm4_has(&shared_bypass_ipv4, packet->destination)) return true;
        return packet->destination_port == 53 &&
               lpm4_has(&shared_dns_direct_ipv4, packet->destination);
    }
    if (lpm6_has(&shared_host_ipv6, packet->destination) ||
        lpm6_has(&shared_bypass_ipv6, packet->destination)) return true;
    return packet->destination_port == 53 &&
           lpm6_has(&shared_dns_direct_ipv6, packet->destination);
}

static __attribute__((always_inline)) bool protocol_bypass(
    const struct sb_dp2_packet *packet, const struct sb_shared_control *control) {
    if (packet->protocol == IPPROTO_UDP &&
        (packet->source_port == 67 || packet->source_port == 68 ||
         packet->source_port == 546 || packet->source_port == 547 ||
         packet->destination_port == 67 || packet->destination_port == 68 ||
         packet->destination_port == 546 || packet->destination_port == 547)) return true;
    if (packet->destination_port != 53) return destination_bypass(packet);
    if (!(control->flags & SB_SHARED_FLAG_DNS_HIJACK)) return true;
    if (packet->family == SB_DP2_AF_INET)
        return lpm4_has(&shared_dns_direct_ipv4, packet->destination);
    return lpm6_has(&shared_dns_direct_ipv6, packet->destination);
}

static __attribute__((always_inline)) bool learned_direct(const struct sb_dp2_packet *packet) {
    struct sb_shared_flow_key key = {};
    key.family = packet->family;
    key.protocol = packet->protocol;
    key.client_port = packet->source_port;
    key.original_port = packet->destination_port;
    __builtin_memcpy(key.client_addr, packet->source, 16);
    __builtin_memcpy(key.original_addr, packet->destination, 16);
    struct sb_shared_flow_value *value = map_lookup(&shared_flow_direct, &key);
	/* The exact five-tuple is the flow epoch. A policy generation change only
	 * affects future tuples and never invalidates an established direct flow. */
    return value && value->expires_ns > monotonic_ns();
}

static __attribute__((always_inline)) int assign_established_socket(struct __sk_buff *skb,
                                                                    const struct sb_dp2_packet *packet) {
	/* TCP creates an accepted kernel socket. UDP remains on the shared listener
	 * and its flow lifetime is owned by userspace, so a UDP lookup would merely
	 * rediscover the listener and incorrectly bypass first packets. */
	if (packet->protocol != IPPROTO_TCP) return 0;
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (packet->family == SB_DP2_AF_INET) {
        __builtin_memcpy(&tuple.ipv4.saddr, packet->source, 4);
        __builtin_memcpy(&tuple.ipv4.daddr, packet->destination, 4);
        tuple.ipv4.sport = __builtin_bswap16(packet->source_port);
        tuple.ipv4.dport = __builtin_bswap16(packet->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        __builtin_memcpy(tuple.ipv6.saddr, packet->source, 16);
        __builtin_memcpy(tuple.ipv6.daddr, packet->destination, 16);
        tuple.ipv6.sport = __builtin_bswap16(packet->source_port);
        tuple.ipv6.dport = __builtin_bswap16(packet->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
	struct bpf_sock *socket = lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (!socket) return 0;
	if (socket->state == BPF_TCP_LISTEN) {
		release_socket(socket);
		return 0;
	}
	long result = assign_socket(skb, socket, 0);
    release_socket(socket);
	return result == 0 ? 1 : -1;
}

static __attribute__((always_inline)) int remember_original(struct __sk_buff *skb,
                                                             const struct sb_dp2_packet *packet,
                                                             const struct ethhdr *ethernet) {
    struct sb_shared_redirect_key key = {};
    key.family = packet->family;
    key.protocol = packet->protocol;
    key.redirect_port = packet->destination_port;
    key.client_port = packet->source_port;
    __builtin_memcpy(key.redirect_addr, packet->destination, 16);
    __builtin_memcpy(key.client_addr, packet->source, 16);

    /* UDP reuses this entry for the lifetime of its tuple.  Avoid a map write
     * for every QUIC/datagram packet; an LRU eviction is recoverable because
     * the next packet still carries the original destination and recreates it
     * before socket assignment. */
    if (map_lookup(&shared_redirect, &key)) return 0;

    struct sb_shared_original_dst value = {};
    value.family = packet->family;
    value.protocol = packet->protocol;
    value.port = packet->destination_port;
    /* Reuse the ABI field that v1 uses for ingress ownership.  Userspace
     * consumes it as IngressIfIndex when constructing routing metadata. */
    struct sb_dp2_mac mac = {};
    __builtin_memcpy(mac.addr, ethernet->h_dest, 6);
    __u32 *logical_ifindex = map_lookup(&shared_interface_mac, &mac);
    value.socket_cookie = logical_ifindex ? *logical_ifindex :
        (skb->ingress_ifindex ? skb->ingress_ifindex : skb->ifindex);
    __builtin_memcpy(value.addr, packet->destination, 16);
    return map_update(&shared_redirect, &key, &value, BPF_ANY);
}

static __attribute__((always_inline)) void forget_original(const struct sb_dp2_packet *packet) {
    struct sb_shared_redirect_key key = {};
    key.family = packet->family;
    key.protocol = packet->protocol;
    key.redirect_port = packet->destination_port;
    key.client_port = packet->source_port;
    __builtin_memcpy(key.redirect_addr, packet->destination, 16);
    __builtin_memcpy(key.client_addr, packet->source, 16);
    map_delete(&shared_redirect, &key);
}

SEC("classifier/ingress")
int sb_share_v2_in(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (!control || !control->enabled || !(control->flags & SB_SHARED_FLAG_SOCKET_ASSIGN))
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct sb_dp2_packet packet = {};
    if (sb_dp2_parse(data, data_end, &packet) != 0 || packet.fragmented) {
        count_stat(SB_SHARED_STAT_PARSE_FAILURES);
        count_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_OK;
    }
    if (packet.protocol != IPPROTO_TCP && packet.protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    if ((packet.protocol == IPPROTO_TCP && !(control->flags & SB_SHARED_FLAG_TCP)) ||
        (packet.protocol == IPPROTO_UDP && !(control->flags & SB_SHARED_FLAG_UDP)))
        return TC_ACT_OK;
	int established = assign_established_socket(skb, &packet);
	if (established > 0) {
		skb->mark = control->routing_mark;
        count_stat(SB_SHARED_STAT_ESTABLISHED_BYPASS);
        return TC_ACT_OK;
    }
	if (established < 0) {
		count_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
		count_stat(SB_SHARED_STAT_FALLBACK_OPEN);
		return TC_ACT_OK;
	}
    if (protocol_bypass(&packet, control) ||
		((control->flags & SB_SHARED_FLAG_FLOW_DIRECT) && learned_direct(&packet))) {
        count_stat(SB_SHARED_STAT_POLICY_BYPASS);
        count_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_OK;
    }
    if (packet.protocol == IPPROTO_UDP && packet.destination_port == 443 &&
        (control->flags & SB_SHARED_FLAG_DROP_UDP_443)) {
        count_stat(SB_SHARED_STAT_INGRESS_DROPS);
        return TC_ACT_SHOT;
    }
    if (remember_original(skb, &packet, data) != 0) {
        count_stat(SB_SHARED_STAT_FLOW_UPDATE_FAILURES);
        count_stat(SB_SHARED_STAT_FALLBACK_OPEN);
        return TC_ACT_OK;
    }

    __u32 listener = packet.family == SB_DP2_AF_INET ?
        (packet.protocol == IPPROTO_TCP ? SB_SHARED_LISTENER_TCP4 : SB_SHARED_LISTENER_UDP4) :
        (packet.protocol == IPPROTO_TCP ? SB_SHARED_LISTENER_TCP6 : SB_SHARED_LISTENER_UDP6);
    void *socket = map_lookup(&shared_listener_sockets, &listener);
    if (!socket) {
        count_stat(SB_SHARED_STAT_LISTENER_MISSES);
        count_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
        count_stat(SB_SHARED_STAT_FALLBACK_OPEN);
		forget_original(&packet);
        return TC_ACT_OK;
    }
    long result = assign_socket(skb, socket, 0);
	/* The Linux TC verifier exposes a SOCKMAP lookup as ref_obj_id and rejects
	 * every exit path that does not release it.  This is covered by the real
	 * kernel verifier matrix rather than assumed from generic map semantics. */
	release_socket(socket);
    if (result != 0) {
        count_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
        count_stat(SB_SHARED_STAT_FALLBACK_OPEN);
		forget_original(&packet);
        return TC_ACT_OK;
    }
	skb->mark = control->routing_mark;
    count_stat(SB_SHARED_STAT_SOCKET_ASSIGNMENTS);
    count_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
    return TC_ACT_OK;
}

char sb_dp2_license[] SEC("license") = "GPL";
