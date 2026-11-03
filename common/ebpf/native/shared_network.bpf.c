// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared_network.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))
#define NOINLINE static __attribute__((noinline))

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IP_FRAGMENT_MASK 0x3fffU

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct sb_lpm4_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct sb_lpm6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct tcp_header_min {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgement;
    __be16 flags;
    __sum16 checksum;
};

struct udp_header_min {
    __be16 source;
    __be16 destination;
    __be16 length;
    __sum16 checksum;
};

#define EXTERNAL_MAP(name, key_type, value_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), \
        .max_entries = entries, \
    }

EXTERNAL_MAP(shared_control, __u32, struct sb_shared_control, 1U);
EXTERNAL_MAP(shared_interface_mac, __u32, struct sb_shared_interface_mac, SB_SHARED_NETWORK_INTERFACE_ENTRIES);
EXTERNAL_MAP(shared_original_to_token, struct sb_shared_original_key, struct sb_shared_token_value, SB_SHARED_NETWORK_MAP_ENTRIES);
EXTERNAL_MAP(shared_token_to_original, struct sb_shared_reverse_key, struct sb_shared_reverse_value, SB_SHARED_NETWORK_MAP_ENTRIES);
EXTERNAL_MAP(shared_redirect, struct sb_shared_redirect_key, struct sb_shared_original_dst, SB_SHARED_NETWORK_MAP_ENTRIES);
/* Runtime owns this as a bounded LRU map. Exact five-tuple entries remain
 * stable while active traffic refreshes them, while expired idle epochs can
 * no longer exhaust all slots. */
EXTERNAL_MAP(shared_flow_direct, struct sb_shared_flow_key, struct sb_shared_flow_value, SB_SHARED_NETWORK_MAP_ENTRIES);
struct bpf_map_def SEC("maps") shared_listener_sockets = {
    .type = BPF_MAP_TYPE_SOCKMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = SB_SHARED_LISTENER_COUNT,
};
struct bpf_map_def SEC("maps") shared_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = SB_SHARED_STAT_COUNT,
};
EXTERNAL_MAP(shared_host_ipv4, struct sb_lpm4_key, __u8, 256U);
EXTERNAL_MAP(shared_host_ipv6, struct sb_lpm6_key, __u8, 256U);
EXTERNAL_MAP(shared_bypass_ipv4, struct sb_lpm4_key, __u8, 16384U);
EXTERNAL_MAP(shared_bypass_ipv6, struct sb_lpm6_key, __u8, 16384U);
/* dns_kernel_direct: :53 to these destinations stays kernel when hijack is on. */
EXTERNAL_MAP(shared_dns_direct_ipv4, struct sb_lpm4_key, __u8, 256U);
EXTERNAL_MAP(shared_dns_direct_ipv6, struct sb_lpm6_key, __u8, 256U);
struct bpf_map_def SEC("maps") shared_scratch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sb_shared_scratch),
    .max_entries = 1U,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*skb_pull_data)(struct __sk_buff *skb, __u32 length) = (void *)BPF_FUNC_skb_pull_data;
static long (*skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static long (*sk_assign)(struct __sk_buff *skb, struct bpf_sock *sk, __u64 flags) =
    (void *)BPF_FUNC_sk_assign;
static void (*sk_release)(struct bpf_sock *sk) = (void *)BPF_FUNC_sk_release;

INLINE void increment_stat(__u32 key) {
    __u64 *value = map_lookup(&shared_stats, &key);
    if (value != 0) __sync_fetch_and_add(value, 1U);
}

INLINE __u16 swap16(__u16 value) {
    return __builtin_bswap16(value);
}

INLINE __u32 swap32(__u32 value) {
    return __builtin_bswap32(value);
}

INLINE void copy_address(__u8 destination[16], const __u8 source[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size) destination[index] = source[index];
    }
}

INLINE bool equal_address(const __u8 left[16], const __u8 right[16], __u32 size) {
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 16U; ++index) {
        if (index < size && left[index] != right[index]) return false;
    }
    return true;
}

INLINE bool selected_protocol(__u8 protocol, const struct sb_shared_control *control) {
    if (protocol == IPPROTO_TCP_VALUE) return (control->flags & SB_SHARED_FLAG_TCP) != 0U;
    if (protocol == IPPROTO_UDP_VALUE) return (control->flags & SB_SHARED_FLAG_UDP) != 0U;
    return false;
}

INLINE bool ingress_destination_matches_interface(
    const struct __sk_buff *skb,
    const struct ethernet_header *ethernet) {
    __u32 ifindex = skb->ifindex;
    struct sb_shared_interface_mac *interface_mac = map_lookup(&shared_interface_mac, &ifindex);
    if (interface_mac == 0) return false;
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < 6U; ++index) {
        if (ethernet->destination[index] != interface_mac->addr[index]) return false;
    }
    return true;
}

INLINE bool dhcp_packet(__u8 protocol, __u16 source_port, __u16 destination_port) {
    if (protocol != IPPROTO_UDP_VALUE) return false;
    return source_port == 67U || source_port == 68U ||
        source_port == 546U || source_port == 547U ||
        destination_port == 67U || destination_port == 68U ||
        destination_port == 546U || destination_port == 547U;
}

INLINE bool ipv4_builtin_bypass(const __u8 address[4]) {
    if (address[0] == 0U || address[0] == 10U || address[0] == 127U || address[0] >= 224U) return true;
    if (address[0] == 100U && (address[1] & 0xc0U) == 0x40U) return true;
    if (address[0] == 169U && address[1] == 254U) return true;
    if (address[0] == 172U && (address[1] & 0xf0U) == 0x10U) return true;
    if (address[0] == 192U && address[1] == 168U) return true;
    return false;
}

INLINE bool ipv6_builtin_bypass(const __u8 address[16]) {
    if (address[0] == 0xffU || (address[0] & 0xfeU) == 0xfcU) return true;
    return address[0] == 0xfeU && (address[1] & 0xc0U) == 0x80U;
}

INLINE void fill_flow_key(
    struct sb_shared_flow_key *key,
    __u8 family,
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    const __u8 source[16],
    const __u8 destination[16]) {
    __builtin_memset(key, 0, sizeof(*key));
    key->family = family;
    key->protocol = protocol;
    key->client_port = source_port;
    key->original_port = destination_port;
    copy_address(key->client_addr, source, family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(key->original_addr, destination, family == AF_INET6_VALUE ? 16U : 4U);
}

INLINE bool direct_flow_hit(
    const struct sb_shared_control *control,
    const struct sb_shared_flow_key *key) {
    if ((control->flags & SB_SHARED_FLAG_FLOW_DIRECT) == 0U) return false;
    struct sb_shared_flow_value *value = map_lookup(&shared_flow_direct, key);
    if (value == 0) return false;
    __u64 now = ktime_get_ns();
    if (value->generation != control->flow_generation || value->expires_ns <= now) {
        map_delete(&shared_flow_direct, key);
        return false;
    }
    return true;
}

NOINLINE bool proxy_ipv4(
    const __u8 destination[4],
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    bool hijack_dns) {
    if (dhcp_packet(protocol, source_port, destination_port)) return false;
    if (destination_port == 53U) {
        if (!hijack_dns) return false;
        /* dns_kernel_direct: selected DNS servers keep kernel path. */
        struct sb_lpm4_key dns_key = {.prefixlen = 32U};
        __builtin_memcpy(dns_key.addr, destination, 4U);
        if (map_lookup(&shared_dns_direct_ipv4, &dns_key) != 0) return false;
        return true;
    }
    if (ipv4_builtin_bypass(destination)) return false;
    struct sb_lpm4_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.addr, destination, 4U);
    if (map_lookup(&shared_host_ipv4, &key) != 0) return false;
    return map_lookup(&shared_bypass_ipv4, &key) == 0;
}

NOINLINE bool proxy_ipv6(
    const __u8 destination[16],
    __u8 protocol,
    __u16 source_port,
    __u16 destination_port,
    bool hijack_dns) {
    if (dhcp_packet(protocol, source_port, destination_port)) return false;
    if (destination_port == 53U) {
        if (!hijack_dns) return false;
        struct sb_lpm6_key dns_key = {.prefixlen = 128U};
        __builtin_memcpy(dns_key.addr, destination, 16U);
        if (map_lookup(&shared_dns_direct_ipv6, &dns_key) != 0) return false;
        return true;
    }
    if (ipv6_builtin_bypass(destination)) return false;
    struct sb_lpm6_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.addr, destination, 16U);
    if (map_lookup(&shared_host_ipv6, &key) != 0) return false;
    return map_lookup(&shared_bypass_ipv6, &key) == 0;
}

NOINLINE __u32 hash_original(const struct sb_shared_original_key *key, __u32 salt) {
    const __u8 *bytes = (const __u8 *)key;
    __u32 hash = 2166136261U ^ salt;
#pragma clang loop unroll(full)
    for (__u32 index = 0U; index < sizeof(*key); ++index) {
        hash ^= bytes[index];
        hash *= 16777619U;
    }
    hash ^= hash >> 16U;
    hash *= 0x7feb352dU;
    hash ^= hash >> 15U;
    hash *= 0x846ca68bU;
    hash ^= hash >> 16U;
    return hash;
}

INLINE void fill_redirect(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    __builtin_memset(&scratch->redirect_key, 0, sizeof(scratch->redirect_key));
    scratch->redirect_key.family = scratch->original.family;
    scratch->redirect_key.protocol = scratch->original.protocol;
    scratch->redirect_key.redirect_port = control->bridge_port;
    scratch->redirect_key.client_port = scratch->original.client_port;
    copy_address(
        scratch->redirect_key.redirect_addr,
        scratch->token.token_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(
        scratch->redirect_key.client_addr,
        scratch->original.client_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    __builtin_memset(&scratch->redirect_value, 0, sizeof(scratch->redirect_value));
    scratch->redirect_value.family = scratch->original.family;
    scratch->redirect_value.protocol = scratch->original.protocol;
    scratch->redirect_value.port = scratch->original.original_port;
    copy_address(
        scratch->redirect_value.addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    /* Carry the ingress interface to userspace without changing the shared ABI. */
    scratch->redirect_value.socket_cookie = (__u64)scratch->original.ifindex;
}

INLINE void fill_reverse(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    __builtin_memset(&scratch->reverse_key, 0, sizeof(scratch->reverse_key));
    /* Replies may leave through the parent device instead of the ingress macvlan. */
    scratch->reverse_key.ifindex = 0U;
    scratch->reverse_key.family = scratch->original.family;
    scratch->reverse_key.protocol = scratch->original.protocol;
    scratch->reverse_key.client_port = scratch->original.client_port;
    scratch->reverse_key.token_port = control->bridge_port;
    copy_address(
        scratch->reverse_key.client_addr,
        scratch->original.client_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(
        scratch->reverse_key.token_addr,
        scratch->token.token_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    __builtin_memset(&scratch->reverse_value, 0, sizeof(scratch->reverse_value));
    scratch->reverse_value.original_port = scratch->original.original_port;
    copy_address(
        scratch->reverse_value.original_addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
}

NOINLINE bool sync_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u64 redirect_flags) {
    fill_redirect(scratch, control);
    fill_reverse(scratch, control);
    if (map_update(&shared_redirect, &scratch->redirect_key, &scratch->redirect_value, redirect_flags) != 0) return false;
    if (map_update(&shared_token_to_original, &scratch->reverse_key, &scratch->reverse_value, BPF_ANY) != 0) {
        if (redirect_flags == BPF_NOEXIST) map_delete(&shared_redirect, &scratch->redirect_key);
        return false;
    }
    return true;
}

NOINLINE bool reserve_token(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    struct sb_shared_token_value *existing = map_lookup(&shared_original_to_token, &scratch->original);
    if (existing != 0) {
        __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
        return sync_token(scratch, control, BPF_ANY);
    }
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < SB_SHARED_TOKEN_ATTEMPTS; ++attempt) {
        __builtin_memset(&scratch->token, 0, sizeof(scratch->token));
        __u32 hash = hash_original(&scratch->original, 0x9e3779b9U * (attempt + 1U));
        if (scratch->original.family == AF_INET_VALUE) {
            __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
                ((__u32)control->token_ipv4_prefix[1] << 16U) |
                ((__u32)control->token_ipv4_prefix[2] << 8U) |
                (__u32)control->token_ipv4_prefix[3];
            __u32 host_bits = 32U - (__u32)control->token_ipv4_prefix_bits;
            __u32 host_mask = 0xffffffffU >> (32U - host_bits);
            __u32 candidate = (prefix & ~host_mask) | (hash & host_mask);
            if ((candidate & host_mask) == 0U || (candidate & host_mask) == host_mask) continue;
            scratch->token.token_addr[0] = (__u8)(candidate >> 24U);
            scratch->token.token_addr[1] = (__u8)(candidate >> 16U);
            scratch->token.token_addr[2] = (__u8)(candidate >> 8U);
            scratch->token.token_addr[3] = (__u8)candidate;
        } else {
            copy_address(scratch->token.token_addr, control->token_ipv6_prefix, 8U);
            __u32 second = hash_original(&scratch->original, 0x85ebca6bU ^ attempt);
            scratch->token.token_addr[8] = (__u8)(hash >> 24U);
            scratch->token.token_addr[9] = (__u8)(hash >> 16U);
            scratch->token.token_addr[10] = (__u8)(hash >> 8U);
            scratch->token.token_addr[11] = (__u8)hash;
            scratch->token.token_addr[12] = (__u8)(second >> 24U);
            scratch->token.token_addr[13] = (__u8)(second >> 16U);
            scratch->token.token_addr[14] = (__u8)(second >> 8U);
            scratch->token.token_addr[15] = (__u8)second;
        }
        if (!sync_token(scratch, control, BPF_NOEXIST)) continue;
        if (map_update(&shared_original_to_token, &scratch->original, &scratch->token, BPF_ANY) == 0) return true;
        map_delete(&shared_token_to_original, &scratch->reverse_key);
        map_delete(&shared_redirect, &scratch->redirect_key);
        return false;
    }
    return false;
}

NOINLINE bool publish_socket_flow(struct sb_shared_scratch *scratch) {
    __builtin_memset(&scratch->redirect_key, 0, sizeof(scratch->redirect_key));
    scratch->redirect_key.family = scratch->original.family;
    scratch->redirect_key.protocol = scratch->original.protocol;
    scratch->redirect_key.redirect_port = scratch->original.original_port;
    scratch->redirect_key.client_port = scratch->original.client_port;
    copy_address(
        scratch->redirect_key.redirect_addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    copy_address(
        scratch->redirect_key.client_addr,
        scratch->original.client_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    __builtin_memset(&scratch->redirect_value, 0, sizeof(scratch->redirect_value));
    scratch->redirect_value.family = scratch->original.family;
    scratch->redirect_value.protocol = scratch->original.protocol;
    scratch->redirect_value.port = scratch->original.original_port;
    copy_address(
        scratch->redirect_value.addr,
        scratch->original.original_addr,
        scratch->original.family == AF_INET6_VALUE ? 16U : 4U);
    scratch->redirect_value.socket_cookie = (__u64)scratch->original.ifindex;
    return map_update(
        &shared_redirect,
        &scratch->redirect_key,
        &scratch->redirect_value,
        BPF_ANY) == 0;
}

NOINLINE bool assign_transparent_listener(
    struct __sk_buff *skb,
    __u8 family,
    __u8 protocol) {
    __u32 key;
    if (family == AF_INET_VALUE) {
        key = protocol == IPPROTO_TCP_VALUE
            ? SB_SHARED_LISTENER_TCP4
            : SB_SHARED_LISTENER_UDP4;
    } else {
        key = protocol == IPPROTO_TCP_VALUE
            ? SB_SHARED_LISTENER_TCP6
            : SB_SHARED_LISTENER_UDP6;
    }
    struct bpf_sock *sk = map_lookup(&shared_listener_sockets, &key);
    if (sk == 0) return false;
    long result = sk_assign(skb, sk, 0U);
    sk_release(sk);
    return result == 0;
}

INLINE __u64 checksum_address_flags(__u8 protocol, __u64 size) {
    __u64 flags = BPF_F_PSEUDO_HDR | size;
    if (protocol == IPPROTO_UDP_VALUE) flags |= BPF_F_MARK_MANGLED_0;
    return flags;
}

INLINE __u64 checksum_port_flags(__u8 protocol, __u64 size) {
    /* TCP/UDP ports are transport-header fields, not pseudo-header fields. */
    __u64 flags = size;
    if (protocol == IPPROTO_UDP_VALUE) flags |= BPF_F_MARK_MANGLED_0;
    return flags;
}

INLINE int rewrite_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    __be32 old_address,
    __be32 new_address,
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv4_header, source)
        : __builtin_offsetof(struct ipv4_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
    __u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
        ? __builtin_offsetof(struct tcp_header_min, checksum)
        : __builtin_offsetof(struct udp_header_min, checksum));
    if (l3_csum_replace(
            skb,
            l3_offset + __builtin_offsetof(struct ipv4_header, checksum),
            old_address,
            new_address,
            4U) != 0) {
        return TC_ACT_SHOT;
    }
    if (l4_csum_replace(skb, checksum_offset, old_address, new_address, checksum_address_flags(protocol, 4U)) != 0 ||
        l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_port_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, &new_address, sizeof(new_address), 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int rewrite_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    const __u8 old_address[16],
    const __u8 new_address[16],
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
        ? __builtin_offsetof(struct tcp_header_min, checksum)
        : __builtin_offsetof(struct udp_header_min, checksum));
#pragma clang loop unroll(full)
    for (__u32 offset = 0U; offset < 16U; offset += 4U) {
        __be32 old_word;
        __be32 new_word;
        __builtin_memcpy(&old_word, old_address + offset, 4U);
        __builtin_memcpy(&new_word, new_address + offset, 4U);
        if (l4_csum_replace(
                skb,
                checksum_offset,
                old_word,
                new_word,
                checksum_address_flags(protocol, 4U)) != 0) {
            return TC_ACT_SHOT;
        }
    }
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv6_header, source)
        : __builtin_offsetof(struct ipv6_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
    if (l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_port_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, new_address, 16U, 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE bool ipv4_token_address(__be32 address, const struct sb_shared_control *control) {
    __u32 host = swap32(address);
    __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
        ((__u32)control->token_ipv4_prefix[1] << 16U) |
        ((__u32)control->token_ipv4_prefix[2] << 8U) |
        (__u32)control->token_ipv4_prefix[3];
    __u32 bits = control->token_ipv4_prefix_bits;
    __u32 mask = bits == 0U ? 0U : 0xffffffffU << (32U - bits);
    return (host & mask) == (prefix & mask);
}

INLINE bool ipv6_token_address(const __u8 address[16], const struct sb_shared_control *control) {
    return equal_address(address, control->token_ipv6_prefix, 8U);
}

INLINE bool tcp_initial_syn(void *data, void *data_end, __u32 l4_offset, __u8 protocol) {
    if (protocol != IPPROTO_TCP_VALUE) return true;
    struct tcp_header_min *tcp = data + l4_offset;
    if ((void *)(tcp + 1) > data_end) return false;
    return (swap16(tcp->flags) & 0x0002U) != 0U;
}

NOINLINE int ingress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return TC_ACT_PIPE;
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_PIPE;
    if ((swap16(ip->fragment_offset) & IP_FRAGMENT_MASK) != 0U) return TC_ACT_PIPE;
    __u16 source_port = swap16(ports->source);
    __u16 destination_port = swap16(ports->destination);
    struct sb_shared_flow_key flow_key;
    fill_flow_key(&flow_key, AF_INET_VALUE, ip->protocol, source_port, destination_port,
        (const __u8 *)&ip->source, (const __u8 *)&ip->destination);
    if (direct_flow_hit(control, &flow_key)) return TC_ACT_PIPE;
    /* Drop QUIC before divert (same intent as nft "udp dport 443 drop" on tproxy). */
    if ((control->flags & SB_SHARED_FLAG_DROP_UDP_443) != 0U &&
        ip->protocol == IPPROTO_UDP_VALUE &&
        destination_port == 443U) {
        increment_stat(SB_SHARED_STAT_INGRESS_DROPS);
        return TC_ACT_SHOT;
    }
    if (!selected_protocol(ip->protocol, control)) return TC_ACT_PIPE;
    if (!proxy_ipv4(
            (const __u8 *)&ip->destination,
            ip->protocol,
            source_port,
            destination_port,
            (control->flags & SB_SHARED_FLAG_DNS_HIJACK) != 0U)) {
        increment_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_PIPE;
    }

    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_PIPE;
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET_VALUE;
    scratch->original.protocol = ip->protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    __builtin_memcpy(scratch->original.client_addr, &ip->source, 4U);
    __builtin_memcpy(scratch->original.original_addr, &ip->destination, 4U);
    if ((control->flags & SB_SHARED_FLAG_SOCKET_ASSIGN) != 0U) {
        if (!publish_socket_flow(scratch)) {
            increment_stat(SB_SHARED_STAT_FLOW_UPDATE_FAILURES);
            return TC_ACT_PIPE;
        }
		if ((ip->protocol == IPPROTO_UDP_VALUE ||
		     tcp_initial_syn(data, data_end, l3_offset + header_length, ip->protocol)) &&
            !assign_transparent_listener(skb, AF_INET_VALUE, ip->protocol)) {
            increment_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
            map_delete(&shared_redirect, &scratch->redirect_key);
            return TC_ACT_PIPE;
        }
        skb->mark = control->routing_mark;
        increment_stat(SB_SHARED_STAT_SOCKET_ASSIGNMENTS);
        increment_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
        return TC_ACT_OK;
    }
    if (!reserve_token(scratch, control)) {
        increment_stat(SB_SHARED_STAT_TOKEN_FAILURES);
        return TC_ACT_PIPE;
    }
    __be32 token_address;
    __builtin_memcpy(&token_address, scratch->token.token_addr, 4U);
    int result = rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        false,
        ip->destination,
        token_address,
        ports->destination,
        swap16(control->bridge_port),
        ip->protocol);
    if (result == TC_ACT_OK) {
        increment_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
    } else {
        increment_stat(SB_SHARED_STAT_REWRITE_FAILURES);
        increment_stat(SB_SHARED_STAT_INGRESS_DROPS);
    }
    return result;
}

NOINLINE int egress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return TC_ACT_PIPE;
    if (!ipv4_token_address(ip->source, control)) return TC_ACT_PIPE;
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end ||
        (swap16(ip->fragment_offset) & IP_FRAGMENT_MASK) != 0U ||
        !selected_protocol(ip->protocol, control)) {
        return TC_ACT_SHOT;
    }
    if (swap16(ports->source) != control->bridge_port) return TC_ACT_PIPE;

    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    __builtin_memset(&scratch->reverse_key, 0, sizeof(scratch->reverse_key));
    scratch->reverse_key.ifindex = 0U;
    scratch->reverse_key.family = AF_INET_VALUE;
    scratch->reverse_key.protocol = ip->protocol;
    scratch->reverse_key.client_port = swap16(ports->destination);
    scratch->reverse_key.token_port = control->bridge_port;
    __builtin_memcpy(scratch->reverse_key.client_addr, &ip->destination, 4U);
    __builtin_memcpy(scratch->reverse_key.token_addr, &ip->source, 4U);
    struct sb_shared_reverse_value *original = map_lookup(
        &shared_token_to_original,
        &scratch->reverse_key);
    if (original == 0) {
        increment_stat(SB_SHARED_STAT_EGRESS_REVERSE_MISSES);
        return TC_ACT_SHOT;
    }
    __be32 original_address;
    __builtin_memcpy(&original_address, original->original_addr, 4U);
    int result = rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        true,
        ip->source,
        original_address,
        ports->source,
        swap16(original->original_port),
        ip->protocol);
    if (result == TC_ACT_OK) {
        increment_stat(SB_SHARED_STAT_EGRESS_RESTORES);
    } else {
        increment_stat(SB_SHARED_STAT_REWRITE_FAILURES);
    }
    return result;
}

NOINLINE int ipv6_transport_offset(
    void *data,
    void *data_end,
    __u32 l3_offset,
    __u8 *protocol_out) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end) return -1;
    __u8 protocol = ip->next_header;
    __u32 offset = l3_offset + sizeof(*ip);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) {
            *protocol_out = protocol;
            return (int)offset;
        }
        if (protocol == 44U ||
            (protocol != 0U && protocol != 43U && protocol != 60U && protocol != 51U)) {
            return -1;
        }
        struct ipv6_extension_header *extension = data + offset;
        if ((void *)(extension + 1) > data_end) return -1;
        __u8 current = protocol;
        protocol = extension->next_header;
        offset += current == 51U
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (data + offset > data_end) return -1;
    }
    return -1;
}

NOINLINE int ingress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_PIPE;
    __u8 protocol = 0U;
    int transport = ipv6_transport_offset(data, data_end, l3_offset, &protocol);
    if (transport < 0) return TC_ACT_PIPE;
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_PIPE;
    __u16 source_port = swap16(ports->source);
    __u16 destination_port = swap16(ports->destination);
    struct sb_shared_flow_key flow_key;
    fill_flow_key(&flow_key, AF_INET6_VALUE, protocol, source_port, destination_port,
        ip->source, ip->destination);
    if (direct_flow_hit(control, &flow_key)) return TC_ACT_PIPE;
    if ((control->flags & SB_SHARED_FLAG_DROP_UDP_443) != 0U &&
        protocol == IPPROTO_UDP_VALUE &&
        destination_port == 443U) {
        increment_stat(SB_SHARED_STAT_INGRESS_DROPS);
        return TC_ACT_SHOT;
    }
    if (!selected_protocol(protocol, control)) return TC_ACT_PIPE;
    if (!proxy_ipv6(
            ip->destination,
            protocol,
            source_port,
            destination_port,
            (control->flags & SB_SHARED_FLAG_DNS_HIJACK) != 0U)) {
        increment_stat(SB_SHARED_STAT_INGRESS_BYPASS);
        return TC_ACT_PIPE;
    }

    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_PIPE;
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET6_VALUE;
    scratch->original.protocol = protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    copy_address(scratch->original.client_addr, ip->source, 16U);
    copy_address(scratch->original.original_addr, ip->destination, 16U);
    if ((control->flags & SB_SHARED_FLAG_SOCKET_ASSIGN) != 0U) {
        if (!publish_socket_flow(scratch)) {
            increment_stat(SB_SHARED_STAT_FLOW_UPDATE_FAILURES);
            return TC_ACT_PIPE;
        }
		if ((protocol == IPPROTO_UDP_VALUE ||
		     tcp_initial_syn(data, data_end, (__u32)transport, protocol)) &&
            !assign_transparent_listener(skb, AF_INET6_VALUE, protocol)) {
            increment_stat(SB_SHARED_STAT_SOCKET_ASSIGN_FAILURES);
            map_delete(&shared_redirect, &scratch->redirect_key);
            return TC_ACT_PIPE;
        }
        skb->mark = control->routing_mark;
        increment_stat(SB_SHARED_STAT_SOCKET_ASSIGNMENTS);
        increment_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
        return TC_ACT_OK;
    }
    if (!reserve_token(scratch, control)) {
        increment_stat(SB_SHARED_STAT_TOKEN_FAILURES);
        return TC_ACT_PIPE;
    }
    int result = rewrite_ipv6(
        skb,
        l3_offset,
        (__u32)transport,
        false,
        scratch->redirect_value.addr,
        scratch->redirect_key.redirect_addr,
        ports->destination,
        swap16(control->bridge_port),
        protocol);
    if (result == TC_ACT_OK) {
        increment_stat(SB_SHARED_STAT_INGRESS_REDIRECTS);
    } else {
        increment_stat(SB_SHARED_STAT_REWRITE_FAILURES);
        increment_stat(SB_SHARED_STAT_INGRESS_DROPS);
    }
    return result;
}

NOINLINE int egress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (swap32(ip->version_flow) >> 28U) != 6U) return TC_ACT_PIPE;
    if (!ipv6_token_address(ip->source, control)) return TC_ACT_PIPE;
    __u8 protocol = 0U;
    int transport = ipv6_transport_offset(data, data_end, l3_offset, &protocol);
    if (transport < 0 || !selected_protocol(protocol, control)) return TC_ACT_SHOT;
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    if (swap16(ports->source) != control->bridge_port) return TC_ACT_PIPE;

    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    __builtin_memset(&scratch->reverse_key, 0, sizeof(scratch->reverse_key));
    scratch->reverse_key.ifindex = 0U;
    scratch->reverse_key.family = AF_INET6_VALUE;
    scratch->reverse_key.protocol = protocol;
    scratch->reverse_key.client_port = swap16(ports->destination);
    scratch->reverse_key.token_port = control->bridge_port;
    copy_address(scratch->reverse_key.client_addr, ip->destination, 16U);
    copy_address(scratch->reverse_key.token_addr, ip->source, 16U);
    struct sb_shared_reverse_value *original = map_lookup(
        &shared_token_to_original,
        &scratch->reverse_key);
    if (original == 0) {
        increment_stat(SB_SHARED_STAT_EGRESS_REVERSE_MISSES);
        return TC_ACT_SHOT;
    }
    __builtin_memcpy(&scratch->reverse_value, original, sizeof(scratch->reverse_value));
    int result = rewrite_ipv6(
        skb,
        l3_offset,
        (__u32)transport,
        true,
        scratch->reverse_key.token_addr,
        scratch->reverse_value.original_addr,
        ports->source,
        swap16(scratch->reverse_value.original_port),
        protocol);
    if (result == TC_ACT_OK) {
        increment_stat(SB_SHARED_STAT_EGRESS_RESTORES);
    } else {
        increment_stat(SB_SHARED_STAT_REWRITE_FAILURES);
    }
    return result;
}

NOINLINE int classify(struct __sk_buff *skb, bool ingress) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return TC_ACT_PIPE;
    if (!ingress && (control->flags & SB_SHARED_FLAG_SOCKET_ASSIGN) != 0U) return TC_ACT_PIPE;
    if (skb_pull_data(skb, 0U) != 0) return TC_ACT_PIPE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return TC_ACT_PIPE;
    if (ingress && !ingress_destination_matches_interface(skb, ethernet)) return TC_ACT_PIPE;
    __u16 protocol = swap16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return TC_ACT_PIPE;
        protocol = swap16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
        return ingress
            ? ingress_ipv4(skb, l3_offset, control)
            : egress_ipv4(skb, l3_offset, control);
    }
    if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
        return ingress
            ? ingress_ipv6(skb, l3_offset, control)
            : egress_ipv6(skb, l3_offset, control);
    }
    return TC_ACT_PIPE;
}

SEC("classifier/ingress")
int singbox_shared_ingress(struct __sk_buff *skb) {
    return classify(skb, true);
}

SEC("classifier/egress")
int singbox_shared_egress(struct __sk_buff *skb) {
    return classify(skb, false);
}

char _license[] SEC("license") = "GPL";
