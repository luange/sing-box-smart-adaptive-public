// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "singbox_ebpf.h"
#include "shared_network.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

static void shared_network_init(struct sb_ebpf_shared_network_runtime *runtime) {
    memset(runtime, 0xff, sizeof(*runtime));
}

static int shared_network_close_fd(int *fd) {
    if (fd == NULL || *fd < 0) return 0;
    int value = *fd;
    *fd = -1;
    return close(value);
}

static int shared_network_create_lpm4(void) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv4_cidr_lpm_key),
        sizeof(uint8_t),
        256U,
        BPF_F_NO_PREALLOC);
}

static int shared_network_create_lpm6(void) {
    return sb_ebpf_create_map(
        BPF_MAP_TYPE_LPM_TRIE,
        sizeof(struct sb_ebpf_ipv6_cidr_lpm_key),
        sizeof(uint8_t),
        256U,
        BPF_F_NO_PREALLOC);
}

int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    int dns_direct_ipv4_map_fd,
    int dns_direct_ipv6_map_fd,
    bool data_plane_v2,
    struct sb_ebpf_shared_network_runtime *runtime) {
    if (object == NULL || object_size == 0U || runtime == NULL) {
        errno = EINVAL;
        return -1;
    }
    shared_network_init(runtime);
    const char *stage = "create control map";
    runtime->control_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(struct sb_shared_control),
        1U,
        0U);
    stage = "create interface MAC map";
    runtime->interface_mac_map_fd = sb_ebpf_create_map(
            BPF_MAP_TYPE_HASH,
            data_plane_v2 ? sizeof(struct sb_shared_interface_mac) : sizeof(uint32_t),
            data_plane_v2 ? sizeof(uint32_t) : sizeof(struct sb_shared_interface_mac),
            SB_SHARED_NETWORK_INTERFACE_ENTRIES,
            0U);
    if (!data_plane_v2) {
        stage = "create original-to-token map";
        runtime->original_to_token_map_fd = sb_ebpf_create_map(
            BPF_MAP_TYPE_LRU_HASH,
            sizeof(struct sb_shared_original_key),
            sizeof(struct sb_shared_token_value),
            SB_SHARED_NETWORK_MAP_ENTRIES,
            0U);
        stage = "create token-to-original map";
        runtime->token_to_original_map_fd = sb_ebpf_create_map(
            BPF_MAP_TYPE_LRU_HASH,
            sizeof(struct sb_shared_reverse_key),
            sizeof(struct sb_shared_reverse_value),
            SB_SHARED_NETWORK_MAP_ENTRIES,
            0U);
    }
    stage = "create redirect map";
    runtime->redirect_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_redirect_key),
        sizeof(struct sb_shared_original_dst),
        SB_SHARED_NETWORK_MAP_ENTRIES,
        0U);
    stage = "create direct flow verdict map";
    runtime->flow_direct_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_LRU_HASH,
        sizeof(struct sb_shared_flow_key),
        sizeof(struct sb_shared_flow_value),
        SB_SHARED_NETWORK_MAP_ENTRIES,
        0U);
    stage = "create listener socket map";
    runtime->listener_socket_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_SOCKMAP,
        sizeof(uint32_t),
        sizeof(uint64_t),
        SB_SHARED_LISTENER_COUNT,
        0U);
    stage = "create stats map";
    runtime->stats_map_fd = sb_ebpf_create_map(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(uint64_t),
        SB_SHARED_STAT_COUNT,
        0U);
    stage = "create host maps";
    runtime->host_ipv4_map_fd = shared_network_create_lpm4();
    runtime->host_ipv6_map_fd = shared_network_create_lpm6();
    if (!data_plane_v2) {
        stage = "create scratch map";
        runtime->scratch_map_fd = sb_ebpf_create_map(
            BPF_MAP_TYPE_PERCPU_ARRAY,
            sizeof(uint32_t),
            sizeof(struct sb_shared_scratch),
            1U,
            0U);
    }
    if (runtime->control_map_fd < 0 ||
        runtime->interface_mac_map_fd < 0 ||
        (!data_plane_v2 && runtime->original_to_token_map_fd < 0) ||
        (!data_plane_v2 && runtime->token_to_original_map_fd < 0) ||
        runtime->redirect_map_fd < 0 ||
        runtime->flow_direct_map_fd < 0 ||
        runtime->listener_socket_map_fd < 0 ||
        runtime->stats_map_fd < 0 ||
        runtime->host_ipv4_map_fd < 0 ||
        runtime->host_ipv6_map_fd < 0 ||
        (!data_plane_v2 && runtime->scratch_map_fd < 0)) {
        goto fail;
    }
    if (bypass_ipv4_map_fd < 0) {
        stage = "create fallback IPv4 bypass map";
        runtime->fallback_bypass_ipv4_map_fd = shared_network_create_lpm4();
        if (runtime->fallback_bypass_ipv4_map_fd < 0) goto fail;
        bypass_ipv4_map_fd = runtime->fallback_bypass_ipv4_map_fd;
    }
    if (bypass_ipv6_map_fd < 0) {
        stage = "create fallback IPv6 bypass map";
        runtime->fallback_bypass_ipv6_map_fd = shared_network_create_lpm6();
        if (runtime->fallback_bypass_ipv6_map_fd < 0) goto fail;
        bypass_ipv6_map_fd = runtime->fallback_bypass_ipv6_map_fd;
    }
    if (dns_direct_ipv4_map_fd < 0) {
        stage = "create fallback IPv4 dns_direct map";
        runtime->fallback_dns_direct_ipv4_map_fd = shared_network_create_lpm4();
        if (runtime->fallback_dns_direct_ipv4_map_fd < 0) goto fail;
        dns_direct_ipv4_map_fd = runtime->fallback_dns_direct_ipv4_map_fd;
    }
    if (dns_direct_ipv6_map_fd < 0) {
        stage = "create fallback IPv6 dns_direct map";
        runtime->fallback_dns_direct_ipv6_map_fd = shared_network_create_lpm6();
        if (runtime->fallback_dns_direct_ipv6_map_fd < 0) goto fail;
        dns_direct_ipv6_map_fd = runtime->fallback_dns_direct_ipv6_map_fd;
    }
    stage = "load shared-network programs";
    if (sb_ebpf_load_shared_network_programs(
            object,
            object_size,
            bypass_ipv4_map_fd,
            bypass_ipv6_map_fd,
            dns_direct_ipv4_map_fd,
            dns_direct_ipv6_map_fd,
            data_plane_v2,
            runtime) != 0) {
        goto fail;
    }
    return 0;

fail: {
        int saved_errno = errno;
        fprintf(stderr, "shared-network stage '%s' failed: errno=%d\n", stage, saved_errno);
        (void)sb_ebpf_shared_network_close(runtime);
        errno = saved_errno;
        return -1;
    }
}

int sb_ebpf_shared_network_close(struct sb_ebpf_shared_network_runtime *runtime) {
    if (runtime == NULL) return 0;
    int result = 0;
#define CLOSE_SHARED_FD(FD) \
    do { \
        if (shared_network_close_fd(&(FD)) != 0 && result == 0) result = -1; \
    } while (0)
    CLOSE_SHARED_FD(runtime->egress_prog_fd);
    CLOSE_SHARED_FD(runtime->ingress_prog_fd);
    CLOSE_SHARED_FD(runtime->scratch_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_dns_direct_ipv6_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_dns_direct_ipv4_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_bypass_ipv6_map_fd);
    CLOSE_SHARED_FD(runtime->fallback_bypass_ipv4_map_fd);
    CLOSE_SHARED_FD(runtime->host_ipv6_map_fd);
    CLOSE_SHARED_FD(runtime->host_ipv4_map_fd);
    CLOSE_SHARED_FD(runtime->redirect_map_fd);
    CLOSE_SHARED_FD(runtime->flow_direct_map_fd);
    CLOSE_SHARED_FD(runtime->listener_socket_map_fd);
    CLOSE_SHARED_FD(runtime->stats_map_fd);
    CLOSE_SHARED_FD(runtime->token_to_original_map_fd);
    CLOSE_SHARED_FD(runtime->original_to_token_map_fd);
    CLOSE_SHARED_FD(runtime->interface_mac_map_fd);
    CLOSE_SHARED_FD(runtime->control_map_fd);
#undef CLOSE_SHARED_FD
    return result;
}

/* ── Token-mode flow purge (v1 data_plane="token") ────────────────────────
 * Userspace closes a UDP flow and deletes the shared_redirect row, but the
 * token-mode ingress also wrote shared_original_to_token and
 * shared_token_to_original rows. Leaving them behind let a reply to a stale
 * token address rewrite to a dead original until LRU pressure, and let a
 * reused client tuple inherit stale token state. This helper walks the
 * original_to_token map, deletes every row matching the flow tuple on the
 * identity fields (any ingress ifindex), and removes the paired reverse row
 * (reverse rows are always published with ifindex 0). */
#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#elif defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#endif
#endif

static int shared_network_map_next_key(int map_fd, const void *key, void *next_key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.next_key = (uint64_t)(uintptr_t)next_key;
    return (int)syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int shared_network_map_delete_entry(int map_fd, const void *key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    return (int)syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int shared_network_map_lookup_entry(int map_fd, const void *key, void *value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    return (int)syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int sb_ebpf_shared_network_purge_token_flow(
    struct sb_ebpf_shared_network_runtime *runtime,
    const struct sb_shared_original_key *match) {
    if (runtime == NULL || match == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (runtime->original_to_token_map_fd < 0 || runtime->token_to_original_map_fd < 0) {
        /* socket_assign data plane never publishes token rows. */
        return 0;
    }
    struct sb_shared_control control;
    memset(&control, 0, sizeof(control));
    __u32 control_key = 0;
    if (runtime->control_map_fd >= 0) {
        (void)shared_network_map_lookup_entry(runtime->control_map_fd, &control_key, &control);
    }

    struct sb_shared_original_key key;
    struct sb_shared_original_key next;
    int result = 0;
    memset(&key, 0, sizeof(key));
    for (;;) {
        if (shared_network_map_next_key(runtime->original_to_token_map_fd,
                                        key.ifindex == 0 && key.family == 0 ? NULL : (const void *)&key,
                                        &next) != 0)
            break;
        key = next;
        if (key.family != match->family || key.protocol != match->protocol ||
            key.client_port != match->client_port || key.original_port != match->original_port ||
            memcmp(key.client_addr, match->client_addr, sizeof(key.client_addr)) != 0 ||
            memcmp(key.original_addr, match->original_addr, sizeof(key.original_addr)) != 0)
            continue;
        struct sb_shared_token_value token;
        memset(&token, 0, sizeof(token));
        if (shared_network_map_lookup_entry(runtime->original_to_token_map_fd, &key, &token) != 0)
            continue;
        struct sb_shared_reverse_key reverse;
        memset(&reverse, 0, sizeof(reverse));
        reverse.ifindex = 0U;
        reverse.family = key.family;
        reverse.protocol = key.protocol;
        reverse.client_port = key.client_port;
        reverse.token_port = control.bridge_port;
        reverse.reserved = 0;
        memcpy(reverse.client_addr, key.client_addr, sizeof(reverse.client_addr));
        memcpy(reverse.token_addr, token.token_addr, sizeof(reverse.token_addr));
        if (shared_network_map_delete_entry(runtime->token_to_original_map_fd, &reverse) != 0 &&
            errno != ENOENT && result == 0)
            result = -1;
        if (shared_network_map_delete_entry(runtime->original_to_token_map_fd, &key) != 0 &&
            errno != ENOENT && result == 0)
            result = -1;
    }
    return result;
}
