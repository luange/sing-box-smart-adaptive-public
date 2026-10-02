// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef SING_BOX_EBPF_H
#define SING_BOX_EBPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Shared-network ABI types (sb_shared_original_key et al.) live here; the
 * runtime struct below embeds them, so the full definitions must be visible
 * to every cgo translation unit that includes this header. */
#include "shared_network.h" 

#define SB_EBPF_DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define SB_EBPF_MAX_TCP_REDIRECT_MAP_ENTRIES 16384U
#define SB_EBPF_MAX_UDP_REDIRECT_MAP_ENTRIES 16384U
#define SB_EBPF_MAX_UDP_PEER_MAP_ENTRIES 16384U
#define SB_EBPF_MAX_POLICY_MAP_ENTRIES 4096U
#define SB_EBPF_MAX_BYPASS_CIDR_MAP_ENTRIES 16384U
#define SB_EBPF_STATS_COUNT 6U
#define SB_EBPF_ORIGINAL_DST_FLAG_CONNECTED_UDP 1U

#define SB_EBPF_PROTO_TCP 6U
#define SB_EBPF_PROTO_UDP 17U
#define SB_EBPF_NETWORK_TCP 1U
#define SB_EBPF_NETWORK_UDP 2U
#define SB_EBPF_NETWORK_BOTH (SB_EBPF_NETWORK_TCP | SB_EBPF_NETWORK_UDP)

enum sb_ebpf_stat_index {
    SB_EBPF_STAT_TCP_REDIRECT_ENTRIES = 0,
    SB_EBPF_STAT_UDP_REDIRECT_ENTRIES = 1,
    SB_EBPF_STAT_UDP_REDIRECT_DELETES = 2,
    SB_EBPF_STAT_TOKEN_COLLISIONS = 3,
    SB_EBPF_STAT_MAP_UPDATE_FAILURES = 4,
    SB_EBPF_STAT_REDIRECT_DROPS = 5,
};

struct sb_ebpf_redirect_key {
    uint8_t family;
    uint8_t protocol;
    uint16_t redirect_port;
    uint8_t redirect_addr[16];
};

struct sb_ebpf_original_dst {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
    uint8_t flags;
    uint8_t reserved[3];
    uint64_t socket_cookie;
    uint32_t uid;
    uint32_t reserved_tail;
};

struct sb_ebpf_udp_peer_key {
    uint64_t cookie;
};

struct sb_ebpf_udp_peer_value {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
};

_Static_assert(sizeof(struct sb_ebpf_redirect_key) == 20U, "unexpected redirect key ABI");
_Static_assert(sizeof(struct sb_ebpf_original_dst) == 40U, "unexpected original destination ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, socket_cookie) == 24U, "unexpected socket cookie ABI");
_Static_assert(offsetof(struct sb_ebpf_original_dst, uid) == 32U, "unexpected UID ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_key) == 8U, "unexpected UDP peer key ABI");
_Static_assert(sizeof(struct sb_ebpf_udp_peer_value) == 20U, "unexpected UDP peer value ABI");

struct sb_ebpf_uid_lpm_key {
    uint32_t prefixlen;
    uint8_t uid[4];
};

struct sb_ebpf_ipv4_cidr_lpm_key {
    uint32_t prefixlen;
    uint8_t addr[4];
};

struct sb_ebpf_ipv6_cidr_lpm_key {
    uint32_t prefixlen;
    uint8_t addr[16];
};

struct sb_ebpf_inbound_config {
    uint8_t inbound_network;
    bool disable_ipv4;
    bool hijack_dns;
    int stats_map_fd;
    /* dns_kernel_direct LPM fds (-1 when unused); checked on :53 before hijack. */
    int dns_direct_ipv4_map_fd;
    int dns_direct_ipv6_map_fd;
    uint8_t redirect_ipv4_prefix[4];
    uint32_t redirect_ipv4_prefix_bits;
    uint8_t redirect_ipv6_prefix[16];
    uint32_t redirect_ipv6_prefix_bits;
};

struct sb_ebpf_inbound_runtime {
    int cgroup_fd;
    int tcp_redirect_map_fd;
    int udp_redirect_map_fd;
    int udp_token_map_fd;
    int stats_map_fd;
    int udp_peer_map_fd;
    int bypass_socket_cookie_map_fd;
    int include_uid_map_fd;
    int exclude_uid_map_fd;
    int bypass_ipv4_cidr_map_fd;
    int bypass_ipv6_cidr_map_fd;
    /* dns_kernel_direct: :53 exceptions (owned by inbound, shared with TC). */
    int dns_direct_ipv4_cidr_map_fd;
    int dns_direct_ipv6_cidr_map_fd;
    /* Module A: flow verdict offload maps (owned by inbound runtime). */
    int out_verdict_map_fd;
    int out_verdict_control_map_fd;
    int out_verdict_stats_map_fd; /* ARRAY u64 × SB_OUT_VERDICT_STAT_COUNT */
    /* Module C: self-listen port registry (host-order u16 → u8). */
    int self_listen_port_map_fd;
    int connect4_prog_fd;
    int connect6_prog_fd;
    int connect6_v4mapped_prog_fd;
    int udp4_sendmsg_prog_fd;
    int udp6_sendmsg_prog_fd;
    int udp6_v4mapped_sendmsg_prog_fd;
    int udp4_recvmsg_prog_fd;
    int udp6_recvmsg_prog_fd;
    int udp6_v4mapped_recvmsg_prog_fd;
    int socket_release_prog_fd;
    uint32_t attached_programs;
};

struct sb_ebpf_shared_network_runtime {
    int control_map_fd;
    int interface_mac_map_fd;
    int original_to_token_map_fd;
    int token_to_original_map_fd;
    int redirect_map_fd;
    int flow_direct_map_fd;
    int listener_socket_map_fd;
    int stats_map_fd;
    int host_ipv4_map_fd;
    int host_ipv6_map_fd;
    int fallback_bypass_ipv4_map_fd;
    int fallback_bypass_ipv6_map_fd;
    int fallback_dns_direct_ipv4_map_fd;
    int fallback_dns_direct_ipv6_map_fd;
    int scratch_map_fd;
    int ingress_prog_fd;
    int egress_prog_fd;
};

int sb_ebpf_inbound_prepare(
    const char *cgroup_path,
    bool capture_local,
    uint16_t listen_port,
    bool enable_tcp,
    bool enable_udp,
    bool enable_ipv4,
    bool enable_bypass_cidr,
    bool hijack_dns,
    bool enable_flow_verdict,
    uint32_t flow_verdict_max_entries, /* 0 → SB_OUT_VERDICT_MAX_ENTRIES */
    const uint8_t redirect_ipv4[4],
    uint32_t redirect_ipv4_prefix_bits,
    bool enable_ipv6,
    const uint8_t redirect_ipv6[16],
    uint32_t redirect_ipv6_prefix_bits,
    uint32_t include_uid_entries,
    uint32_t exclude_uid_entries,
    struct sb_ebpf_inbound_runtime *runtime);
int sb_ebpf_inbound_attach(struct sb_ebpf_inbound_runtime *runtime);
int sb_ebpf_inbound_close(struct sb_ebpf_inbound_runtime *runtime);

int sb_ebpf_load_shared_network_programs(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    int dns_direct_ipv4_map_fd,
    int dns_direct_ipv6_map_fd,
    bool data_plane_v2,
    struct sb_ebpf_shared_network_runtime *runtime);
int sb_ebpf_shared_network_prepare(
    const uint8_t *object,
    size_t object_size,
    int bypass_ipv4_map_fd,
    int bypass_ipv6_map_fd,
    int dns_direct_ipv4_map_fd,
    int dns_direct_ipv6_map_fd,
    bool data_plane_v2,
    struct sb_ebpf_shared_network_runtime *runtime);
int sb_ebpf_shared_network_close(struct sb_ebpf_shared_network_runtime *runtime);
/* Delete the token-mode forward/reverse rows for one flow tuple (any ingress
 * ifindex). No-op on the socket_assign data plane. */
struct sb_shared_original_key; /* defined in shared_network.h */
int sb_ebpf_shared_network_purge_token_flow(
    struct sb_ebpf_shared_network_runtime *runtime,
    const struct sb_shared_original_key *match);

/* eBPF shared-network engine=v3 runtime (independent maps/programs). */
struct sb_ebpf_v3_runtime {
	int control_map_fd;
	int policy4_bank0_fd;
	int policy4_bank1_fd;
	int policy6_bank0_fd;
	int policy6_bank1_fd;
	int dynamic_direct4_fd;
	int dynamic_direct6_fd;
	int host4_map_fd;
	int host6_map_fd;
	int flow_map_fd;
	int dns_hint_map_fd;
	int dns_observe_map_fd;
	int dns_scratch_map_fd;
	int source_mac_map_fd;
	int redirect_map_fd;
	int listener_map_fd;
	int stats_map_fd;
	int ingress_prog_fd;
	int egress_prog_fd;
};

int sb_ebpf_v3_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t policy_lpm_entries,
	uint32_t flow_entries,
	uint32_t dns_hint_entries,
	struct sb_ebpf_v3_runtime *runtime);
int sb_ebpf_v3_close(struct sb_ebpf_v3_runtime *runtime);

/* Optional AF_XDP DIRECT accelerator.  It shares the v3 policy-map FDs but
 * has its own control and XSK map.  Preparing the object never enables it;
 * callers must attach, bind every queue, and then publish control. */
struct sb_ebpf_xdp_runtime {
	int control_map_fd;
	int xsk_map_fd;
	int program_fd;
	int link_fd;
	uint32_t ifindex;
	uint32_t queue_count;
	uint32_t mode;
	uint64_t xsk_bound_mask;
};

enum sb_ebpf_xdp_mode {
	SB_EBPF_XDP_MODE_SKB = 1,
	SB_EBPF_XDP_MODE_NATIVE = 2,
	SB_EBPF_XDP_MODE_OFFLOAD = 3,
};

int sb_ebpf_xdp_prepare(
	const uint8_t *object,
	size_t object_size,
	const struct sb_ebpf_v3_runtime *v3,
	uint32_t max_queues,
	struct sb_ebpf_xdp_runtime *runtime);
int sb_ebpf_xdp_attach(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex);
int sb_ebpf_xdp_attach_mode(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex, uint32_t mode);
/* Probe the real verifier/attach path and immediately detach.  This never
 * enables the data plane and returns failure for an occupied or unsupported
 * mode so the caller can keep TC active. */
int sb_ebpf_xdp_probe_mode(struct sb_ebpf_xdp_runtime *runtime, uint32_t ifindex, uint32_t mode);
/* Hardware capability probe: loads a pass-everything XDP program and briefly
 * attaches it in native/skb mode. Never routes sing-box traffic. Returns 0 on
 * successful probe; native_ok/skb_ok report per-mode support. */
int sb_ebpf_xdp_probe_hardware(uint32_t ifindex, int *native_ok, int *skb_ok);
int sb_ebpf_xdp_detach(struct sb_ebpf_xdp_runtime *runtime);
int sb_ebpf_xdp_set_control(
	struct sb_ebpf_xdp_runtime *runtime,
	bool enabled,
	uint32_t policy_generation,
	uint32_t active_bank,
	uint32_t queue_count,
	uint32_t max_frame_size,
	bool allow_multibuffer,
	uint64_t attached_since_ns);
int sb_ebpf_xdp_set_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue, int xsk_fd);
int sb_ebpf_xdp_clear_xsk(struct sb_ebpf_xdp_runtime *runtime, uint32_t queue);
int sb_ebpf_xdp_close(struct sb_ebpf_xdp_runtime *runtime);

int sb_ebpf_create_map(
    enum bpf_map_type type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t flags);
int sb_ebpf_load_prog(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    bool log_error);
/* target_fd is a cgroup fd for cgroup programs, or a map fd for sockmap/sk_skb. */
int sb_ebpf_attach_prog(int target_fd, int prog_fd, enum bpf_attach_type attach_type);
int sb_ebpf_detach_prog(int target_fd, int prog_fd, enum bpf_attach_type attach_type);
int sb_ebpf_detach_owned_progs(int cgroup_fd);

/* Generic ELF BPF object loader (parameterized prog type + map fd table). */
struct sb_ebpf_object_map_entry {
	const char *name;
	int fd;
};

struct sb_ebpf_object_map_table {
	const struct sb_ebpf_object_map_entry *entries;
	size_t count;
};

int sb_ebpf_object_load_section(
	const uint8_t *object,
	size_t object_size,
	const char *section_name,
	const char *program_name,
	enum bpf_prog_type prog_type,
	enum bpf_attach_type expected_attach_type,
	const struct sb_ebpf_object_map_table *maps);

#endif
