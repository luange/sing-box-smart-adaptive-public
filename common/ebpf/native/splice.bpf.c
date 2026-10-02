// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Module B: SK_SKB stream parser + verdict for sockhash redirect (egress, flags=0).
// Contract: docs/ebpf-in-out-framework-master-20260803.md §6.1 — sk_skb not sk_msg.

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline))

#define SB_SPLICE_MAX_ENTRIES 8192U

enum sb_splice_stat_index {
	/* 0/1 reserved: pair created/released are maintained in Go atomics only.
	 * Kernel never increments these slots (E8). */
	SB_SPLICE_STAT_PAIRS_CREATED = 0,
	SB_SPLICE_STAT_PAIRS_RELEASED,
	SB_SPLICE_STAT_REDIRECTS,
	SB_SPLICE_STAT_REDIRECT_FAILURES,
	SB_SPLICE_STAT_PEER_MISSES,
	SB_SPLICE_STAT_PASSTHROUGH,
	SB_SPLICE_STAT_COUNT,
};

#define SB_SPLICE_CTRL_FLAG_ACCOUNTING (1U << 0)

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef SK_PASS
#define SK_PASS 1
#endif

/* Host endianness: kernel convert_ctx_access only LSH 16 remote_port on LE. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "splice.bpf.c assumes little-endian (remote_port high-half quirk)"
#endif

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct sb_splice_key {
	__u8 family;
	__u8 protocol;
	__u16 local_port;
	__u16 remote_port;
	__u16 reserved;
	__u8 local_addr[16];
	__u8 remote_addr[16];
};

struct sb_splice_control {
	__u32 enabled;
	__u32 flags;
};

struct bpf_map_def SEC("maps") sb_splice_socks = {
	.type = BPF_MAP_TYPE_SOCKHASH,
	.key_size = sizeof(struct sb_splice_key),
	.value_size = sizeof(__u64),
	.max_entries = SB_SPLICE_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") sb_splice_peer = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct sb_splice_key),
	.value_size = sizeof(struct sb_splice_key),
	.max_entries = SB_SPLICE_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") sb_splice_bytes = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct sb_splice_key),
	.value_size = sizeof(__u64),
	.max_entries = SB_SPLICE_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") sb_splice_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = SB_SPLICE_STAT_COUNT,
};

struct bpf_map_def SEC("maps") sb_splice_control = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct sb_splice_control),
	.max_entries = 1U,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*sk_redirect_hash)(struct __sk_buff *skb, void *map, void *key, __u64 flags) =
	(void *)BPF_FUNC_sk_redirect_hash;

INLINE void splice_inc_stat(__u32 index) {
	__u64 *value = map_lookup(&sb_splice_stats, &index);
	if (value != 0) {
		__sync_fetch_and_add(value, 1U);
	}
}

/*
 * Build key from SK_SKB ctx. Only access fields with their native width.
 * remote_port: u32, network order in high 16 bits (kernel selftests convention, LE).
 *
 * W2 IPv6: verifier only accepts constant-index whole-word access to
 * local_ip6/remote_ip6. Do NOT memcpy 16B from ctx, do NOT mix ip4+ip6 in one
 * branch, and do NOT put ctx reads inside a loop. Stack-only zeroing loop is OK.
 */
INLINE int fill_splice_key(struct __sk_buff *skb, struct sb_splice_key *key) {
	__u32 family = skb->family;
	__u32 local_port = skb->local_port;
	__u32 remote_port = skb->remote_port;

	key->protocol = IPPROTO_TCP;
	key->local_port = (__u16)local_port;
	/* remote_port high half is already network-order port; store host order */
	key->remote_port = (__u16)(remote_port >> 16);
	key->remote_port = __builtin_bswap16(key->remote_port);
	key->reserved = 0;

	if (family == AF_INET) {
		__u32 local_ip4 = skb->local_ip4;
		__u32 remote_ip4 = skb->remote_ip4;

		key->family = AF_INET;
		__builtin_memcpy(&key->local_addr[0], &local_ip4, 4);
		__builtin_memcpy(&key->remote_addr[0], &remote_ip4, 4);
#pragma clang loop unroll(full)
		for (int i = 4; i < 16; i++) {
			key->local_addr[i] = 0;
			key->remote_addr[i] = 0;
		}
		return 0;
	}

	if (family == AF_INET6) {
		/* Four independent scalar-index loads — no 16B ctx memcpy (EACCES root cause). */
		__u32 l0 = skb->local_ip6[0];
		__u32 l1 = skb->local_ip6[1];
		__u32 l2 = skb->local_ip6[2];
		__u32 l3 = skb->local_ip6[3];
		__u32 r0 = skb->remote_ip6[0];
		__u32 r1 = skb->remote_ip6[1];
		__u32 r2 = skb->remote_ip6[2];
		__u32 r3 = skb->remote_ip6[3];

		key->family = AF_INET6;
		__builtin_memcpy(&key->local_addr[0], &l0, 4);
		__builtin_memcpy(&key->local_addr[4], &l1, 4);
		__builtin_memcpy(&key->local_addr[8], &l2, 4);
		__builtin_memcpy(&key->local_addr[12], &l3, 4);
		__builtin_memcpy(&key->remote_addr[0], &r0, 4);
		__builtin_memcpy(&key->remote_addr[4], &r1, 4);
		__builtin_memcpy(&key->remote_addr[8], &r2, 4);
		__builtin_memcpy(&key->remote_addr[12], &r3, 4);
		return 0;
	}

	return -1;
}

SEC("sk_skb/stream_parser")
int sb_splice_parser(struct __sk_buff *skb) {
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int sb_splice_verdict(struct __sk_buff *skb) {
	__u32 zero = 0;
	struct sb_splice_control *ctrl = map_lookup(&sb_splice_control, &zero);
	if (ctrl == 0 || ctrl->enabled == 0) {
		splice_inc_stat(SB_SPLICE_STAT_PASSTHROUGH);
		return SK_PASS;
	}

	/* Stack key must be written field-by-field for verifier. */
	struct sb_splice_key self = {};
	if (fill_splice_key(skb, &self) != 0) {
		/* unsupported family: pass to userspace path */
		splice_inc_stat(SB_SPLICE_STAT_PASSTHROUGH);
		return SK_PASS;
	}

	struct sb_splice_key *peer = map_lookup(&sb_splice_peer, &self);
	if (peer == 0) {
		splice_inc_stat(SB_SPLICE_STAT_PEER_MISSES);
		return SK_PASS;
	}

	if ((ctrl->flags & SB_SPLICE_CTRL_FLAG_ACCOUNTING) != 0) {
		__u64 *bytes = map_lookup(&sb_splice_bytes, &self);
		if (bytes != 0) {
			__sync_fetch_and_add(bytes, skb->len);
		}
	}

	/*
	 * flags=0: tcp_bpf_sendmsg_redir — data leaves via peer socket to the network.
	 * BPF_F_INGRESS would enqueue into peer receive queue (sidecar model) and stall
	 * once userspace stops reading. Contract review 2026-08-03: must be 0.
	 */
	long ret = sk_redirect_hash(skb, &sb_splice_socks, peer, 0);
	if (ret == SK_PASS) {
		splice_inc_stat(SB_SPLICE_STAT_REDIRECTS);
		return (int)ret;
	}
	splice_inc_stat(SB_SPLICE_STAT_REDIRECT_FAILURES);
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
