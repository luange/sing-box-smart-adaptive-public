// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "singbox_ebpf.h"
#include "singbox_ebpf_out.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Do NOT #define enum attach/prog types — they are enum constants in linux/bpf.h.
 * Using #ifndef + wrong numeric fallback overrides attach with invalid values. */

#define SB_SPLICE_ATTACHED_PARSER (1U << 0)
#define SB_SPLICE_ATTACHED_VERDICT (1U << 1)
/* BPF_SK_SKB_VERDICT = 10 since Linux 5.13. Always available as a number so we
 * can probe at runtime even when older uapi headers omit the enum constant. */
#define SB_BPF_SK_SKB_VERDICT 10

static void splice_runtime_init(struct sb_splice_runtime *runtime) {
	memset(runtime, 0xff, sizeof(*runtime));
	runtime->attached_programs = 0U;
}

static int splice_close_fd(int *fd) {
	if (fd == NULL || *fd < 0) {
		return 0;
	}
	int value = *fd;
	*fd = -1;
	return close(value);
}

static void splice_fill_map_table(
	const struct sb_splice_runtime *runtime,
	struct sb_ebpf_object_map_entry *entries,
	struct sb_ebpf_object_map_table *table) {
	entries[0] = (struct sb_ebpf_object_map_entry){"sb_splice_socks", runtime->sock_map_fd};
	entries[1] = (struct sb_ebpf_object_map_entry){"sb_splice_peer", runtime->peer_map_fd};
	entries[2] = (struct sb_ebpf_object_map_entry){"sb_splice_bytes", runtime->bytes_map_fd};
	entries[3] = (struct sb_ebpf_object_map_entry){"sb_splice_stats", runtime->stats_map_fd};
	entries[4] = (struct sb_ebpf_object_map_entry){"sb_splice_control", runtime->control_map_fd};
	table->entries = entries;
	table->count = 5U;
}

static int splice_create_map_or_fail(
	const char **stage,
	const char *name,
	int *out_fd,
	enum bpf_map_type type,
	uint32_t key_size,
	uint32_t value_size,
	uint32_t max_entries,
	uint32_t flags) {
	*stage = name;
	*out_fd = sb_ebpf_create_map(type, key_size, value_size, max_entries, flags);
	if (*out_fd < 0) {
		return -1;
	}
	return 0;
}

int sb_ebpf_splice_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t max_entries,
	bool enable_accounting,
	struct sb_splice_runtime *runtime) {
	if (object == NULL || object_size == 0U || runtime == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (max_entries == 0U) {
		max_entries = SB_SPLICE_MAX_ENTRIES;
	}
	splice_runtime_init(runtime);
	const char *stage = "init";

	if (splice_create_map_or_fail(
		    &stage,
		    "create sockhash",
		    &runtime->sock_map_fd,
		    (enum bpf_map_type)BPF_MAP_TYPE_SOCKHASH,
		    sizeof(struct sb_splice_key),
		    sizeof(uint64_t),
		    max_entries,
		    0U) != 0) {
		goto fail;
	}
	/* LRU_HASH: same class of fix as IN-FIX-1 — plain HASH fills and stays full. */
	if (splice_create_map_or_fail(
		    &stage,
		    "create peer map",
		    &runtime->peer_map_fd,
		    BPF_MAP_TYPE_LRU_HASH,
		    sizeof(struct sb_splice_key),
		    sizeof(struct sb_splice_key),
		    max_entries,
		    0U) != 0) {
		goto fail;
	}
	if (splice_create_map_or_fail(
		    &stage,
		    "create bytes map",
		    &runtime->bytes_map_fd,
		    (enum bpf_map_type)BPF_MAP_TYPE_PERCPU_HASH,
		    sizeof(struct sb_splice_key),
		    sizeof(uint64_t),
		    max_entries,
		    0U) != 0) {
		goto fail;
	}
	if (splice_create_map_or_fail(
		    &stage,
		    "create stats map",
		    &runtime->stats_map_fd,
		    BPF_MAP_TYPE_ARRAY,
		    sizeof(uint32_t),
		    sizeof(uint64_t),
		    SB_SPLICE_STAT_COUNT,
		    0U) != 0) {
		goto fail;
	}
	if (splice_create_map_or_fail(
		    &stage,
		    "create control map",
		    &runtime->control_map_fd,
		    BPF_MAP_TYPE_ARRAY,
		    sizeof(uint32_t),
		    sizeof(struct sb_splice_control),
		    1U,
		    0U) != 0) {
		goto fail;
	}
	runtime->events_map_fd = -1;
	runtime->sockops_prog_fd = -1;

	/* control.enabled is written from Go after attach (default 0 = off).
	 * enable_accounting is applied via control.flags from Go Attach(). */
	(void)enable_accounting;

	struct sb_ebpf_object_map_entry entries[5];
	struct sb_ebpf_object_map_table maps;
	splice_fill_map_table(runtime, entries, &maps);

	stage = "load stream parser";
	runtime->parser_prog_fd = sb_ebpf_object_load_section(
		object,
		object_size,
		"sk_skb/stream_parser",
		"sb_spl_par",
		(enum bpf_prog_type)BPF_PROG_TYPE_SK_SKB,
		(enum bpf_attach_type)BPF_SK_SKB_STREAM_PARSER,
		&maps);
	if (runtime->parser_prog_fd < 0) {
		goto fail;
	}
	stage = "load stream verdict";
	runtime->verdict_prog_fd = sb_ebpf_object_load_section(
		object,
		object_size,
		"sk_skb/stream_verdict",
		"sb_spl_ver",
		(enum bpf_prog_type)BPF_PROG_TYPE_SK_SKB,
		(enum bpf_attach_type)BPF_SK_SKB_STREAM_VERDICT,
		&maps);
	if (runtime->verdict_prog_fd < 0) {
		goto fail;
	}
	return 0;

fail: {
	int saved = errno;
	fprintf(stderr, "splice stage '%s' failed: errno=%d\n", stage, saved);
	(void)sb_ebpf_splice_close(runtime);
	errno = saved;
	return -1;
}
}

int sb_ebpf_splice_attach(struct sb_splice_runtime *runtime) {
	if (runtime == NULL || runtime->sock_map_fd < 0 || runtime->verdict_prog_fd < 0) {
		errno = EINVAL;
		return -1;
	}

	/* Preferred: stream parser + stream verdict (needs CONFIG_BPF_STREAM_PARSER). */
	if (runtime->parser_prog_fd >= 0 &&
	    sb_ebpf_attach_prog(
		    runtime->sock_map_fd,
		    runtime->parser_prog_fd,
		    BPF_SK_SKB_STREAM_PARSER) == 0) {
		runtime->attached_programs |= SB_SPLICE_ATTACHED_PARSER;
		if (sb_ebpf_attach_prog(
			    runtime->sock_map_fd,
			    runtime->verdict_prog_fd,
			    BPF_SK_SKB_STREAM_VERDICT) == 0) {
			runtime->attached_programs |= SB_SPLICE_ATTACHED_VERDICT;
			return 0;
		}
		(void)sb_ebpf_detach_prog(
			runtime->sock_map_fd,
			runtime->parser_prog_fd,
			BPF_SK_SKB_STREAM_PARSER);
		runtime->attached_programs &= ~SB_SPLICE_ATTACHED_PARSER;
	}

	/*
	 * Fallback: verdict-only attach (BPF_SK_SKB_VERDICT = 10). Works on kernels
	 * where CONFIG_BPF_STREAM_PARSER is off but CONFIG_NET_SOCK_MSG is on.
	 * Runtime probe — do not #ifdef enum constants (they are not macros).
	 */
	if (sb_ebpf_attach_prog(
		    runtime->sock_map_fd,
		    runtime->verdict_prog_fd,
		    (enum bpf_attach_type)SB_BPF_SK_SKB_VERDICT) == 0) {
		runtime->attached_programs |= SB_SPLICE_ATTACHED_VERDICT;
		return 0;
	}
	return -1;
}

int sb_ebpf_splice_close(struct sb_splice_runtime *runtime) {
	if (runtime == NULL) {
		return 0;
	}
	int result = 0;
	if ((runtime->attached_programs & SB_SPLICE_ATTACHED_VERDICT) != 0U &&
	    runtime->sock_map_fd >= 0 && runtime->verdict_prog_fd >= 0) {
		/* Try stream_verdict first, then verdict-only. */
		if (sb_ebpf_detach_prog(
			    runtime->sock_map_fd,
			    runtime->verdict_prog_fd,
			    BPF_SK_SKB_STREAM_VERDICT) != 0) {
			if (sb_ebpf_detach_prog(
				    runtime->sock_map_fd,
				    runtime->verdict_prog_fd,
				    (enum bpf_attach_type)SB_BPF_SK_SKB_VERDICT) != 0 &&
			    result == 0) {
				result = -1;
			}
		}
	}
	if ((runtime->attached_programs & SB_SPLICE_ATTACHED_PARSER) != 0U &&
	    runtime->sock_map_fd >= 0 && runtime->parser_prog_fd >= 0) {
		if (sb_ebpf_detach_prog(
			    runtime->sock_map_fd,
			    runtime->parser_prog_fd,
			    BPF_SK_SKB_STREAM_PARSER) != 0 &&
		    result == 0) {
			result = -1;
		}
	}
	runtime->attached_programs = 0U;
#define CLOSE_SPLICE_FD(FD) \
	do { \
		if (splice_close_fd(&(FD)) != 0 && result == 0) { \
			result = -1; \
		} \
	} while (0)
	CLOSE_SPLICE_FD(runtime->sockops_prog_fd);
	CLOSE_SPLICE_FD(runtime->verdict_prog_fd);
	CLOSE_SPLICE_FD(runtime->parser_prog_fd);
	CLOSE_SPLICE_FD(runtime->events_map_fd);
	CLOSE_SPLICE_FD(runtime->control_map_fd);
	CLOSE_SPLICE_FD(runtime->stats_map_fd);
	CLOSE_SPLICE_FD(runtime->bytes_map_fd);
	CLOSE_SPLICE_FD(runtime->peer_map_fd);
	CLOSE_SPLICE_FD(runtime->sock_map_fd);
#undef CLOSE_SPLICE_FD
	return result;
}
