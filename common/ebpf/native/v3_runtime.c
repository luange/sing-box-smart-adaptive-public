// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Kernel map create + ELF load for shared-network engine=v3.

#include "singbox_ebpf.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Pull v3 ABI layouts (same as kern/abi.h). Keep path relative to native/. */
#include "../v3/kern/abi.h"

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1U
#endif

static void v3_init(struct sb_ebpf_v3_runtime *runtime) {
	memset(runtime, 0xff, sizeof(*runtime));
}

static int v3_close_fd(int *fd) {
	if (fd == NULL || *fd < 0)
		return 0;
	int value = *fd;
	*fd = -1;
	return close(value);
}

static int v3_create_lpm4(uint32_t max_entries, uint32_t value_size) {
	return sb_ebpf_create_map(
		BPF_MAP_TYPE_LPM_TRIE,
		sizeof(struct sb_v3_lpm4_key),
		value_size,
		max_entries,
		BPF_F_NO_PREALLOC);
}

static int v3_create_lpm6(uint32_t max_entries, uint32_t value_size) {
	return sb_ebpf_create_map(
		BPF_MAP_TYPE_LPM_TRIE,
		sizeof(struct sb_v3_lpm6_key),
		value_size,
		max_entries,
		BPF_F_NO_PREALLOC);
}

static int v3_load_programs(
	const uint8_t *object,
	size_t object_size,
	struct sb_ebpf_v3_runtime *runtime) {
	struct sb_ebpf_object_map_entry entries[20];
	struct sb_ebpf_object_map_table maps;
	size_t n = 0;
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_control", runtime->control_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank0", runtime->policy4_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy4_bank1", runtime->policy4_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank0", runtime->policy6_bank0_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_policy6_bank1", runtime->policy6_bank1_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dynamic_direct4", runtime->dynamic_direct4_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dynamic_direct6", runtime->dynamic_direct6_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host4", runtime->host4_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_host6", runtime->host6_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_flow_verdict", runtime->flow_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_ip_hint", runtime->dns_hint_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_observe", runtime->dns_observe_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_dns_scratch", runtime->dns_scratch_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_source_mac", runtime->source_mac_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_redirect", runtime->redirect_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_listener_sockets", runtime->listener_map_fd};
	entries[n++] = (struct sb_ebpf_object_map_entry){"v3_stats", runtime->stats_map_fd};
	maps.entries = entries;
	maps.count = n;

	runtime->ingress_prog_fd = sb_ebpf_object_load_section(
		object,
		object_size,
		"classifier/ingress",
		"sb_v3_ingress",
		BPF_PROG_TYPE_SCHED_CLS,
		(enum bpf_attach_type)0,
		&maps);
	if (runtime->ingress_prog_fd < 0)
		return -1;
	/* socket_assign: no egress rewrite required (design §10). */
	runtime->egress_prog_fd = -1;
	return 0;
}

int sb_ebpf_v3_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t policy_lpm_entries,
	uint32_t flow_entries,
	uint32_t dns_hint_entries,
	struct sb_ebpf_v3_runtime *runtime) {
	if (object == NULL || object_size == 0U || runtime == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (policy_lpm_entries == 0U)
		policy_lpm_entries = SB_V3_DEFAULT_POLICY_LPM;
	if (policy_lpm_entries > SB_V3_MAX_POLICY_LPM_ENTRIES)
		policy_lpm_entries = SB_V3_MAX_POLICY_LPM_ENTRIES;
	if (flow_entries == 0U)
		flow_entries = SB_V3_DEFAULT_FLOW_ENTRIES;
	if (flow_entries > SB_V3_MAX_FLOW_ENTRIES)
		flow_entries = SB_V3_MAX_FLOW_ENTRIES;
	if (dns_hint_entries == 0U)
		dns_hint_entries = SB_V3_DEFAULT_DNS_HINTS;
	if (dns_hint_entries > SB_V3_MAX_DNS_HINTS)
		dns_hint_entries = SB_V3_MAX_DNS_HINTS;

	v3_init(runtime);
	const char *stage = "create v3_control";
	runtime->control_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_ARRAY,
		sizeof(uint32_t),
		sizeof(struct sb_v3_control),
		1U,
		0U);
	stage = "create policy4 banks";
	runtime->policy4_bank0_fd =
		v3_create_lpm4(policy_lpm_entries, sizeof(struct sb_v3_policy_value));
	runtime->policy4_bank1_fd =
		v3_create_lpm4(policy_lpm_entries, sizeof(struct sb_v3_policy_value));
	stage = "create policy6 banks";
	runtime->policy6_bank0_fd =
		v3_create_lpm6(policy_lpm_entries, sizeof(struct sb_v3_policy_value));
	runtime->policy6_bank1_fd =
		v3_create_lpm6(policy_lpm_entries, sizeof(struct sb_v3_policy_value));
	stage = "create dynamic direct maps";
	runtime->dynamic_direct4_fd =
		sb_ebpf_create_map(BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_v3_lpm4_key),
				   sizeof(struct sb_v3_dynamic_direct_value), SB_V3_DEFAULT_DYNAMIC_DIRECT_ENTRIES,
				   BPF_F_NO_PREALLOC);
	runtime->dynamic_direct6_fd =
		sb_ebpf_create_map(BPF_MAP_TYPE_LPM_TRIE, sizeof(struct sb_v3_lpm6_key),
				   sizeof(struct sb_v3_dynamic_direct_value), SB_V3_DEFAULT_DYNAMIC_DIRECT_ENTRIES,
				   BPF_F_NO_PREALLOC);
	stage = "create host maps";
	runtime->host4_map_fd = v3_create_lpm4(1024U, sizeof(uint8_t));
	runtime->host6_map_fd = v3_create_lpm6(1024U, sizeof(uint8_t));
	stage = "create flow map";
	runtime->flow_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_LRU_HASH,
		sizeof(struct sb_v3_flow_key),
		sizeof(struct sb_v3_flow_value),
		flow_entries,
		0U);
	stage = "create dns hint map";
	runtime->dns_hint_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_LRU_HASH,
		sizeof(struct sb_v3_dns_ip_key),
		sizeof(struct sb_v3_dns_ip_value),
		dns_hint_entries,
		0U);
	stage = "create dns observation map";
	runtime->dns_observe_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_LRU_HASH,
		sizeof(struct sb_v3_dns_obs_key),
		sizeof(struct sb_v3_dns_obs_value),
		SB_V3_MAX_DNS_OBSERVATIONS,
		0U);
	stage = "create dns scratch map";
	runtime->dns_scratch_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_PERCPU_ARRAY,
		sizeof(uint32_t),
		sizeof(struct sb_v3_dns_scratch),
		1U,
		0U);
	stage = "create source mac map";
	runtime->source_mac_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_HASH,
		sizeof(struct sb_v3_mac_key),
		sizeof(struct sb_v3_source_policy_value),
		SB_V3_MAX_SOURCE_POLICY > 8192U ? 8192U : SB_V3_MAX_SOURCE_POLICY,
		0U);
	stage = "create redirect map";
	runtime->redirect_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_LRU_HASH,
		sizeof(struct sb_v3_redirect_key),
		sizeof(struct sb_v3_redirect_value),
		flow_entries,
		0U);
	stage = "create listener sockmap";
	runtime->listener_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_SOCKMAP,
		sizeof(uint32_t),
		sizeof(uint64_t),
		SB_V3_LISTENER_COUNT,
		0U);
	stage = "create stats map";
	runtime->stats_map_fd = sb_ebpf_create_map(
		BPF_MAP_TYPE_PERCPU_ARRAY,
		sizeof(uint32_t),
		sizeof(struct sb_v3_stats_value),
		1U,
		0U);

	if (runtime->control_map_fd < 0 || runtime->policy4_bank0_fd < 0 ||
	    runtime->policy4_bank1_fd < 0 || runtime->policy6_bank0_fd < 0 ||
	    runtime->policy6_bank1_fd < 0 || runtime->dynamic_direct4_fd < 0 ||
	    runtime->dynamic_direct6_fd < 0 || runtime->host4_map_fd < 0 ||
	    runtime->host6_map_fd < 0 || runtime->flow_map_fd < 0 ||
	    runtime->dns_hint_map_fd < 0 || runtime->dns_observe_map_fd < 0 || runtime->dns_scratch_map_fd < 0 || runtime->source_mac_map_fd < 0 ||
	    runtime->redirect_map_fd < 0 || runtime->listener_map_fd < 0 ||
	    runtime->stats_map_fd < 0) {
		goto fail;
	}

	stage = "load v3 TC programs";
	if (v3_load_programs(object, object_size, runtime) != 0)
		goto fail;
	return 0;

fail: {
	int saved = errno;
	fprintf(stderr, "ebpf v3 stage '%s' failed: errno=%d\n", stage, saved);
	(void)sb_ebpf_v3_close(runtime);
	errno = saved;
	return -1;
}
}

int sb_ebpf_v3_close(struct sb_ebpf_v3_runtime *runtime) {
	if (runtime == NULL)
		return 0;
	int result = 0;
#define CLOSE_V3(FD)                           \
	do {                                   \
		if (v3_close_fd(&(FD)) != 0 && result == 0) \
			result = -1;           \
	} while (0)
	CLOSE_V3(runtime->egress_prog_fd);
	CLOSE_V3(runtime->ingress_prog_fd);
	CLOSE_V3(runtime->stats_map_fd);
	CLOSE_V3(runtime->listener_map_fd);
	CLOSE_V3(runtime->redirect_map_fd);
	CLOSE_V3(runtime->source_mac_map_fd);
	CLOSE_V3(runtime->dns_hint_map_fd);
	CLOSE_V3(runtime->dns_observe_map_fd);
	CLOSE_V3(runtime->dns_scratch_map_fd);
	CLOSE_V3(runtime->flow_map_fd);
	CLOSE_V3(runtime->host6_map_fd);
	CLOSE_V3(runtime->host4_map_fd);
	CLOSE_V3(runtime->policy6_bank1_fd);
	CLOSE_V3(runtime->policy6_bank0_fd);
	CLOSE_V3(runtime->dynamic_direct6_fd);
	CLOSE_V3(runtime->dynamic_direct4_fd);
	CLOSE_V3(runtime->policy4_bank1_fd);
	CLOSE_V3(runtime->policy4_bank0_fd);
	CLOSE_V3(runtime->control_map_fd);
#undef CLOSE_V3
	return result;
}
