// Copyright 2026, Asterisk4Magisk contributors
// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "singbox_ebpf.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void shared_network_fill_map_table(
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	int dns_direct_ipv4_map_fd,
	int dns_direct_ipv6_map_fd,
	const struct sb_ebpf_shared_network_runtime *runtime,
	bool data_plane_v2,
	struct sb_ebpf_object_map_entry *entries,
	struct sb_ebpf_object_map_table *table) {
	entries[0] = (struct sb_ebpf_object_map_entry){"shared_control", runtime->control_map_fd};
	if (data_plane_v2) {
		entries[1] = (struct sb_ebpf_object_map_entry){"shared_redirect", runtime->redirect_map_fd};
		entries[2] = (struct sb_ebpf_object_map_entry){"shared_flow_direct", runtime->flow_direct_map_fd};
		entries[3] = (struct sb_ebpf_object_map_entry){"shared_listener_sockets", runtime->listener_socket_map_fd};
		entries[4] = (struct sb_ebpf_object_map_entry){"shared_interface_mac", runtime->interface_mac_map_fd};
		entries[5] = (struct sb_ebpf_object_map_entry){"shared_stats", runtime->stats_map_fd};
		entries[6] = (struct sb_ebpf_object_map_entry){"shared_host_ipv4", runtime->host_ipv4_map_fd};
		entries[7] = (struct sb_ebpf_object_map_entry){"shared_host_ipv6", runtime->host_ipv6_map_fd};
		entries[8] = (struct sb_ebpf_object_map_entry){"shared_bypass_ipv4", bypass_ipv4_map_fd};
		entries[9] = (struct sb_ebpf_object_map_entry){"shared_bypass_ipv6", bypass_ipv6_map_fd};
		entries[10] = (struct sb_ebpf_object_map_entry){"shared_dns_direct_ipv4", dns_direct_ipv4_map_fd};
		entries[11] = (struct sb_ebpf_object_map_entry){"shared_dns_direct_ipv6", dns_direct_ipv6_map_fd};
		table->entries = entries;
		table->count = 12U;
		return;
	}
	entries[1] = (struct sb_ebpf_object_map_entry){"shared_interface_mac", runtime->interface_mac_map_fd};
	entries[2] = (struct sb_ebpf_object_map_entry){"shared_original_to_token", runtime->original_to_token_map_fd};
	entries[3] = (struct sb_ebpf_object_map_entry){"shared_token_to_original", runtime->token_to_original_map_fd};
	entries[4] = (struct sb_ebpf_object_map_entry){"shared_redirect", runtime->redirect_map_fd};
	entries[5] = (struct sb_ebpf_object_map_entry){"shared_flow_direct", runtime->flow_direct_map_fd};
	entries[6] = (struct sb_ebpf_object_map_entry){"shared_listener_sockets", runtime->listener_socket_map_fd};
	entries[7] = (struct sb_ebpf_object_map_entry){"shared_stats", runtime->stats_map_fd};
	entries[8] = (struct sb_ebpf_object_map_entry){"shared_host_ipv4", runtime->host_ipv4_map_fd};
	entries[9] = (struct sb_ebpf_object_map_entry){"shared_host_ipv6", runtime->host_ipv6_map_fd};
	entries[10] = (struct sb_ebpf_object_map_entry){"shared_bypass_ipv4", bypass_ipv4_map_fd};
	entries[11] = (struct sb_ebpf_object_map_entry){"shared_bypass_ipv6", bypass_ipv6_map_fd};
	entries[12] = (struct sb_ebpf_object_map_entry){"shared_dns_direct_ipv4", dns_direct_ipv4_map_fd};
	entries[13] = (struct sb_ebpf_object_map_entry){"shared_dns_direct_ipv6", dns_direct_ipv6_map_fd};
	entries[14] = (struct sb_ebpf_object_map_entry){"shared_scratch", runtime->scratch_map_fd};
	table->entries = entries;
	table->count = 15U;
}

int sb_ebpf_load_shared_network_programs(
	const uint8_t *object,
	size_t object_size,
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	int dns_direct_ipv4_map_fd,
	int dns_direct_ipv6_map_fd,
	bool data_plane_v2,
	struct sb_ebpf_shared_network_runtime *runtime) {
	if (object == NULL || runtime == NULL ||
	    bypass_ipv4_map_fd < 0 || bypass_ipv6_map_fd < 0 ||
	    dns_direct_ipv4_map_fd < 0 || dns_direct_ipv6_map_fd < 0) {
		errno = EINVAL;
		return -1;
	}

	struct sb_ebpf_object_map_entry entries[15];
	struct sb_ebpf_object_map_table maps;
	shared_network_fill_map_table(
		bypass_ipv4_map_fd,
		bypass_ipv6_map_fd,
		dns_direct_ipv4_map_fd,
		dns_direct_ipv6_map_fd,
		runtime,
		data_plane_v2,
		entries,
		&maps);

	runtime->ingress_prog_fd = sb_ebpf_object_load_section(
		object,
		object_size,
		"classifier/ingress",
		data_plane_v2 ? "sb_share_v2_in" : "sb_share_in",
		BPF_PROG_TYPE_SCHED_CLS,
		(enum bpf_attach_type)0,
		&maps);
	if (runtime->ingress_prog_fd < 0) {
		return -1;
	}
	if (data_plane_v2) {
		/* socket_assign preserves the original tuple and replies through the
		 * normal kernel stack. It deliberately has no egress TC program. */
		runtime->egress_prog_fd = -1;
		return 0;
	}
	runtime->egress_prog_fd = sb_ebpf_object_load_section(
		object,
		object_size,
		"classifier/egress",
		"sb_share_out",
		BPF_PROG_TYPE_SCHED_CLS,
		(enum bpf_attach_type)0,
		&maps);
	return runtime->egress_prog_fd < 0 ? -1 : 0;
}
