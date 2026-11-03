// Copyright 2026 sing-box smart-adaptive contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XDP map surface.  Policy maps are declared by policy_maps.h so the XDP
// object and the TC object consume the same userspace-owned FDs.  The only
// XDP-specific state is the bounded queue-to-XSK map and its separate control
// record.

#ifndef SING_BOX_EBPF_V3_XDP_POLICY_MAPS_H
#define SING_BOX_EBPF_V3_XDP_POLICY_MAPS_H

#include "policy_maps.h"

#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP 17
#endif

/* A missing queue entry must return XDP_PASS.  The helper's flags argument
 * uses the XDP action value, so no userspace fallback code is required. */
SB_V3_MAP(v3_xdp_control, BPF_MAP_TYPE_ARRAY, __u32, struct sb_xdp_control, 1U, 0U);
SB_V3_MAP(v3_xsk_map, BPF_MAP_TYPE_XSKMAP, __u32, __u32, SB_XDP_MAX_QUEUES, 0U);

#endif /* SING_BOX_EBPF_V3_XDP_POLICY_MAPS_H */
