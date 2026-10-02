// Copyright 2026 sing-box data-plane v2 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_BOX_DATAPLANE_V2_H
#define SING_BOX_DATAPLANE_V2_H

#include <linux/types.h>

struct sb_dp2_packet {
    __u8 family;
    __u8 protocol;
    __u8 fragmented;
    __u8 vlan_depth;
    __u16 source_port;
    __u16 destination_port;
    __u8 source[16];
    __u8 destination[16];
};

_Static_assert(sizeof(struct sb_dp2_packet) == 40U, "dp2 packet ABI");

#endif
