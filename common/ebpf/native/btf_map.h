// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef SING_BOX_BTF_MAP_H
#define SING_BOX_BTF_MAP_H

/* Minimal libbpf-compatible BTF map declaration helpers.  They intentionally
 * avoid a libbpf runtime dependency: the project loader replaces map symbols
 * with process-owned map FDs, while Clang still emits standard .maps BTF. */
#define SB_BTF_UINT(name, value) int (*name)[value]
#define SB_BTF_TYPE(name, value) value *name
#define SB_BTF_MAP(name, map_type, key_type, value_type, count, flags_value) \
    struct { \
        SB_BTF_UINT(type, map_type); \
        SB_BTF_UINT(max_entries, count); \
        SB_BTF_TYPE(key, key_type); \
        SB_BTF_TYPE(value, value_type); \
        SB_BTF_UINT(map_flags, flags_value); \
    } name SEC(".maps")

#endif
