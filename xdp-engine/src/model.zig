//! Hook-neutral verdicts, XDP actions, and bounded resource constants.
//! No allocator, no OS, no sockets.

pub const abi_version: u32 = 1;

pub const Verdict = enum(u8) {
    unseen = 0,
    direct = 1,
    proxy = 2,
    block = 3,
    must_control = 4,
};

pub const XdpAction = enum(u8) {
    aborted = 0,
    drop = 1,
    pass = 2,
    tx = 3,
    redirect = 4,
};

/// Empty XSKMAP slot must continue into the kernel, never drop.
pub const redirect_empty_slot_flags: u32 = @intFromEnum(XdpAction.pass);

pub const Reason = enum(u16) {
    none = 0,
    static_direct = 1,
    flow_direct = 2,
    fakeip_direct = 3,
    dns_hint_direct = 4,
    policy_proxy = 5,
    map_miss_proxy = 6,
    generation_miss_proxy = 7,
    parse_fail_proxy = 8,
    blocked = 11,
    dns_hint_conflict = 12,
    security_bypass = 14,
    established_bypass = 15,
    static_proxy = 16,
    static_block = 17,
    must_control = 18,
    flow_proxy = 20,
    weak_dns_proxy = 22,
};

pub const Evidence = enum(u8) {
    none = 0,
    fakeip = 1,
    strong = 2,
    weak = 3,
};

pub const af_inet: u8 = 2;
pub const af_inet6: u8 = 10;
pub const proto_icmp: u8 = 1;
pub const proto_tcp: u8 = 6;
pub const proto_udp: u8 = 17;
pub const proto_icmpv6: u8 = 58;

pub const umem_frame_size: u32 = 2048;
pub const umem_frame_count: u32 = 4096;
pub const umem_frame_size_min: u32 = 2048;
pub const umem_frame_size_max: u32 = 4096;
pub const umem_frame_count_min: u32 = 512;
pub const umem_frame_count_max: u32 = 16384;
pub const max_queues: u32 = 64;

fn floorPowerOfTwo(value: u32) u32 {
    var power: u32 = 1;
    while ((power << 1) <= value) : (power <<= 1) {}
    return power;
}

pub fn clampUmem(frame_size: u32, frame_count: u32) struct { size: u32, count: u32 } {
    var size = frame_size;
    var count = frame_count;
    if (size < umem_frame_size_min) size = umem_frame_size_min;
    if (size > umem_frame_size_max) size = umem_frame_size_max;
    // The kernel requires UMEM chunk_size to be a power of two.  Round down
    // instead of silently asking the bind path to accept an invalid chunk.
    size = floorPowerOfTwo(size);
    if (count < umem_frame_count_min) count = umem_frame_count_min;
    if (count > umem_frame_count_max) count = umem_frame_count_max;
    return .{ .size = size, .count = count };
}

const std = @import("std");

test "redirect empty slot uses xdp pass" {
    try std.testing.expectEqual(@as(u32, 2), redirect_empty_slot_flags);
    try std.testing.expect(redirect_empty_slot_flags != @intFromEnum(XdpAction.aborted));
    try std.testing.expect(redirect_empty_slot_flags != @intFromEnum(XdpAction.drop));
}

test "umem bounds do not grow with node count" {
    const huge_nodes: u32 = 1_000_000;
    const clamped = clampUmem(2048, huge_nodes);
    try std.testing.expectEqual(umem_frame_count_max, clamped.count);
    try std.testing.expectEqual(umem_frame_size, clampUmem(2048, 4096).size);
}

test "umem chunk size is a kernel-valid power of two" {
    try std.testing.expectEqual(@as(u32, 2048), clampUmem(3072, 512).size);
    try std.testing.expectEqual(@as(u32, 2048), clampUmem(4095, 512).size);
    try std.testing.expectEqual(@as(u32, 4096), clampUmem(4096, 512).size);
}
