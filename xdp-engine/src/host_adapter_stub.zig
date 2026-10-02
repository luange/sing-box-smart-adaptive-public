//! Non-Linux placeholder for the AF_XDP host adapter.
//!
//! The policy core remains portable, but AF_XDP is a Linux UAPI.  Keeping the
//! same small surface here makes accidental Darwin/Windows enablement fail at
//! construction time instead of turning into a silent no-op.

const std = @import("std");

pub const BindMode = enum(u32) {
    zero_copy = 0,
    copy = 1,
};

pub const Config = extern struct {
    ifindex: u32,
    queue_count: u32,
    ring_size: u32,
    frame_size: u32,
    frame_count: u32,
    mode: u32,
};

pub const CFrame = extern struct {
    queue: u32,
    address: u64,
    length: u32,
    options: u32,
};

pub const Stats = extern struct {
    rx: u64 = 0,
    tx: u64 = 0,
    recycled: u64 = 0,
    completed: u64 = 0,
    fill_starved: u64 = 0,
    tx_full: u64 = 0,
    invalid_descriptor: u64 = 0,
};

pub const Adapter = struct {};

pub fn init(_: std.mem.Allocator, _: Config) error{UnsupportedPlatform}!Adapter {
    return error.UnsupportedPlatform;
}

test "non-Linux adapter is explicit" {
    try std.testing.expectError(error.UnsupportedPlatform, init(std.testing.allocator, .{}));
}
