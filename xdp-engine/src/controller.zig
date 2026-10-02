//! Host-neutral XDP hand-off ordering.
//!
//! The Linux adapter owns sockets and rings; the C loader owns BPF program/map
//! FDs. This small value type is the common contract between them. It makes an
//! early control-map enable impossible even when a host (sing-box, mihomo, or
//! another consumer) is implemented in a different language.

const std = @import("std");
const probe = @import("probe.zig");

pub const State = enum(u8) {
    disabled = 0,
    probing = 1,
    attached = 2,
    enabled = 3,
    fallback_tc = 4,
    detaching = 5,
};

pub const Controller = struct {
    state: State = .disabled,
    mode: ?probe.Mode = null,
    queue_count: u32 = 0,
    xsk_bound_mask: u64 = 0,
    program_attached: bool = false,
    allow_multibuffer: bool = false,
    generation: u32 = 0,

    pub fn beginProbe(self: *Controller, queue_count: u32, mode: probe.Mode, allow_multibuffer: bool) bool {
        if (queue_count == 0 or queue_count > 64) return false;
        if (self.state != .disabled and self.state != .fallback_tc) return false;
        self.* = .{
            .state = .probing,
            .mode = mode,
            .queue_count = queue_count,
            .allow_multibuffer = allow_multibuffer,
        };
        return true;
    }

    pub fn markProgramAttached(self: *Controller) bool {
        if (self.state != .probing) return false;
        self.program_attached = true;
        self.state = .attached;
        return true;
    }

    pub fn markQueueBound(self: *Controller, queue: u32) bool {
        if (self.state != .attached or queue >= self.queue_count) return false;
        self.xsk_bound_mask |= @as(u64, 1) << @intCast(queue);
        return true;
    }

    pub fn allQueuesBound(self: *const Controller) bool {
        if (self.queue_count == 0) return false;
        const required = if (self.queue_count == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(self.queue_count)) - 1;
        return (self.xsk_bound_mask & required) == required;
    }

    pub fn enable(self: *Controller, generation: u32) bool {
        if (self.state != .attached or !self.program_attached or !self.allQueuesBound()) return false;
        if (self.allow_multibuffer or generation == 0) return false;
        self.generation = generation;
        self.state = .enabled;
        return true;
    }

    pub fn fallback(self: *Controller) void {
        self.state = .fallback_tc;
        self.program_attached = false;
        self.xsk_bound_mask = 0;
        self.generation = 0;
    }

    pub fn onLinkChange(self: *Controller) void {
        if (self.state == .enabled or self.state == .attached or self.state == .probing) {
            self.state = .detaching;
        }
        self.fallback();
    }

    pub fn close(self: *Controller) void {
        self.* = .{};
    }

    pub fn enabled(self: *const Controller) bool {
        return self.state == .enabled;
    }
};

test "controller never enables before every queue is bound" {
    var controller = Controller{};
    try std.testing.expect(controller.beginProbe(2, .native, false));
    try std.testing.expect(controller.markProgramAttached());
    try std.testing.expect(!controller.enable(1));
    try std.testing.expect(controller.markQueueBound(0));
    try std.testing.expect(!controller.enable(1));
    try std.testing.expect(controller.markQueueBound(1));
    try std.testing.expect(controller.enable(1));
    try std.testing.expect(controller.enabled());
}

test "link changes immediately return to TC" {
    var controller = Controller{};
    try std.testing.expect(controller.beginProbe(2, .native, false));
    try std.testing.expect(controller.markProgramAttached());
    try std.testing.expect(controller.markQueueBound(0));
    try std.testing.expect(controller.markQueueBound(1));
    try std.testing.expect(controller.enable(4));
    controller.onLinkChange();
    try std.testing.expectEqual(State.fallback_tc, controller.state);
    try std.testing.expect(!controller.enabled());
    try std.testing.expectEqual(@as(u64, 0), controller.xsk_bound_mask);
}

test "multibuffer and zero generation are never enabled" {
    var controller = Controller{};
    try std.testing.expect(controller.beginProbe(2, .native, true));
    try std.testing.expect(controller.markProgramAttached());
    try std.testing.expect(controller.markQueueBound(0));
    try std.testing.expect(controller.markQueueBound(1));
    try std.testing.expect(!controller.enable(1));

    controller.fallback();
    try std.testing.expect(controller.beginProbe(2, .native, false));
    try std.testing.expect(controller.markProgramAttached());
    try std.testing.expect(controller.markQueueBound(0));
    try std.testing.expect(controller.markQueueBound(1));
    try std.testing.expect(!controller.enable(0));
}
