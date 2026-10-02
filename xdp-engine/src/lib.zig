//! Next-gen XDP policy core and optional Linux AF_XDP host adapter.

const std = @import("std");
const model = @import("model.zig");
const classify = @import("classify.zig");
const probe = @import("probe.zig");
const lifecycle = @import("lifecycle.zig");
const controller = @import("controller.zig");
pub const afxdp = @import("afxdp.zig");
pub const host = if (@import("builtin").os.tag == .linux)
    @import("linux_adapter.zig")
else
    @import("host_adapter_stub.zig");

pub const abi_version = model.abi_version;
pub const Verdict = model.Verdict;
pub const XdpAction = model.XdpAction;
pub const classifyPacket = classify.classify;
pub const evaluateProbe = probe.evaluate;
pub const XdpMode = probe.Mode;
pub const XdpModeCapabilities = probe.ModeCapabilities;
pub const selectXdpMode = probe.selectMode;
pub const Session = lifecycle.Session;
pub const XdpController = controller.Controller;

pub fn version() u32 {
    return abi_version;
}

comptime {
    _ = model;
    _ = classify;
    _ = probe;
    _ = lifecycle;
    _ = controller;
    _ = afxdp;
    _ = host;
}

test "abi version is stable" {
    try std.testing.expectEqual(@as(u32, 1), version());
}

test "proxy traffic cannot ride an attached session" {
    var session = Session{};
    session.beginProbe();
    const sample = probe.Sample{
        .features = probe.feat_basic | probe.feat_redirect | probe.feat_xsk_zerocopy,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    };
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expect(session.attached());

    const decision = classify.classify(.{
        .generation = 1,
        .xdp_attached = session.attached(),
        .packet = .{ .dport = 443, .tcp_flags = 0x02 },
        .static_hit = .{ .verdict = .proxy, .generation = 1 },
    });
    try std.testing.expectEqual(model.XdpAction.pass, decision.action);
    try std.testing.expectEqual(model.Verdict.proxy, decision.verdict);
}
