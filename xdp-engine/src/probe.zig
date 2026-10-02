//! Capability matrix for AF_XDP admission. Inputs are already-observed bits
//! (normally from the Linux `netdev` generic-netlink XDP feature attribute);
//! this module does not call netlink, ioctl, or bind.

const model = @import("model.zig");

pub const feat_basic: u64 = 1 << 0;
pub const feat_redirect: u64 = 1 << 1;
pub const feat_ndo_xmit: u64 = 1 << 2;
pub const feat_xsk_zerocopy: u64 = 1 << 3;
pub const feat_hw_offload: u64 = 1 << 4;
pub const feat_rx_sg: u64 = 1 << 5;
pub const feat_ndo_xmit_sg: u64 = 1 << 6;

pub const BindResult = enum(u8) {
    none = 0,
    zerocopy_ok = 1,
    copy_ok = 2,
    failed = 3,
};

pub const Outcome = enum(u8) {
    attach_zerocopy = 1,
    attach_copy = 2,
    fallback_tc = 3,
};

/// Linux XDP attach modes, ordered from the most capable to the most
/// compatible.  `skb` is generic XDP; `native` is driver/zero-copy XDP; and
/// `offload` asks the NIC to verify and run the program in hardware.
pub const Mode = enum(u8) { auto = 0, skb = 1, native = 2, offload = 3 };

pub const ModeCapabilities = struct {
    skb: bool = false,
    native: bool = false,
    offload: bool = false,
    /// The probe must include the actual program load/attach result.  A
    /// feature bitmap alone is not enough because drivers can reject maps or
    /// helpers at verifier time.
    skb_program_ok: bool = false,
    native_program_ok: bool = false,
    offload_program_ok: bool = false,
};

pub const ModeDecision = struct {
    selected: ?Mode,
    reason: FallbackReason,
};

/// Select a mode only after the program has been loaded in that mode.  Auto
/// prefers hardware, then native, then generic; explicit modes never silently
/// change the requested mode.  A null result is always a TC fallback.
pub fn selectMode(requested: Mode, capabilities: ModeCapabilities) ModeDecision {
    if (requested != .auto) {
        const ok = switch (requested) {
            .skb => capabilities.skb and capabilities.skb_program_ok,
            .native => capabilities.native and capabilities.native_program_ok,
            .offload => capabilities.offload and capabilities.offload_program_ok,
            .auto => unreachable,
        };
        return if (ok) .{ .selected = requested, .reason = .none } else .{ .selected = null, .reason = .bind_failed };
    }
    if (capabilities.offload and capabilities.offload_program_ok) {
        return .{ .selected = .offload, .reason = .none };
    }
    if (capabilities.native and capabilities.native_program_ok) {
        return .{ .selected = .native, .reason = .none };
    }
    if (capabilities.skb and capabilities.skb_program_ok) {
        return .{ .selected = .skb, .reason = .none };
    }
    return .{ .selected = null, .reason = .bind_failed };
}

pub const FallbackReason = enum(u8) {
    none = 0,
    missing_redirect = 1,
    missing_zerocopy = 2,
    single_queue = 3,
    bind_failed = 4,
    copy_disallowed = 5,
    features_absent_skip = 6,
    multibuffer_unsupported = 7,
};

pub const Sample = struct {
    features: u64 = 0,
    features_present: bool = true,
    rx_queues: u32 = 0,
    bind: BindResult = .none,
    allow_copy_mode: bool = false,
};

pub const Result = struct {
    outcome: Outcome,
    reason: FallbackReason,
    need_multibuffer_pass: bool = false,
    fatal: bool = false,
};

fn fallback(reason: FallbackReason, multibuffer: bool) Result {
    return .{
        .outcome = .fallback_tc,
        .reason = reason,
        .need_multibuffer_pass = multibuffer,
        .fatal = false,
    };
}

pub fn evaluate(sample: Sample) Result {
    const multibuffer = sample.features_present and (sample.features & feat_rx_sg) != 0;

    if (sample.features_present) {
        // The current parser and Zig adapter consume one descriptor per
        // packet. RX scatter-gather requires a bounded multi-segment parser;
        // until that exists, keep the whole interface on TC rather than
        // redirecting only the first segment into UMEM.
        if (multibuffer) return fallback(.multibuffer_unsupported, true);
        if (sample.features & feat_redirect == 0) {
            return fallback(.missing_redirect, multibuffer);
        }
        // XSK_ZEROCOPY is only an admission requirement for the zero-copy
        // bind. Generic/SKB copy mode must remain usable on drivers that
        // expose redirect but not zero-copy support.
        if (sample.bind == .zerocopy_ok and sample.features & feat_xsk_zerocopy == 0) {
            return fallback(.missing_zerocopy, multibuffer);
        }
    }

    return switch (sample.bind) {
        .zerocopy_ok => if (sample.rx_queues >= 2) .{
            .outcome = .attach_zerocopy,
            .reason = if (sample.features_present) .none else .features_absent_skip,
            .need_multibuffer_pass = multibuffer,
            .fatal = false,
        } else fallback(.single_queue, multibuffer),
        .copy_ok => if (sample.rx_queues == 0) fallback(.single_queue, multibuffer) else if (sample.allow_copy_mode) .{
            .outcome = .attach_copy,
            .reason = .none,
            .need_multibuffer_pass = multibuffer,
            .fatal = false,
        } else fallback(.copy_disallowed, multibuffer),
        .failed, .none => fallback(.bind_failed, multibuffer),
    };
}

const std = @import("std");

const capable: u64 = feat_basic | feat_redirect | feat_xsk_zerocopy;

test "missing redirect falls back" {
    const r = evaluate(.{ .features = feat_basic | feat_xsk_zerocopy, .rx_queues = 4, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.missing_redirect, r.reason);
    try std.testing.expect(!r.fatal);
}

test "missing zerocopy falls back" {
    const r = evaluate(.{ .features = feat_basic | feat_redirect, .rx_queues = 4, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.missing_zerocopy, r.reason);
}

test "single queue falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 1, .bind = .zerocopy_ok });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.single_queue, r.reason);
}

test "bind failed falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .failed });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.bind_failed, r.reason);
}

test "copy bind without allow_copy_mode falls back" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .copy_ok, .allow_copy_mode = false });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.copy_disallowed, r.reason);
}

test "copy bind with allow_copy_mode attaches copy" {
    const r = evaluate(.{ .features = capable, .rx_queues = 4, .bind = .copy_ok, .allow_copy_mode = true });
    try std.testing.expectEqual(Outcome.attach_copy, r.outcome);
    try std.testing.expect(!r.fatal);
}

test "copy mode does not require zero-copy capability or two queues" {
    const r = evaluate(.{
        .features = feat_basic | feat_redirect,
        .rx_queues = 1,
        .bind = .copy_ok,
        .allow_copy_mode = true,
    });
    try std.testing.expectEqual(Outcome.attach_copy, r.outcome);
    try std.testing.expectEqual(FallbackReason.none, r.reason);
}

test "rx_sg stays on TC until multi-buffer parsing exists" {
    const r = evaluate(.{
        .features = capable | feat_rx_sg,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    });
    try std.testing.expectEqual(Outcome.fallback_tc, r.outcome);
    try std.testing.expectEqual(FallbackReason.multibuffer_unsupported, r.reason);
    try std.testing.expect(r.need_multibuffer_pass);
}

test "absent feature bitmap skips tier 0" {
    const r = evaluate(.{
        .features = 0,
        .features_present = false,
        .rx_queues = 4,
        .bind = .zerocopy_ok,
    });
    try std.testing.expectEqual(Outcome.attach_zerocopy, r.outcome);
    try std.testing.expectEqual(FallbackReason.features_absent_skip, r.reason);
    try std.testing.expect(!r.fatal);
}

test "no probe result is fatal" {
    const samples = [_]Sample{
        .{},
        .{ .features = capable, .rx_queues = 0, .bind = .failed },
        .{ .features = capable, .rx_queues = 8, .bind = .zerocopy_ok },
    };
    for (samples) |sample| {
        try std.testing.expect(!evaluate(sample).fatal);
    }
}

test "probe sample has no driver or kind fields" {
    const sample = Sample{ .features = capable, .rx_queues = 2, .bind = .zerocopy_ok };
    const r = evaluate(sample);
    try std.testing.expectEqual(Outcome.attach_zerocopy, r.outcome);
    _ = model.abi_version;
}

test "auto mode prefers verified offload then native then skb" {
    const all = selectMode(.auto, .{
        .skb = true,
        .native = true,
        .offload = true,
        .skb_program_ok = true,
        .native_program_ok = true,
        .offload_program_ok = true,
    });
    try std.testing.expectEqual(Mode.offload, all.selected.?);
    const native = selectMode(.auto, .{
        .skb = true,
        .native = true,
        .offload = true,
        .skb_program_ok = true,
        .native_program_ok = true,
        .offload_program_ok = false,
    });
    try std.testing.expectEqual(Mode.native, native.selected.?);
    const skb = selectMode(.auto, .{ .skb = true, .skb_program_ok = true });
    try std.testing.expectEqual(Mode.skb, skb.selected.?);
}

test "explicit mode failure never silently downgrades" {
    const decision = selectMode(.native, .{ .skb = true, .skb_program_ok = true });
    try std.testing.expect(decision.selected == null);
    try std.testing.expectEqual(FallbackReason.bind_failed, decision.reason);
}
