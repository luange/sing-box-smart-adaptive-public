const std = @import("std");
const adaptive = @import("adaptive.zig");

const AdaptiveEngine = struct {
    config: adaptive.Config,
    state: adaptive.State = .{},
};

export fn adaptive_engine_abi_version() u32 {
    return 2;
}

export fn adaptive_engine_create(config: adaptive.Config) ?*AdaptiveEngine {
    const engine = std.heap.page_allocator.create(AdaptiveEngine) catch return null;
    var normalized = config;
    if (!(normalized.switch_margin >= 0) or !isFinite(normalized.switch_margin)) normalized.switch_margin = 0.15;
    if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
    engine.* = .{ .config = normalized };
    return engine;
}

export fn adaptive_engine_configure(engine: ?*AdaptiveEngine, config: adaptive.Config) void {
    if (engine) |value| {
        var normalized = config;
        if (!(normalized.switch_margin >= 0) or !isFinite(normalized.switch_margin)) normalized.switch_margin = 0.15;
        if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
        value.config = normalized;
    }
}

export fn adaptive_engine_destroy(engine: ?*AdaptiveEngine) void {
    if (engine) |value| std.heap.page_allocator.destroy(value);
}

export fn adaptive_engine_choose(engine: ?*AdaptiveEngine, candidates: ?[*]const adaptive.Candidate, count: usize, now_ms: u64) adaptive.Decision {
    if (engine) |value| {
        if (candidates) |pointer| {
            if (count <= adaptive.max_candidates) return adaptive.choose(&value.state, value.config, pointer[0..count], now_ms);
        }
    }
    return .{ .selected_id = 0, .switched = 0, .reason = 5, .score = 0 };
}

export fn adaptive_engine_set_bulk_sequence(engine: ?*AdaptiveEngine, sequence: u64) void {
    if (engine) |value| value.state.bulk_sequence = sequence;
}

export fn adaptive_engine_remember(engine: ?*AdaptiveEngine, id: u64, now_ms: u64, cooldown_ms: u64) void {
    if (engine) |value| {
        value.state.sticky_id = id;
        value.state.sticky_until = if (cooldown_ms > 0) now_ms +| cooldown_ms else 0;
        value.state.selected_id = id;
    }
}

export fn adaptive_engine_forget(engine: ?*AdaptiveEngine) void {
    if (engine) |value| {
        value.state.sticky_id = 0;
        value.state.sticky_until = 0;
    }
}

fn isFinite(value: f64) bool {
    return value == value and value != std.math.inf(f64) and value != -std.math.inf(f64);
}

test "adaptive ABI exposes a live policy engine" {
    try std.testing.expectEqual(@as(u32, 2), adaptive_engine_abi_version());
    const engine = adaptive_engine_create(.{ .switch_margin = 0.15, .switch_cooldown_ms = 0, .mode = 1, .manual_failure = 0 }) orelse return error.OutOfMemory;
    defer adaptive_engine_destroy(engine);
    const candidates = [_]adaptive.Candidate{
        .{ .id = 1, .health_priority = 1, .weighted_delay_ms = 20, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
    };
    const decision = adaptive_engine_choose(engine, &candidates, candidates.len, 0);
    try std.testing.expectEqual(@as(u64, 1), decision.selected_id);
}
