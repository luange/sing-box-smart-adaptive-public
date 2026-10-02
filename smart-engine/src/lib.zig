const std = @import("std");
const model = @import("model.zig");
const metrics = @import("metrics.zig");
const policy = @import("policy.zig");
const scoring = @import("scoring.zig");
const adaptive = @import("adaptive.zig");

const max_candidates = 8192;

fn isFinite(value: f64) bool {
    return value == value and value != std.math.inf(f64) and value != -std.math.inf(f64);
}

pub const Candidate = model.Candidate;
pub const Config = model.Config;
pub const Decision = model.Decision;

const Engine = struct {
    config: Config,
    observations: metrics.Store = .{},
    state: policy.State = .{},

    fn init(config: Config) Engine {
        var normalized = config;
        if (!(normalized.exploration >= 0) or !isFinite(normalized.exploration)) normalized.exploration = 0;
        if (!(normalized.switch_margin >= 0) or !isFinite(normalized.switch_margin)) normalized.switch_margin = 0;
        if (normalized.switch_margin > 0.95) normalized.switch_margin = 0.95;
        if (normalized.switch_confirm_samples == 0) normalized.switch_confirm_samples = 1;
        if (normalized.selection_mode > model.selection_mode_spread) normalized.selection_mode = model.selection_mode_spread;
        if (normalized.min_samples == 0) normalized.min_samples = 3;
        return .{ .config = normalized };
    }

    fn reset(self: *Engine) void {
        self.observations.reset();
        self.state.reset();
    }

    fn observe(self: *Engine, id: u64, success: bool, elapsed_ms: f64, now_ms: u64) void {
        self.observations.observe(id, success, elapsed_ms, now_ms);
    }
};

export fn smart_engine_create(config: Config) ?*Engine {
    const engine = std.heap.page_allocator.create(Engine) catch return null;
    engine.* = Engine.init(config);
    return engine;
}

export fn smart_engine_abi_version() u32 {
    return 6;
}

export fn smart_engine_destroy(engine: ?*Engine) void {
    if (engine) |value| {
        value.reset();
        std.heap.page_allocator.destroy(value);
    }
}

export fn smart_engine_observe(engine: ?*Engine, id: u64, success: u8, elapsed_ms: f64, now_ms: u64) void {
    if (engine) |value| value.observe(id, success != 0, elapsed_ms, now_ms);
}

export fn smart_engine_choose(engine: ?*Engine, candidates: ?[*]const Candidate, count: usize, now_ms: u64) Decision {
    if (engine) |value| {
        if (count > max_candidates) return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
        if (candidates) |pointer| return policy.choose(&value.state, value.config, &value.observations, pointer[0..count], now_ms);
    }
    return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
}

export fn smart_engine_choose_profile(engine: ?*Engine, candidates: ?[*]const Candidate, count: usize, now_ms: u64, profile: u8) Decision {
    if (engine) |value| {
        if (count > max_candidates) return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
        if (candidates) |pointer| {
            const selected_profile: scoring.TrafficProfile = switch (profile) {
                1 => .bulk,
                2 => .udp,
                else => .interactive,
            };
            return policy.chooseProfile(&value.state, value.config, &value.observations, pointer[0..count], now_ms, selected_profile);
        }
    }
    return .{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = 3 };
}

// The host owns the actual dial result. Synchronize that incumbent into the
// policy FSM after a successful selection so a cold policy engine does not
// mistake the first ranking snapshot for a confirmed performance switch.
export fn smart_engine_set_selected(engine: ?*Engine, id: u64, now_ms: u64) void {
    if (engine) |value| {
        if (id == 0) return;
        value.state.selected_id = id;
        if (value.state.deferred_id == id) value.state.deferred_id = 0;
        value.state.challenge_id = 0;
        value.state.challenge_count = 0;
        value.state.challenge_since = 0;
        value.state.sticky_until = if (value.config.site_stickiness_ms > 0)
            now_ms +| value.config.site_stickiness_ms
        else
            0;
    }
}

// Seed a newly-created context from the host's last confirmed dial without
// overriding a decision that is already in flight.  Context engines are
// intentionally bounded and may be evicted under provider churn; restoring
// only an empty state prevents that maintenance event from looking like a
// healthy performance switch while keeping the host as the source of truth
// for successful dials.
export fn smart_engine_adopt_selected(engine: ?*Engine, id: u64, now_ms: u64) void {
    if (engine) |value| {
        if (id == 0 or value.state.selected_id != 0) return;
        value.state.selected_id = id;
        if (value.state.deferred_id == id) value.state.deferred_id = 0;
        value.state.challenge_id = 0;
        value.state.challenge_count = 0;
        value.state.challenge_since = 0;
        value.state.sticky_until = if (value.config.site_stickiness_ms > 0)
            now_ms +| value.config.site_stickiness_ms
        else
            0;
    }
}

export fn smart_engine_prune(engine: ?*Engine, ids: ?[*]const u64, count: usize) void {
    if (engine) |value| {
        // The host must never hand the bounded kernel an untrusted span. A
        // malformed provider snapshot is handled as a cold reset rather than
        // allowing pointer arithmetic in the FFI boundary to escape memory.
        if (count > max_candidates or (count != 0 and ids == null)) {
            value.reset();
            return;
        }
        if (count == 0) {
            value.observations.prune(&[_]u64{});
        } else if (ids) |pointer| {
            value.observations.prune(pointer[0..count]);
        }
        if (value.state.selected_id != 0) {
            var retained = false;
            if (ids) |pointer| {
                for (pointer[0..count]) |id| {
                    if (id == value.state.selected_id) {
                        retained = true;
                        break;
                    }
                }
            }
            if (!retained) value.state.reset();
        }
    }
}

export fn smart_engine_reset(engine: ?*Engine) void {
    if (engine) |value| value.reset();
}

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

test "retains incumbent until confirmation" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.05, .switch_confirm_samples = 2, .switch_confirm_ms = 1000, .switch_cooldown_ms = 2000 });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.9, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
    };
    try std.testing.expectEqual(@as(u64, 1), policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..1], 0).selected_id);
    // The policy result is only a proposal. The host commits the incumbent
    // after the real dial succeeds.
    engine.state.selected_id = 1;
    try std.testing.expectEqual(@as(u8, 0), policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 1000).switched);
    try std.testing.expectEqual(@as(u8, 1), policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 2000).switched);
}

test "spread host order replaces incumbent confirmation FSM in spread mode" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.95, .switch_confirm_samples = 10, .switch_confirm_ms = 60000, .switch_cooldown_ms = 60000, .selection_mode = model.selection_mode_spread });
    engine.state.selected_id = 1;
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 1, .connect_ms = 10, .first_byte_ms = 10, .jitter_ms = 0, .throughput_bps = 0, .samples = 4, .weight = 1, .candidate_order = 2, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 1, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 0, .throughput_bps = 0, .samples = 4, .weight = 1, .candidate_order = 1, .state = 1, .eligible = 1 },
    };
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 1000);
    try std.testing.expectEqual(@as(u64, 2), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
}

test "spread is the default selection mode" {
    const engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0.15,
        .switch_confirm_samples = 2,
        .switch_confirm_ms = 1000,
        .switch_cooldown_ms = 2000,
    });
    try std.testing.expectEqual(model.selection_mode_spread, engine.config.selection_mode);
}

test "ABI configuration rejects non-finite limits" {
    const smart = Engine.init(.{
        .exploration = std.math.inf(f64),
        .switch_margin = -std.math.inf(f64),
        .switch_confirm_samples = 0,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .selection_mode = 99,
    });
    try std.testing.expectEqual(@as(f64, 0), smart.config.exploration);
    try std.testing.expectEqual(@as(f64, 0), smart.config.switch_margin);
    try std.testing.expectEqual(@as(u32, 1), smart.config.switch_confirm_samples);
    try std.testing.expectEqual(model.selection_mode_spread, smart.config.selection_mode);
    try std.testing.expectEqual(@as(u32, 3), smart.config.min_samples);

    const custom = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .min_samples = 7,
    });
    try std.testing.expectEqual(@as(u32, 7), custom.config.min_samples);

    const adaptive_engine = adaptive_engine_create(.{
        .switch_margin = std.math.inf(f64),
        .switch_cooldown_ms = 0,
        .mode = 1,
        .manual_failure = 0,
    }) orelse return error.OutOfMemory;
    defer adaptive_engine_destroy(adaptive_engine);
    try std.testing.expectEqual(@as(f64, 0.15), adaptive_engine.config.switch_margin);
}

test "hard-open incumbent fails over without confirmation" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.95, .switch_confirm_samples = 3, .switch_confirm_ms = 60000, .switch_cooldown_ms = 2000 });
    const incumbent = Candidate{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    const fallback = Candidate{ .id = 2, .reliability = 0.30, .connect_ms = 500, .first_byte_ms = 500, .jitter_ms = 10, .throughput_bps = 0, .samples = 1, .weight = 1, .state = 1, .eligible = 1 };
    const initial = [_]Candidate{incumbent};
    _ = policy.chooseProfile(&engine.state, engine.config, &engine.observations, initial[0..], 0, .bulk);
    engine.state.selected_id = 1;
    const opened = [_]Candidate{ .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 4, .eligible = 1 }, fallback };
    const decision = policy.chooseProfile(&engine.state, engine.config, &engine.observations, opened[0..], 1, .bulk);
    try std.testing.expectEqual(@as(u64, 2), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
}

test "policy proposal is not committed before host dial succeeds" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
    });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 },
    };
    const proposal = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 0);
    try std.testing.expectEqual(@as(u64, 2), proposal.selected_id);
    try std.testing.expectEqual(@as(u64, 0), engine.state.selected_id);
}

test "confirmed switch remains pending until host commits it" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
    });
    engine.state.selected_id = 1;
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.80, .connect_ms = 200, .first_byte_ms = 200, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
    };
    const pending = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 1);
    try std.testing.expectEqual(@as(u64, 1), pending.selected_id);
    try std.testing.expectEqual(@as(u8, 0), pending.switched);
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 2);
    try std.testing.expectEqual(@as(u64, 2), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
    try std.testing.expectEqual(@as(u64, 1), engine.state.selected_id);
}

test "failed primary stays deferred after recovery until replacement fails" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
    });
    engine.state.selected_id = 1;
    const failed = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 4, .eligible = 1 },
        .{ .id = 2, .reliability = 0.85, .connect_ms = 80, .first_byte_ms = 80, .jitter_ms = 2, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
    };
    const failover = policy.choose(&engine.state, engine.config, &engine.observations, failed[0..], 1);
    try std.testing.expectEqual(@as(u64, 2), failover.selected_id);
    try std.testing.expectEqual(@as(u8, 1), failover.switched);
    try std.testing.expectEqual(@as(u64, 1), engine.state.deferred_id);

    // The host has now completed the B dial. A is healthy again but must not
    // preempt B simply because it has a lower latency.
    engine.state.selected_id = 2;
    const recovered = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.85, .connect_ms = 80, .first_byte_ms = 80, .jitter_ms = 2, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
    };
    const retained = policy.choose(&engine.state, engine.config, &engine.observations, recovered[0..], 2);
    try std.testing.expectEqual(@as(u64, 2), retained.selected_id);
    try std.testing.expectEqual(@as(u8, 0), retained.switched);

    // Even a still-usable suspect replacement remains the primary. The
    // deferred endpoint is not allowed to reclaim it until it reaches open.
    const suspect_replacement = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.85, .connect_ms = 80, .first_byte_ms = 80, .jitter_ms = 2, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 3, .eligible = 1 },
    };
    const suspect_retained = policy.choose(&engine.state, engine.config, &engine.observations, suspect_replacement[0..], 3);
    try std.testing.expectEqual(@as(u64, 2), suspect_retained.selected_id);
    try std.testing.expectEqual(@as(u8, 0), suspect_retained.switched);

    // Only when B fails may the recovered A take over. The failed B becomes
    // the new deferred backup marker, so a later recovery of B cannot reclaim
    // the primary slot without another hard failure.
    const replacement_failed = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.85, .connect_ms = 80, .first_byte_ms = 80, .jitter_ms = 2, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 4, .eligible = 1 },
    };
    const promoted = policy.choose(&engine.state, engine.config, &engine.observations, replacement_failed[0..], 4);
    try std.testing.expectEqual(@as(u64, 1), promoted.selected_id);
    try std.testing.expectEqual(@as(u8, 1), promoted.switched);
    try std.testing.expectEqual(@as(u64, 2), engine.state.deferred_id);
    smart_engine_set_selected(&engine, 1, 4);
    try std.testing.expectEqual(@as(u64, 1), engine.state.selected_id);
    try std.testing.expectEqual(@as(u64, 2), engine.state.deferred_id);
}

test "healthy tier wins over faster suspect candidate" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 800, .first_byte_ms = 800, .jitter_ms = 10, .throughput_bps = 0, .samples = 12, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.65, .connect_ms = 10, .first_byte_ms = 10, .jitter_ms = 1, .throughput_bps = 0, .samples = 12, .weight = 1, .state = 3, .eligible = 1 },
    };
    const decision = policy.chooseProfile(&engine.state, engine.config, &engine.observations, candidates[0..], 0, .interactive);
    try std.testing.expectEqual(@as(u64, 1), decision.selected_id);
}

test "spread selection is stable and health bounded" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0.20,
        .switch_confirm_samples = 2,
        .switch_confirm_ms = 1000,
        .switch_cooldown_ms = 2000,
        .affinity_seed = 0x1234,
        .selection_mode = model.selection_mode_spread,
    });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.99, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 2, .reliability = 0.98, .connect_ms = 21, .first_byte_ms = 21, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
    };
    const first = policy.chooseProfile(&engine.state, engine.config, &engine.observations, candidates[0..], 0, .interactive);
    const second = policy.chooseProfile(&engine.state, engine.config, &engine.observations, candidates[0..], 1, .interactive);
    try std.testing.expect(first.selected_id == 1 or first.selected_id == 2);
    try std.testing.expectEqual(first.selected_id, second.selected_id);

    var health_engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0.20,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .affinity_seed = 0x5678,
        .selection_mode = model.selection_mode_spread,
    });
    const health_bounded = [_]Candidate{
        .{ .id = 11, .reliability = 0.90, .connect_ms = 500, .first_byte_ms = 500, .jitter_ms = 10, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 12, .reliability = 0.99, .connect_ms = 1, .first_byte_ms = 1, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 3, .eligible = 1 },
    };
    const bounded = policy.chooseProfile(&health_engine.state, health_engine.config, &health_engine.observations, health_bounded[0..], 0, .interactive);
    try std.testing.expectEqual(@as(u64, 11), bounded.selected_id);
}

test "fixed and spread modes differ" {
    const candidates = [_]Candidate{
        .{ .id = 21, .reliability = 0.99, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
        .{ .id = 22, .reliability = 0.98, .connect_ms = 21, .first_byte_ms = 21, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 },
    };
    var primary_backup = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0.20,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .affinity_seed = 0x99,
        .selection_mode = model.selection_mode_fixed,
    });
    var spread = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0.20,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .affinity_seed = 0x99,
        .selection_mode = model.selection_mode_spread,
    });
    const old_value = policy.choose(&primary_backup.state, primary_backup.config, &primary_backup.observations, candidates[0..], 0);
    const new_value = policy.choose(&spread.state, spread.config, &spread.observations, candidates[0..], 0);
    try std.testing.expectEqual(@as(u64, 21), old_value.selected_id);
    try std.testing.expectEqual(@as(u64, 22), new_value.selected_id);
}

test "site stickiness retains a healthy incumbent until expiry" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .site_stickiness_ms = 60000,
    });
    const incumbent = Candidate{ .id = 1, .reliability = 0.90, .connect_ms = 500, .first_byte_ms = 500, .jitter_ms = 10, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 };
    const better = Candidate{ .id = 2, .reliability = 0.99, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 };
    const initial = [_]Candidate{incumbent};
    _ = policy.choose(&engine.state, engine.config, &engine.observations, initial[0..], 1);
    // This mirrors the host callback after the first real dial succeeds.
    engine.state.selected_id = 1;
    engine.state.sticky_until = 60001;
    const candidates = [_]Candidate{ incumbent, better };
    const retained = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 60000);
    try std.testing.expectEqual(@as(u64, 1), retained.selected_id);
    try std.testing.expectEqual(@as(u8, 0), retained.switched);
    const pending = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 60001);
    try std.testing.expectEqual(@as(u64, 1), pending.selected_id);
    const switched = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 60002);
    try std.testing.expectEqual(@as(u64, 2), switched.selected_id);
    try std.testing.expectEqual(@as(u8, 1), switched.switched);
}

test "minimum latency improvement is enforced before switching" {
    var engine = Engine.init(.{
        .exploration = 0,
        .switch_margin = 0,
        .switch_confirm_samples = 1,
        .switch_confirm_ms = 0,
        .switch_cooldown_ms = 0,
        .switch_min_improvement_ms = 100,
    });
    const incumbent = Candidate{ .id = 1, .reliability = 0.99, .connect_ms = 200, .first_byte_ms = 200, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 };
    const small_gain = Candidate{ .id = 2, .reliability = 0.99, .connect_ms = 150, .first_byte_ms = 150, .jitter_ms = 1, .throughput_bps = 0, .samples = 8, .weight = 1, .state = 1, .eligible = 1 };
    const initial = [_]Candidate{incumbent};
    _ = policy.choose(&engine.state, engine.config, &engine.observations, initial[0..], 1);
    engine.state.selected_id = 1;
    const candidates = [_]Candidate{ incumbent, small_gain };
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, candidates[0..], 2);
    try std.testing.expectEqual(@as(u64, 1), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 0), decision.switched);
}

test "suspect remains ahead of half-open during recovery" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    const candidates = [_]Candidate{
        .{ .id = 1, .reliability = 0.80, .connect_ms = 30, .first_byte_ms = 30, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 3, .eligible = 1 },
        .{ .id = 2, .reliability = 0.99, .connect_ms = 1, .first_byte_ms = 1, .jitter_ms = 1, .throughput_bps = 0, .samples = 10, .weight = 1, .state = 5, .eligible = 1 },
    };
    const decision = policy.chooseProfile(&engine.state, engine.config, &engine.observations, candidates[0..], 0, .interactive);
    try std.testing.expectEqual(@as(u64, 1), decision.selected_id);
}

test "removed incumbent is replaced immediately after provider refresh" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0.95, .switch_confirm_samples = 3, .switch_confirm_ms = 60000, .switch_cooldown_ms = 2000 });
    const initial = [_]Candidate{.{
        .id = 11,
        .reliability = 0.99,
        .connect_ms = 5,
        .first_byte_ms = 5,
        .jitter_ms = 1,
        .throughput_bps = 0,
        .samples = 10,
        .weight = 1,
        .state = 1,
        .eligible = 1,
    }};
    _ = policy.choose(&engine.state, engine.config, &engine.observations, initial[0..], 0);
    engine.state.selected_id = 11;

    // The provider has replaced the old endpoint ID.  The new candidate is
    // deliberately much worse so a performance-based switch would normally
    // wait for confirmation; catalog removal must still fail over now.
    const refreshed = [_]Candidate{.{
        .id = 22,
        .reliability = 0.30,
        .connect_ms = 500,
        .first_byte_ms = 500,
        .jitter_ms = 10,
        .throughput_bps = 0,
        .samples = 1,
        .weight = 1,
        .state = 1,
        .eligible = 1,
    }};
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, refreshed[0..], 1);
    try std.testing.expectEqual(@as(u64, 22), decision.selected_id);
    try std.testing.expectEqual(@as(u8, 1), decision.switched);
    try std.testing.expectEqual(@as(u8, @intFromEnum(model.DecisionReason.confirmed)), decision.reason);
}

test "bounded observations do not grow after reset" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    var id: u64 = 1;
    while (id <= metrics.max_entries + 1) : (id += 1) engine.observe(id, true, 1, id);
    try std.testing.expectEqual(metrics.max_entries, engine.observations.count);
    engine.reset();
    try std.testing.expectEqual(@as(usize, 0), engine.observations.count);
}

test "hashed observations evict the oldest entry and remain addressable" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    var id: u64 = 1;
    while (id <= metrics.max_entries) : (id += 1) engine.observe(id, true, 1, id);
    // The first entry is the oldest and must be replaced on the next insert.
    engine.observe(metrics.max_entries + 1, true, 2, metrics.max_entries + 1);
    try std.testing.expect(engine.observations.get(1) == null);
    try std.testing.expect(engine.observations.get(2048) != null);
    try std.testing.expect(engine.observations.get(metrics.max_entries + 1) != null);
    try std.testing.expectEqual(metrics.max_entries, engine.observations.count);

    // Cross the tombstone rebuild threshold and verify that reusing a metric
    // slot never leaves the evicted id pointing at the replacement entry.
    var churn: u64 = 0;
    while (churn < 2100) : (churn += 1) {
        engine.observe(metrics.max_entries + 2 + churn, true, 3, metrics.max_entries + 2 + churn);
    }
    try std.testing.expect(engine.observations.get(2) == null);
    try std.testing.expect(engine.observations.get(metrics.max_entries + 2101) != null);
}

test "observations fill missing candidate evidence" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    engine.observe(7, true, 10, 1);
    engine.observe(7, true, 12, 2);
    engine.observe(7, false, 0, 3);
    const candidates = [_]Candidate{.{
        .id = 7,
        .reliability = 0,
        .connect_ms = 0,
        .first_byte_ms = 0,
        .jitter_ms = 0,
        .throughput_bps = 0,
        .samples = 0,
        .weight = 1,
        .state = 1,
        .eligible = 1,
    }};
    const decision = policy.choose(&engine.state, engine.config, &engine.observations, &candidates, 4);
    try std.testing.expectEqual(@as(u64, 7), decision.selected_id);
}

test "profile scoring changes only the intended objective" {
    const config = Config{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 };
    const slow = Candidate{ .id = 1, .reliability = 0.98, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 1_000_000, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    const fast = Candidate{ .id = 2, .reliability = 0.98, .connect_ms = 5, .first_byte_ms = 5, .jitter_ms = 1, .throughput_bps = 100_000_000, .samples = 10, .weight = 1, .state = 1, .eligible = 1 };
    try std.testing.expect(scoring.score(config, fast, 20, .bulk) < scoring.score(config, slow, 20, .bulk));
    try std.testing.expectEqual(scoring.score(config, fast, 20, .interactive), scoring.score(config, slow, 20, .interactive));
}

test "prune keeps only listed ids and resets state exactly once" {
    var engine = Engine.init(.{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 });
    var id: u64 = 1;
    while (id <= 100) : (id += 1) engine.observe(id, true, 1, id);
    var keep: [10]u64 = undefined;
    for (&keep, 0..) |*slot, index| slot.* = @intCast((index + 1) * 10);
    engine.observations.prune(&keep);
    try std.testing.expectEqual(@as(usize, 10), engine.observations.count);
    for (keep) |kept_id| try std.testing.expect(engine.observations.get(kept_id) != null);
    try std.testing.expect(engine.observations.get(1) == null);
    try std.testing.expect(engine.observations.get(99) == null);

    // The full prune path (empty keep list) must wipe everything, matching
    // smart_engine_prune(engine, null, 0).
    engine.observations.prune(&[_]u64{});
    try std.testing.expectEqual(@as(usize, 0), engine.observations.count);
    try std.testing.expect(engine.observations.get(10) == null);
}
