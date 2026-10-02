const std = @import("std");

pub const max_candidates = 8192;

pub const Candidate = extern struct {
    id: u64,
    sort_key_hi: u64 = 0,
    sort_key_lo: u64 = 0,
    health_priority: i32,
    weighted_delay_ms: f64,
    throughput_bps: f64,
    throughput_samples: f64,
    supported: u8,
    eligible: u8,
    pinned: u8,
    leased: u8,
};

pub const Config = extern struct {
    switch_margin: f64,
    switch_cooldown_ms: u64,
    mode: u8, // 0 strict-affinity, 1 adaptive, 2 latency, 3 bulk, 4 manual
    manual_failure: u8, // 0 fallback, 1 fail-closed
};

pub const State = extern struct {
    selected_id: u64 = 0,
    sticky_id: u64 = 0,
    sticky_until: u64 = 0,
    bulk_sequence: u64 = 0,
    // Reused ordering scratch for bulk rotation.  It is bounded by the same
    // candidate limit as the ABI, so a hostile catalog cannot grow kernel
    // state or allocate on every decision.
    bulk_order: [max_candidates]u32 = [_]u32{0} ** max_candidates,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub const Decision = extern struct {
    selected_id: u64,
    switched: u8,
    reason: u8, // ADAPTIVE_REASON_*: 0 ranked, 1 retained, 2 lease, 3 manual,
    // 4 fallback, 5 no candidate, 6 bulk spread, 7 bulk throughput, 8 cooldown
    score: f64,
};

fn isFinite(value: f64) bool {
    return value == value and value != std.math.inf(f64) and value != -std.math.inf(f64);
}

fn normalizedDelay(value: f64) f64 {
    // A foreign caller can provide NaN/Inf through the C ABI. Treat those as
    // unknown latency, matching the existing <= 0 unknown ordering, instead
    // of making the insertion comparator non-transitive.
    if (!isFinite(value)) return 0;
    return value;
}

fn better(left: Candidate, right: Candidate, mode: u8) bool {
    if (left.health_priority != right.health_priority) return left.health_priority < right.health_priority;
    if (mode == 3) {
        const left_known = left.throughput_samples >= 2 and isFinite(left.throughput_samples) and
            left.throughput_bps > 0 and isFinite(left.throughput_bps);
        const right_known = right.throughput_samples >= 2 and isFinite(right.throughput_samples) and
            right.throughput_bps > 0 and isFinite(right.throughput_bps);
        if (left_known != right_known) return left_known;
        if (left_known and left.throughput_bps != right.throughput_bps) return left.throughput_bps > right.throughput_bps;
    }
    const left_delay = normalizedDelay(left.weighted_delay_ms);
    const right_delay = normalizedDelay(right.weighted_delay_ms);
    if (left_delay != right_delay) {
        if (left_delay <= 0) return false;
        if (right_delay <= 0) return true;
        return left_delay < right_delay;
    }
    if (left.sort_key_hi != right.sort_key_hi) return left.sort_key_hi < right.sort_key_hi;
    if (left.sort_key_lo != right.sort_key_lo) return left.sort_key_lo < right.sort_key_lo;
    return left.id < right.id;
}

fn findByID(candidates: []const Candidate, id: u64) ?Candidate {
    if (id == 0) return null;
    for (candidates) |candidate| {
        if (candidate.id == id) return candidate;
    }
    return null;
}

fn buildOrder(state: *State, candidates: []const Candidate, mode: u8) usize {
    var length: usize = 0;
    for (candidates, 0..) |candidate, index| {
        if (candidate.eligible == 0) continue;
        var position = length;
        while (position > 0) {
            const previous_index = state.bulk_order[position - 1];
            if (!better(candidate, candidates[previous_index], mode)) break;
            state.bulk_order[position] = previous_index;
            position -= 1;
        }
        state.bulk_order[position] = @intCast(index);
        length += 1;
    }
    return length;
}

pub fn choose(state: *State, config: Config, candidates: []const Candidate, now_ms: u64) Decision {
    if (candidates.len == 0 or candidates.len > max_candidates) return .{ .selected_id = 0, .switched = 0, .reason = 5, .score = 0 };

    var selected: ?Candidate = null;
    for (candidates) |candidate| {
        if (candidate.pinned != 0 and candidate.eligible != 0) {
            selected = candidate;
            break;
        }
    }
    var reason: u8 = 0;
    if (selected != null) {
        reason = 3;
    } else {
        for (candidates) |candidate| {
            if (config.mode != 3 and candidate.leased != 0 and candidate.eligible != 0) {
                selected = candidate;
                reason = 2;
                break;
            }
        }
    }
    if (selected == null and config.mode == 3) {
        const ordered = buildOrder(state, candidates, config.mode);
        if (ordered > 0) {
            var trusted = false;
            for (candidates) |candidate| {
                if (candidate.eligible != 0 and isFinite(candidate.throughput_samples) and candidate.throughput_samples >= 2 and
                    isFinite(candidate.throughput_bps) and candidate.throughput_bps > 0) {
                    trusted = true;
                    break;
                }
            }
            var offset: usize = 0;
            if (trusted) {
                if (state.bulk_sequence % 5 == 0) {
                    offset = @intCast((state.bulk_sequence / 5) % ordered);
                    reason = 6; // periodic spread/exploration
                } else {
                    reason = 7; // trusted throughput exploitation
                }
            } else {
                if (state.bulk_sequence > 0) offset = @intCast((state.bulk_sequence - 1) % ordered);
                reason = 6;
            }
            selected = candidates[state.bulk_order[offset]];
        }
    }
    if (selected == null) {
        for (candidates) |candidate| {
            if (candidate.eligible == 0) continue;
            if (selected == null or better(candidate, selected.?, config.mode)) selected = candidate;
        }
    }
    if (selected == null) {
        // Cold start / total outage: permit one supported candidate for the
        // host's bounded warming fallback unless manual mode is fail-closed.
        if (config.manual_failure == 0) {
            for (candidates) |candidate| {
                if (candidate.supported != 0) {
                    selected = candidate;
                    reason = 4;
                    break;
                }
            }
        }
    }
    if (selected == null) return .{ .selected_id = 0, .switched = 0, .reason = 5, .score = 0 };

    // Keep the incumbent during cooldown or until the challenger is clearly
    // better. A hard-unavailable incumbent is never retained.
    if ((config.mode == 0 or config.mode == 1) and reason == 0 and state.sticky_id != 0) {
        if (findByID(candidates, state.sticky_id)) |incumbent| {
            if (incumbent.eligible != 0 and incumbent.pinned == 0 and incumbent.leased == 0) {
                const challenger = selected.?;
                if (challenger.id != incumbent.id) {
                    const cooldown = state.sticky_until != 0 and now_ms < state.sticky_until;
                    var keep = cooldown;
                    if (!keep and challenger.health_priority == incumbent.health_priority) {
                        const margin = std.math.clamp(config.switch_margin, 0.0, 0.95);
                        if (isFinite(incumbent.weighted_delay_ms) and incumbent.weighted_delay_ms > 0 and
                            isFinite(challenger.weighted_delay_ms) and challenger.weighted_delay_ms > 0) {
                            keep = challenger.weighted_delay_ms > incumbent.weighted_delay_ms * (1.0 - margin);
                        }
                    }
                    if (keep) {
                        selected = incumbent;
                        reason = if (cooldown) 8 else 1;
                    }
                }
            }
        }
    }

    const previous = state.selected_id;
    const switched: u8 = if (previous != 0 and previous != selected.?.id) 1 else 0;
    state.selected_id = selected.?.id;
    if (state.sticky_id != selected.?.id) {
        state.sticky_id = selected.?.id;
        state.sticky_until = if (config.switch_cooldown_ms > 0) now_ms +| config.switch_cooldown_ms else 0;
    }
    const delay_score = normalizedDelay(selected.?.weighted_delay_ms);
    const score = @as(f64, @floatFromInt(@max(selected.?.health_priority, 0))) * 1_000_000_000_000.0 + @max(delay_score, 0);
    return .{ .selected_id = selected.?.id, .switched = switched, .reason = reason, .score = score };
}

test "adaptive kernel honors pin and lease before ranking" {
    var state = State{};
    const config = Config{ .switch_margin = 0.15, .switch_cooldown_ms = 1000, .mode = 1, .manual_failure = 0 };
    const candidates = [_]Candidate{
        .{ .id = 1, .health_priority = 0, .weighted_delay_ms = 20, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
        .{ .id = 2, .health_priority = 1, .weighted_delay_ms = 100, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 1 },
        .{ .id = 3, .health_priority = 2, .weighted_delay_ms = 200, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 1, .leased = 0 },
    };
    try std.testing.expectEqual(@as(u64, 3), choose(&state, config, candidates[0..], 0).selected_id);
    const no_pin = [_]Candidate{ candidates[0], candidates[1] };
    try std.testing.expectEqual(@as(u64, 2), choose(&state, config, no_pin[0..], 1).selected_id);
}

test "adaptive kernel keeps sticky incumbent within margin" {
    var state = State{};
    const config = Config{ .switch_margin = 0.15, .switch_cooldown_ms = 0, .mode = 1, .manual_failure = 0 };
    const first = [_]Candidate{.{ .id = 1, .health_priority = 0, .weighted_delay_ms = 100, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 }};
    _ = choose(&state, config, first[0..], 0);
    const close = [_]Candidate{
        .{ .id = 1, .health_priority = 0, .weighted_delay_ms = 100, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
        .{ .id = 2, .health_priority = 0, .weighted_delay_ms = 90, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
    };
    try std.testing.expectEqual(@as(u64, 1), choose(&state, config, close[0..], 1).selected_id);
}

test "adaptive kernel treats non-finite delay as unknown" {
    var state = State{};
    const config = Config{ .switch_margin = 0, .switch_cooldown_ms = 0, .mode = 2, .manual_failure = 0 };
    const candidates = [_]Candidate{
        .{ .id = 1, .health_priority = 0, .weighted_delay_ms = std.math.nan(f64), .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
        .{ .id = 2, .health_priority = 0, .weighted_delay_ms = 25, .throughput_bps = 0, .throughput_samples = 0, .supported = 1, .eligible = 1, .pinned = 0, .leased = 0 },
    };
    try std.testing.expectEqual(@as(u64, 2), choose(&state, config, candidates[0..], 0).selected_id);
}
