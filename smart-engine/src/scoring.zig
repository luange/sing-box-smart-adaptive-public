const std = @import("std");
const model = @import("model.zig");

pub fn isFinite(value: f64) bool {
    return value == value and value != std.math.inf(f64) and value != -std.math.inf(f64);
}

pub fn normalizedCost(value: f64, ceiling: f64) f64 {
    if (value != value or value == -std.math.inf(f64)) return 0.5;
    if (value == std.math.inf(f64)) return 1.0;
    if (!(value > 0)) return 0.5;
    return std.math.clamp(std.math.log1p(value) / std.math.log1p(ceiling), 0.0, 1.0);
}

fn normalizedReliability(value: f64) f64 {
    // `std.math.clamp` does not turn NaN into a usable value. A malformed
    // foreign-host snapshot must therefore receive the neutral prior instead
    // of poisoning the whole candidate ordering with a NaN score.
    if (!isFinite(value)) return 0.5;
    return std.math.clamp(value, 0.0, 1.0);
}

pub const TrafficProfile = enum(u8) {
    interactive = 0,
    bulk = 1,
    udp = 2,
};

pub fn score(config: model.Config, candidate: model.Candidate, total_samples: f64, profile: TrafficProfile) f64 {
    const sample_count = if (candidate.samples > 0 and isFinite(candidate.samples)) candidate.samples else 0.0;
    const exploration_budget = if (config.exploration > 0 and isFinite(config.exploration)) config.exploration else 0.0;
    const reliability = normalizedReliability(candidate.reliability);
    // The host supplies robust tail-latency values in these fields. Keeping
    // the ABI names stable lets older callers continue to work; callers that
    // only have an EWMA still get the same bounded fallback behavior.
    const connect_cost = normalizedCost(candidate.connect_ms, 5000.0);
    const first_byte_cost = normalizedCost(candidate.first_byte_ms, 10000.0);
    const jitter_cost = if (candidate.connect_ms > 0 and isFinite(candidate.connect_ms) and
        candidate.jitter_ms >= 0 and isFinite(candidate.jitter_ms))
        std.math.clamp(candidate.jitter_ms / 1000.0, 0.0, 1.0)
    else
        0.5;
    const throughput_ceiling: f64 = 64 * 1024 * 1024;
    const throughput_cost = if (candidate.throughput_bps > 0 and isFinite(candidate.throughput_bps))
        1.0 - std.math.clamp(std.math.log1p(candidate.throughput_bps) / std.math.log1p(throughput_ceiling), 0.0, 1.0)
    else
        0.60;
    const exploration = if (sample_count > 0 and total_samples > 0 and isFinite(total_samples))
        exploration_budget * @sqrt(@log(total_samples + 2.0) / (sample_count + 1.0))
    else
        exploration_budget;
    // Divide by weight for ranking, but keep a floor: a near-zero weight must
    // rank that candidate last, not push every score past the sentinel range
    // and make the kernel report "no candidate" for a healthy pool.
    const weight = if (candidate.weight > 0 and isFinite(candidate.weight))
        @max(candidate.weight, 0.01)
    else
        1.0;
    var reliability_weight: f64 = 0.30;
    var connect_weight: f64 = 0.25;
    var first_byte_weight: f64 = 0.30;
    var throughput_weight: f64 = 0;
    var jitter_weight: f64 = 0.10;
    const confidence_weight: f64 = 0.05;
    switch (profile) {
        .bulk => {
            reliability_weight = 0.30;
            connect_weight = 0.15;
            first_byte_weight = 0.20;
            throughput_weight = 0.30;
            jitter_weight = 0.00;
        },
        .udp => {
            reliability_weight = 0.50;
            connect_weight = 0.25;
            first_byte_weight = 0;
            throughput_weight = 0;
            jitter_weight = 0.20;
        },
        .interactive => {},
    }
    const confidence_cost = if (sample_count < 3.0) 1.0 - sample_count / 3.0 else 0.0;
    var base = reliability_weight * (1.0 - reliability) + connect_weight * connect_cost + first_byte_weight * first_byte_cost + throughput_weight * throughput_cost + jitter_weight * jitter_cost + confidence_weight * confidence_cost;
    // Match the host's recovery semantics: half-open candidates are usable
    // only as bounded trials and must not outrank a healthy incumbent merely
    // because their first retry was fast.
    if (candidate.state == 5) base += 0.20;
    return @max(0.0, base - exploration) / weight;
}

test "non-finite reliability uses a neutral score component" {
    const config = model.Config{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 };
    var candidate = model.Candidate{ .id = 1, .reliability = 0.5, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .state = 1, .eligible = 1 };
    const neutral = score(config, candidate, 4, .interactive);
    candidate.reliability = std.math.nan(f64);
    try std.testing.expectEqual(neutral, score(config, candidate, 4, .interactive));
}

test "non-finite sample counts use the unknown confidence prior" {
    const config = model.Config{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 };
    var candidate = model.Candidate{ .id = 1, .reliability = 0.5, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 0, .weight = 1, .state = 1, .eligible = 1 };
    const unknown = score(config, candidate, 0, .interactive);
    candidate.samples = std.math.nan(f64);
    try std.testing.expectEqual(unknown, score(config, candidate, 0, .interactive));
    candidate.samples = -4;
    try std.testing.expectEqual(unknown, score(config, candidate, 0, .interactive));
}

test "near-zero weight ranks last instead of overflowing the score sentinel" {
    const config = model.Config{ .exploration = 0, .switch_margin = 0, .switch_confirm_samples = 1, .switch_confirm_ms = 0, .switch_cooldown_ms = 0 };
    var candidate = model.Candidate{ .id = 1, .reliability = 0.5, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1e-9, .state = 1, .eligible = 1 };
    const tiny = score(config, candidate, 4, .interactive);
    try std.testing.expect(tiny < 100.0);
    candidate.weight = 1.0;
    const normal = score(config, candidate, 4, .interactive);
    try std.testing.expect(tiny > normal);
}
