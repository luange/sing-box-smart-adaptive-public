const std = @import("std");
const model = @import("model.zig");
const scoring = @import("scoring.zig");
const metrics = @import("metrics.zig");

pub const State = struct {
    selected_id: u64 = 0,
    // The last primary displaced by a hard failure.  It remains eligible as a
    // backup, but must not preempt the replacement when it recovers.  This is
    // intentionally one ID per business context; a later hard failover
    // replaces it with the primary that just failed.
    deferred_id: u64 = 0,
    challenge_id: u64 = 0,
    challenge_count: u32 = 0,
    challenge_since: u64 = 0,
    cooldown_until: u64 = 0,
    sticky_until: u64 = 0,

    pub fn reset(self: *State) void {
        self.* = .{};
    }
};

pub fn choose(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64) model.Decision {
    return chooseProfile(state, config, observations, candidates, now_ms, .interactive);
}

pub fn chooseProfile(state: *State, config: model.Config, observations: *const metrics.Store, candidates: []const model.Candidate, now_ms: u64, profile: scoring.TrafficProfile) model.Decision {
    // ABI v6 lets the host provide the complete Surge A/B/C order after it has
    // applied registered-domain history, transport capability and URL-test
    // state. In this mode Zig is the sole production decision owner, but it no
    // longer adds an incumbent/challenge/cooldown FSM that Surge does not have.
    var ordered_candidate: ?model.Candidate = null;
    var best_order = std.math.inf(f64);
    for (candidates) |candidate| {
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4) continue;
        if (candidate.candidate_order > 0 and scoring.isFinite(candidate.candidate_order) and candidate.candidate_order < best_order) {
            ordered_candidate = candidate;
            best_order = candidate.candidate_order;
        }
    }
    if (ordered_candidate) |candidate| {
        // In fixed mode the host-provided A/B/C order is only a cold-start
        // and failover order.  It must not override the endpoint that already
        // accepted a real connection: applySurgeOrdering deliberately uses a
        // per-request seed, so returning its first item here would turn every
        // parallel browser asset into a possible node migration.  A hard-open
        // or removed incumbent is intentionally not retained, allowing the
        // ranked backup to take over.
        if (config.selection_mode == model.selection_mode_fixed and state.selected_id != 0) {
            for (candidates) |incumbent| {
                if (incumbent.id == state.selected_id and incumbent.id != 0 and
                    incumbent.eligible != 0 and incumbent.state != 4)
                {
                    return .{
                        .selected_id = incumbent.id,
                        .score = if (scoring.isFinite(incumbent.candidate_order) and incumbent.candidate_order > 0)
                            incumbent.candidate_order
                        else
                            best_order,
                        .switched = 0,
                        .reason = @intFromEnum(model.DecisionReason.retained),
                    };
                }
            }
        }
        return .{
            .selected_id = candidate.id,
            .score = best_order,
            .switched = @intFromBool(state.selected_id != 0 and state.selected_id != candidate.id),
            .reason = @intFromEnum(model.DecisionReason.best),
        };
    }
    const switch_margin = if (config.switch_margin >= 0 and scoring.isFinite(config.switch_margin)) @min(config.switch_margin, 0.95) else 0.0;
    var decision = model.Decision{ .selected_id = 0, .score = 100.0, .switched = 0, .reason = @intFromEnum(model.DecisionReason.no_candidate) };
    var best: ?model.Candidate = null;
    var best_score: f64 = std.math.inf(f64);
    var best_tier: u8 = 255;
    var total_samples: f64 = 0;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4) continue;
        const tier = healthTier(candidate.state);
        if (tier < best_tier) best_tier = tier;
    }
    if (best_tier == 255) return decision;
    // Once a hard failure has promoted a backup, keep the recovered old
    // primary out of the active ranking while the replacement remains usable.
    // If the replacement is gone or no other candidate exists, the deferred
    // endpoint is allowed back in as the only viable recovery path.
    var defer_recovered = false;
    if (state.deferred_id != 0 and state.selected_id != 0) {
        var selected_usable = false;
        var alternative_exists = false;
        for (candidates) |raw_candidate| {
            const candidate = observations.enrich(raw_candidate);
            if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4) continue;
            // A suspect/warming incumbent is still the active primary until
            // it is open.  Recovery of the deferred endpoint must not
            // preempt a usable replacement merely because its tier is lower.
            if (candidate.id == state.selected_id) {
                selected_usable = true;
            }
            if (candidate.id != state.deferred_id) {
                alternative_exists = true;
            }
        }
        defer_recovered = selected_usable and alternative_exists;
    }
    if (defer_recovered) {
        // Recompute the best tier without the deferred endpoint. Otherwise a
        // recovered healthy A could leave no candidate in the selected tier
        // after filtering, or force a lower-tier B through a null result.
        var non_deferred_tier: u8 = 255;
        for (candidates) |raw_candidate| {
            const candidate = observations.enrich(raw_candidate);
            if (candidate.id == 0 or candidate.id == state.deferred_id or candidate.eligible == 0 or candidate.state == 4) continue;
            const tier = healthTier(candidate.state);
            if (tier < non_deferred_tier) non_deferred_tier = tier;
        }
        if (non_deferred_tier != 255) best_tier = non_deferred_tier;
    }
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id != 0 and candidate.eligible != 0 and candidate.state != 4 and
            (!defer_recovered or candidate.id != state.deferred_id) and healthTier(candidate.state) == best_tier)
        {
            if (candidate.samples > 0 and scoring.isFinite(candidate.samples)) {
                total_samples += candidate.samples;
            }
        }
    }
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4 or healthTier(candidate.state) != best_tier) continue;
        if (defer_recovered and candidate.id == state.deferred_id) continue;
        const value = scoring.score(config, candidate, total_samples, profile);
        if (scoring.isFinite(value) and (best == null or value < best_score)) {
            best = candidate;
            best_score = value;
        }
    }
    var selected = best orelse return decision;
    var selected_score = best_score;
    // Spread-mode affinity is seeded by the host; no unbounded string key is
    // retained in the Zig state. Fixed mode skips the dispersion step below
    // and preserves a healthy incumbent.
    var incumbent: ?model.Candidate = null;
    if (state.selected_id != 0) {
        for (candidates) |raw_candidate| {
            const candidate = observations.enrich(raw_candidate);
            if (candidate.id == state.selected_id) {
                incumbent = candidate;
                break;
            }
        }
    }
    // Keep the cold-start primary/backup order until every candidate in the
    // best health tier has the normal confidence floor. Hashing an unobserved
    // catalog would make the first request depend on an arbitrary seed and
    // could select a line that has no evidence yet. Once portraits are ready,
    // Spread mode disperses within the healthy near-tie band.
    const affinity_min_samples: f64 = if (config.min_samples > 0)
        @floatFromInt(config.min_samples)
    else
        3.0;
    var affinity_ready = true;
    for (candidates) |raw_candidate| {
        const candidate = observations.enrich(raw_candidate);
        if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4 or healthTier(candidate.state) != best_tier) continue;
        if (!(candidate.samples >= affinity_min_samples) or !scoring.isFinite(candidate.samples)) {
            affinity_ready = false;
            break;
        }
    }
    // Mode 0 is fixed primary/backup; mode 1 uses the host's A/B/C order
    // with stable same-tier dispersion after the confidence floor is met.
    if (affinity_ready and config.selection_mode == model.selection_mode_spread) {
        const threshold = if (best_score > 0) best_score * (1.0 + switch_margin) else 0.05;
        var retained_incumbent = false;
        if (incumbent) |current| {
            const current_score = scoring.score(config, current, total_samples, profile);
            if (current.id != 0 and current.eligible != 0 and current.state != 4 and
                healthTier(current.state) == best_tier and scoring.isFinite(current_score) and current_score <= threshold)
            {
                retained_incumbent = true;
                selected = current;
                selected_score = current_score;
            }
        }
        if (!retained_incumbent) {
            var selected_hash: u64 = 0;
            var found = false;
            for (candidates) |raw_candidate| {
                const candidate = observations.enrich(raw_candidate);
                if (candidate.id == 0 or candidate.eligible == 0 or candidate.state == 4 or healthTier(candidate.state) != best_tier) continue;
                if (defer_recovered and candidate.id == state.deferred_id) continue;
                const value = scoring.score(config, candidate, total_samples, profile);
                if (!scoring.isFinite(value) or value > threshold) continue;
                const hash = rendezvousHash(config.affinity_seed, candidate.id);
                if (!found or hash > selected_hash) {
                    found = true;
                    selected_hash = hash;
                    selected = candidate;
                    selected_score = value;
                }
            }
        }
    }
    // The host calls set_selected only after a real dial succeeds. Hold a
    // healthy incumbent for the configured window so score noise cannot cause
    // rapid oscillation; a hard-open incumbent still fails over below.
    if (incumbent) |current| {
        if (config.site_stickiness_ms > 0 and now_ms < state.sticky_until and
            current.state != 4 and current.eligible != 0 and healthTier(current.state) == best_tier)
        {
            const current_score = scoring.score(config, current, total_samples, profile);
            if (scoring.isFinite(current_score)) {
                decision.selected_id = current.id;
                decision.score = current_score;
                decision.reason = @intFromEnum(model.DecisionReason.retained);
                return decision;
            }
        }
    }
    decision.selected_id = selected.id;
    decision.score = selected_score;
    // `selected_id` is the last candidate whose dial actually succeeded.  Do
    // not commit a cold-start guess here: the host may still fail the dial and
    // report the observation on the next call.  Committing before that
    // callback would turn an unconnected candidate into the apparent primary
    // and could keep retrying it during a transient failure.
    if (state.selected_id == 0 or state.selected_id == selected.id) {
        decision.reason = @intFromEnum(model.DecisionReason.best);
        return decision;
    }
    if (incumbent) |current| {
        // A hard-open incumbent is unavailable (for example after the host's
        // passive throughput floor trips). Do not wait for performance
        // confirmation or cooldown: the next real connection must fail over.
        if (current.state == 4) {
            state.deferred_id = current.id;
            state.cooldown_until = now_ms +| config.switch_cooldown_ms;
            state.challenge_id = 0;
            state.challenge_count = 0;
            state.challenge_since = 0;
            decision.switched = 1;
            decision.reason = @intFromEnum(model.DecisionReason.confirmed);
            return decision;
        }
        const current_score = scoring.score(config, current, total_samples, profile);
        const improvement = if (current_score > 0) (current_score - selected_score) / current_score else 0;
        if (improvement < switch_margin or
            !absoluteImprovement(selected, current, config.switch_min_improvement_ms) or
            now_ms < state.cooldown_until)
        {
            decision.selected_id = current.id;
            decision.score = current_score;
            decision.reason = @intFromEnum(model.DecisionReason.retained);
            return decision;
        }
    }
    // A provider refresh can remove or rename the incumbent while the engine
    // still carries its previous selected_id.  That is a catalog change, not
    // a performance challenge: retaining an ID which cannot be emitted would
    // make the host fall back on every refresh and could strand the engine in
    // a stale challenge state.  Adopt the best currently eligible candidate
    // immediately and clear all confirmation state.
    if (state.selected_id != 0 and incumbent == null) {
        state.cooldown_until = now_ms +| config.switch_cooldown_ms;
        state.challenge_id = 0;
        state.challenge_count = 0;
        state.challenge_since = 0;
        decision.switched = 1;
        decision.reason = @intFromEnum(model.DecisionReason.confirmed);
        return decision;
    }
    if (state.challenge_id != selected.id or state.challenge_since == 0) {
        state.challenge_id = selected.id;
        state.challenge_count = 1;
        state.challenge_since = now_ms;
        decision.selected_id = state.selected_id;
        decision.reason = @intFromEnum(model.DecisionReason.retained);
        return decision;
    }
    state.challenge_count +|= 1;
    if (state.challenge_count < config.switch_confirm_samples or now_ms -| state.challenge_since < config.switch_confirm_ms) {
        decision.selected_id = state.selected_id;
        decision.reason = @intFromEnum(model.DecisionReason.retained);
        return decision;
    }
    state.cooldown_until = now_ms +| config.switch_cooldown_ms;
    state.challenge_id = 0;
    state.challenge_count = 0;
    state.challenge_since = 0;
    decision.switched = 1;
    decision.reason = @intFromEnum(model.DecisionReason.confirmed);
    return decision;
}

fn absoluteImprovement(best: model.Candidate, current: model.Candidate, minimum_ms: u64) bool {
    if (minimum_ms == 0) return true;
    const best_latency = candidateLatencyMS(best);
    const current_latency = candidateLatencyMS(current);
    if (!(best_latency > 0) or !scoring.isFinite(best_latency) or
        !(current_latency > 0) or !scoring.isFinite(current_latency)) return false;
    return current_latency - best_latency >= @as(f64, @floatFromInt(minimum_ms));
}

fn candidateLatencyMS(candidate: model.Candidate) f64 {
    if (candidate.first_byte_ms > 0 and scoring.isFinite(candidate.first_byte_ms)) return candidate.first_byte_ms;
    if (candidate.connect_ms > 0 and scoring.isFinite(candidate.connect_ms)) return candidate.connect_ms;
    return 0;
}

test "fixed mode retains incumbent over per-request spread order" {
    var state = State{ .selected_id = 1 };
    var observations = metrics.Store{};
    const config = model.Config{
        .exploration = 0,
        .switch_margin = 0.25,
        .switch_confirm_samples = 4,
        .switch_confirm_ms = 300_000,
        .switch_cooldown_ms = 1_200_000,
        .selection_mode = model.selection_mode_fixed,
        .site_stickiness_ms = 3_600_000,
        .switch_min_improvement_ms = 250,
        .min_samples = 3,
    };
    // Candidate 2 is first in the host's per-request order. A fixed
    // Smart context must still keep the already successful candidate 1.
    const candidates = [_]model.Candidate{
        .{ .id = 2, .reliability = 0.99, .connect_ms = 20, .first_byte_ms = 20, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .candidate_order = 1, .state = 1, .eligible = 1 },
        .{ .id = 1, .reliability = 0.99, .connect_ms = 30, .first_byte_ms = 30, .jitter_ms = 1, .throughput_bps = 0, .samples = 4, .weight = 1, .candidate_order = 2, .state = 1, .eligible = 1 },
    };
    const retained = chooseProfile(&state, config, &observations, candidates[0..], 1000, .interactive);
    try std.testing.expectEqual(@as(u64, 1), retained.selected_id);
    try std.testing.expectEqual(@as(u8, 0), retained.switched);

    // A hard-open incumbent is the explicit exception: the ranked backup may
    // take over immediately.
    var failed = candidates;
    failed[1].state = 4;
    const switched = chooseProfile(&state, config, &observations, failed[0..], 2000, .interactive);
    try std.testing.expectEqual(@as(u64, 2), switched.selected_id);
    try std.testing.expectEqual(@as(u8, 1), switched.switched);
}

// splitmix64 gives a stable, cheap rendezvous metric for the pair
// (context-seed, canonical endpoint id).  It intentionally has no process
// randomness: the same service context keeps the same line across reloads,
// while independent contexts spread across the near-tied healthy pool.
fn rendezvousHash(seed: u64, id: u64) u64 {
    var value = seed ^ (id +% 0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

// Health is a hard ordering boundary. Latency and throughput may choose the
// primary inside the best available tier, but a suspect or half-open node must
// never displace a healthy incumbent merely because its current sample is
// faster. Open nodes are excluded before this function is called.
fn healthTier(state: u8) u8 {
    return switch (state) {
        1 => 0, // healthy
        2, 0 => 1, // warming/unknown
        3 => 2, // suspect
        5 => 3, // half-open: usable only for a bounded recovery trial
        4 => 4, // defensive: open is filtered above
        else => 2,
    };
}
