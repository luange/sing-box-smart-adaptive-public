const std = @import("std");

pub const max_entries = 4096;
// Keep the metric payload bounded at max_entries while giving the lookup
// index enough headroom for expected O(1) probing.  The index stores 16-bit
// entry numbers, so it is much smaller than duplicating Metrics itself.
const index_capacity = 8192;
const index_mask = index_capacity - 1;
const empty_slot: u16 = std.math.maxInt(u16);
const tombstone_slot: u16 = empty_slot - 1;

fn isFinite(value: f64) bool {
    return value == value and value != std.math.inf(f64) and value != -std.math.inf(f64);
}

fn initialFreeSlots() [max_entries]u16 {
    @setEvalBranchQuota(10000);
    var slots = [_]u16{0} ** max_entries;
    for (&slots, 0..) |*slot, index| slot.* = @intCast(max_entries - index - 1);
    return slots;
}

pub const Metrics = struct {
    id: u64 = 0,
    used: bool = false,
    // Transient prune marker: set for rows whose id appears in the keep list,
    // cleared again in the same prune pass. Never meaningful between calls.
    kept: bool = false,
    successes: u64 = 0,
    failures: u64 = 0,
    connect_ms: f64 = 0,
    jitter_ms: f64 = 0,
    samples: u64 = 0,
    last_ms: f64 = 0,
    last_updated: u64 = 0,
};

pub const Store = struct {
    entries: [max_entries]Metrics = [_]Metrics{Metrics{}} ** max_entries,
    slots: [index_capacity]u16 = [_]u16{empty_slot} ** index_capacity,
    free_slots: [max_entries]u16 = initialFreeSlots(),
    free_count: usize = max_entries,
    count: usize = 0,
    tombstones: usize = 0,

    pub fn reset(self: *Store) void {
        self.entries = [_]Metrics{Metrics{}} ** max_entries;
        self.slots = [_]u16{empty_slot} ** index_capacity;
        for (&self.free_slots, 0..) |*slot, index| slot.* = @intCast(max_entries - index - 1);
        self.free_count = max_entries;
        self.count = 0;
        self.tombstones = 0;
    }

    pub fn observe(self: *Store, id: u64, success: bool, elapsed_ms: f64, now_ms: u64) void {
        if (id == 0) return;
        var slot = self.find(id);
        if (slot == null) slot = self.allocate(id, now_ms);
        if (slot == null) return;
        var metric = &self.entries[slot.?];
        if (success) metric.successes +|= 1 else metric.failures +|= 1;
        // The Go adapter normally supplies a finite duration, but the C ABI is
        // also callable by foreign hosts.  Do not let an infinite sample poison
        // the EWMA/jitter state for every later decision.
        if (elapsed_ms > 0 and isFinite(elapsed_ms)) {
            // Reliability samples can be recorded without a latency value (for
            // example a failed probe).  Use the latency field itself as the
            // first-valid-sample marker so those events do not dilute the first
            // usable timing observation.
            if (metric.connect_ms <= 0 or !isFinite(metric.connect_ms)) {
                metric.connect_ms = elapsed_ms;
            } else {
                const delta = elapsed_ms - metric.connect_ms;
                metric.connect_ms += 0.2 * delta;
                metric.jitter_ms += 0.2 * (@abs(delta) - metric.jitter_ms);
            }
            metric.last_ms = elapsed_ms;
        }
        metric.samples +|= 1;
        metric.last_updated = now_ms;
    }

    test "non-finite latency samples do not poison the metric" {
        var store = Store{};
        store.observe(1, true, std.math.inf(f64), 1);
        store.observe(1, true, std.math.nan(f64), 2);
        var metric = store.get(1).?;
        try std.testing.expectEqual(@as(u64, 2), metric.samples);
        try std.testing.expectEqual(@as(f64, 0), metric.connect_ms);
        store.observe(1, true, 10, 3);
        metric = store.get(1).?;
        try std.testing.expectEqual(@as(f64, 10), metric.connect_ms);
    }

    pub fn get(self: *const Store, id: u64) ?Metrics {
        if (self.findConst(id)) |index| return self.entries[index];
        return null;
    }

    pub fn prune(self: *Store, keep: []const u64) void {
        // Provider reloads can remove an endpoint while its policy context is
        // still retained. Drop those rows before the next Choose so stale
        // aliases cannot inherit health or selection state.
        // Rebuild the lookup first. This is deliberately self-healing: prune
        // is a maintenance boundary, so a stale/torn index must not turn a
        // provider refresh into an out-of-bounds read in the C ABI.
        self.rebuildIndex();
        // Mark retained rows through the O(1) lookup index instead of scanning
        // the keep list once per entry; the keep list can hold thousands of
        // endpoints and prune runs once per provider refresh per context.
        for (keep) |id| {
            if (self.findConst(id)) |entry_index| self.entries[entry_index].kept = true;
        }

        // Compact retained entries in place. Rebuilding both the free list
        // and the hash index afterwards makes the operation safe even if a
        // previous maintenance pass was interrupted or the bounded state was
        // recovered from a malformed snapshot.
        var write_index: usize = 0;
        for (self.entries) |entry| {
            if (!entry.used or !entry.kept) continue;
            var retained = entry;
            retained.kept = false;
            self.entries[write_index] = retained;
            write_index += 1;
        }
        while (write_index < self.entries.len) : (write_index += 1) self.entries[write_index] = .{};
        self.count = 0;
        self.free_count = 0;
        var index: usize = self.entries.len;
        while (index > 0) {
            index -= 1;
            if (self.entries[index].used) {
                self.count += 1;
            } else {
                self.free_slots[self.free_count] = @intCast(index);
                self.free_count += 1;
            }
        }
        self.rebuildIndex();
    }

    test "prune rebuilds bounded state after full table churn" {
        var store = Store{};
        for (1..max_entries + 1) |id| store.observe(id, true, 1, id);
        var keep: [64]u64 = undefined;
        for (&keep, 0..) |*id, index| id.* = index + 1;
        store.prune(&keep);
        try std.testing.expectEqual(@as(usize, keep.len), store.count);
        try std.testing.expectEqual(@as(usize, max_entries - keep.len), store.free_count);
        for (keep) |id| try std.testing.expect(store.get(id) != null);
        // A second refresh must remain safe and leave a fully empty, reusable
        // table; this also exercises the rebuilt free-slot order.
        store.prune(&[_]u64{});
        try std.testing.expectEqual(@as(usize, 0), store.count);
        try std.testing.expectEqual(@as(usize, max_entries), store.free_count);
    }

    pub fn enrich(self: *const Store, candidate: anytype) @TypeOf(candidate) {
        const observed = self.get(candidate.id) orelse return candidate;
        var result = candidate;
        if ((!isFinite(result.samples) or result.samples <= 0) and observed.samples > 0) {
            const total = observed.successes + observed.failures;
            result.samples = @floatFromInt(observed.samples);
            if (total > 0) result.reliability = @as(f64, @floatFromInt(observed.successes)) / @as(f64, @floatFromInt(total));
        }
        if ((!isFinite(result.connect_ms) or result.connect_ms <= 0) and observed.connect_ms > 0) result.connect_ms = observed.connect_ms;
        if ((!isFinite(result.jitter_ms) or result.jitter_ms <= 0) and observed.jitter_ms > 0) result.jitter_ms = observed.jitter_ms;
        return result;
    }

    fn find(self: *Store, id: u64) ?usize {
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return null;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (index < self.entries.len and self.entries[index].used and self.entries[index].id == id) return index;
            }
            position = (position + 1) & index_mask;
        }
        return null;
    }

    fn findConst(self: *const Store, id: u64) ?usize {
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return null;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (index < self.entries.len and self.entries[index].used and self.entries[index].id == id) return index;
            }
            position = (position + 1) & index_mask;
        }
        return null;
    }

    fn allocate(self: *Store, id: u64, now_ms: u64) ?usize {
        var index: usize = undefined;
        if (self.free_count > 0) {
            self.free_count -= 1;
            index = self.free_slots[self.free_count];
            self.count += 1;
        } else {
            var oldest: usize = 0;
            var oldest_time: u64 = std.math.maxInt(u64);
            var found = false;
            for (self.entries, 0..) |entry, candidate_index| {
                if (entry.used and entry.last_updated <= oldest_time) {
                    oldest = candidate_index;
                    oldest_time = entry.last_updated;
                    found = true;
                }
            }
            if (!found) return null;
            self.removeIndex(self.entries[oldest].id);
            index = oldest;
        }
        self.entries[index] = .{ .id = id, .used = true, .last_updated = now_ms };
        // Rebuild only after the replacement entry is written. Rebuilding
        // while the evicted entry is still marked used would briefly restore
        // the old id and leave a stale slot pointing at the reused entry.
        if (self.tombstones > index_capacity / 4) {
            self.rebuildIndex();
        } else {
            self.insertIndex(id, @intCast(index));
        }
        return index;
    }

    fn hash(id: u64) usize {
        var value = id;
        value ^= value >> 30;
        value *%= 0xbf58476d1ce4e5b9;
        value ^= value >> 27;
        value *%= 0x94d049bb133111eb;
        value ^= value >> 31;
        return @intCast(value);
    }

    fn insertIndex(self: *Store, id: u64, entry_index: u16) void {
        var position = hash(id) & index_mask;
        var first_tombstone: ?usize = null;
        while (true) {
            const slot = self.slots[position];
            if (slot == empty_slot) {
                const target = first_tombstone orelse position;
                if (first_tombstone != null) self.tombstones -= 1;
                self.slots[target] = entry_index;
                return;
            }
            if (slot == tombstone_slot and first_tombstone == null) first_tombstone = position;
            position = (position + 1) & index_mask;
        }
    }

    fn removeIndex(self: *Store, id: u64) void {
        var position = hash(id) & index_mask;
        var steps: usize = 0;
        while (steps < index_capacity) : (steps += 1) {
            const slot = self.slots[position];
            if (slot == empty_slot) return;
            if (slot != tombstone_slot) {
                const index: usize = slot;
                if (self.entries[index].used and self.entries[index].id == id) {
                    self.slots[position] = tombstone_slot;
                    self.tombstones += 1;
                    return;
                }
            }
            position = (position + 1) & index_mask;
        }
    }

    fn rebuildIndex(self: *Store) void {
        self.slots = [_]u16{empty_slot} ** index_capacity;
        self.tombstones = 0;
        for (self.entries, 0..) |entry, index| {
            if (entry.used) self.insertIndex(entry.id, @intCast(index));
        }
    }
};
