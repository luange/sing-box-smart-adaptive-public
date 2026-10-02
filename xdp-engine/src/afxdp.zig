//! Allocation-free AF_XDP ring ownership primitives.
//!
//! The kernel/XSK syscalls are intentionally kept behind the host adapter;
//! this module owns bounded frame ownership, producer/consumer arithmetic,
//! and the fail-open return path. A frame is never silently lost when a peer
//! TX ring is full.

const std = @import("std");

pub const max_queues: u32 = 64;
pub const min_ring_size: u32 = 64;
pub const max_ring_size: u32 = 16384;

pub fn clampRingSize(value: u32) u32 {
    if (value < min_ring_size) return min_ring_size;
    if (value > max_ring_size) return max_ring_size;
    // AF_XDP ring sizes must be powers of two. Round down so a bad config
    // never allocates more frames than the configured memory budget.
    const n = value;
    var power: u32 = 1;
    while ((power << 1) <= n) : (power <<= 1) {}
    return power;
}

pub const Ring = struct {
    producer: u32 = 0,
    consumer: u32 = 0,
    size: u32,

    pub fn init(size: u32) Ring {
        return .{ .size = clampRingSize(size) };
    }

    pub fn pending(self: Ring) u32 {
        return self.producer -% self.consumer;
    }

    pub fn free(self: Ring) u32 {
        const used = self.pending();
        return if (used >= self.size) 0 else self.size - used;
    }

    pub fn reserve(self: *Ring, count: u32) ?u32 {
        if (count == 0 or count > self.free()) return null;
        const start = self.producer;
        self.producer +%= count;
        return start;
    }

    pub fn release(self: *Ring, count: u32) bool {
        if (count == 0 or count > self.pending()) return false;
        self.consumer +%= count;
        return true;
    }

    pub fn slot(self: Ring, index: u32) u32 {
        return index & (self.size - 1);
    }
};

pub const Queue = struct {
    rx: Ring,
    tx: Ring,
    completed: Ring,
    fail_open: u64 = 0,

    pub fn init(ring_size: u32) Queue {
        return .{ .rx = Ring.init(ring_size), .tx = Ring.init(ring_size), .completed = Ring.init(ring_size) };
    }

    /// Move one RX frame into a peer TX ring. A full peer ring is normal
    /// backpressure: return the frame to the kernel instead of dropping it
    /// or growing an unbounded userspace queue.
    pub fn forward(self: *Queue, peer: *Queue) bool {
        // Reserve the destination before consuming the source.  If the peer
        // is full, the caller still owns the RX descriptor and can return it
        // to the kernel/TC path.  The old order consumed RX first and lost a
        // frame whenever the peer TX ring was saturated.
        if (self.rx.pending() == 0 or peer.tx.free() == 0) {
            self.fail_open += 1;
            return false;
        }
        _ = peer.tx.reserve(1) orelse {
            self.fail_open += 1;
            return false;
        };
        if (!self.rx.release(1)) {
            // The model is host-serialized, so this is defensive.  Roll back
            // the reservation if a future caller violates that contract.
            _ = peer.tx.release(1);
            self.fail_open += 1;
            return false;
        }
        return true;
    }

    pub fn completeTx(self: *Queue, count: u32) bool {
        if (!self.tx.release(count)) return false;
        self.completed.producer +%= count;
        return true;
    }

    pub fn recycleCompleted(self: *Queue, count: u32) bool {
        if (count == 0 or count > self.completed.pending()) return false;
        self.completed.consumer +%= count;
        self.rx.consumer +%= count;
        return true;
    }
};

pub const Fabric = struct {
    queues: [max_queues]Queue,
    queue_count: u32,

    pub fn init(queue_count: u32, ring_size: u32) Fabric {
        var fabric = Fabric{ .queues = undefined, .queue_count = @min(queue_count, max_queues) };
        for (&fabric.queues) |*item| item.* = Queue.init(ring_size);
        return fabric;
    }

    pub fn queue(self: *Fabric, index: u32) ?*Queue {
        if (index >= self.queue_count) return null;
        return &self.queues[index];
    }
};

test "ring size is bounded and power of two" {
    try std.testing.expectEqual(@as(u32, 64), clampRingSize(1));
    try std.testing.expectEqual(@as(u32, 1024), clampRingSize(1025));
    try std.testing.expectEqual(max_ring_size, clampRingSize(max_ring_size + 1));
}

test "ring refuses over-reservation and double release" {
    var ring = Ring.init(64);
    try std.testing.expect(ring.reserve(64) != null);
    try std.testing.expect(ring.reserve(1) == null);
    try std.testing.expect(ring.release(64));
    try std.testing.expect(!ring.release(1));
}

test "full peer queue fails open without frame growth" {
    var source = Queue.init(64);
    var peer = Queue.init(64);
    _ = source.rx.reserve(1);
    _ = peer.tx.reserve(64);
    try std.testing.expect(!source.forward(&peer));
    try std.testing.expectEqual(@as(u64, 1), source.fail_open);
    try std.testing.expectEqual(@as(u32, 1), source.rx.pending());
    try std.testing.expectEqual(@as(u32, 64), peer.tx.pending());
}

test "forward consumes RX only after reserving peer TX" {
    var source = Queue.init(64);
    var peer = Queue.init(64);
    _ = source.rx.reserve(1);
    try std.testing.expect(source.forward(&peer));
    try std.testing.expectEqual(@as(u32, 0), source.rx.pending());
    try std.testing.expectEqual(@as(u32, 1), peer.tx.pending());
}

test "tx completion recycles bounded ownership" {
    var queue = Queue.init(64);
    _ = queue.rx.reserve(4);
    _ = queue.tx.reserve(4);
    try std.testing.expect(queue.completeTx(4));
    try std.testing.expect(queue.recycleCompleted(4));
    try std.testing.expectEqual(@as(u32, 0), queue.tx.pending());
    try std.testing.expectEqual(@as(u32, 0), queue.rx.pending());
}

test "fabric clamps queue count and rejects out of range" {
    var fabric = Fabric.init(100, 256);
    try std.testing.expectEqual(max_queues, fabric.queue_count);
    try std.testing.expect(fabric.queue(63) != null);
    try std.testing.expect(fabric.queue(64) == null);
}
