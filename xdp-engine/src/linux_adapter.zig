//! Linux AF_XDP host adapter.
//!
//! This is deliberately a small, ownership-focused adapter rather than a
//! packet stack.  It creates bounded shared UMEM, configures one XSK per RX
//! queue, exposes the four kernel rings, and returns frames to the kernel on
//! every failure path.  Policy and XDP attach are owned by the caller
//! (`common/ebpf/native/xdp_runtime.c`); this module never enables the XDP
//! control map by itself.

const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const afxdp = @import("afxdp.zig");

comptime {
    if (builtin.os.tag != .linux) @compileError("linux_adapter.zig is Linux-only");
}

const CInt = i32;
const CUint = u32;

extern fn socket(domain: CInt, socket_type: CInt, protocol: CInt) callconv(.c) CInt;
extern fn setsockopt(fd: CInt, level: CInt, name: CInt, value: *const anyopaque, value_len: CUint) callconv(.c) CInt;
extern fn getsockopt(fd: CInt, level: CInt, name: CInt, value: *anyopaque, value_len: *CUint) callconv(.c) CInt;
extern fn bind(fd: CInt, address: *const anyopaque, address_len: CUint) callconv(.c) CInt;
extern fn close(fd: CInt) callconv(.c) CInt;
extern fn mmap(address: ?*anyopaque, length: usize, protection: CInt, flags: CInt, fd: CInt, offset: i64) callconv(.c) ?*anyopaque;
extern fn munmap(address: *anyopaque, length: usize) callconv(.c) CInt;
extern fn poll(fds: [*]PollFd, count: usize, timeout_ms: CInt) callconv(.c) CInt;
extern fn send(fd: CInt, buffer: ?*const anyopaque, length: usize, flags: CInt) callconv(.c) isize;

const af_xdp: CInt = 44;
const sock_raw: CInt = 3;
const sock_cloexec: CInt = 0x80000;
const sol_xdp: CInt = 283;
const xdp_umem_reg: CInt = 4;
const xdp_umem_fill_ring: CInt = 5;
const xdp_umem_completion_ring: CInt = 6;
const xdp_rx_ring: CInt = 7;
const xdp_tx_ring: CInt = 8;
const xdp_mmap_offsets: CInt = 1;
const xdp_shared_umem: u16 = 1 << 0;
const xdp_copy: u16 = 1 << 1;
const xdp_zerocopy: u16 = 1 << 2;
const xdp_use_need_wakeup: u16 = 1 << 3;
const xdp_need_wakeup: u32 = 1;
const xdp_pgoff_rx_ring: i64 = 0;
const xdp_pgoff_tx_ring: i64 = 0x80000000;
const xdp_umem_pgoff_fill_ring: i64 = 0x100000000;
const xdp_umem_pgoff_completion_ring: i64 = 0x180000000;
const prot_read: CInt = 1;
const prot_write: CInt = 2;
const map_shared: CInt = 1;
const map_private: CInt = 2;
const map_anonymous: CInt = 0x20;
const poll_in: i16 = 0x001;
const poll_err: i16 = 0x008;
const poll_hup: i16 = 0x010;
const poll_nval: i16 = 0x020;
const msg_dontwait: CInt = 0x40;

const max_usize = std.math.maxInt(usize);

const SockAddrXdp = extern struct {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue: u32,
    shared_umem_fd: u32,
};

const UmemReg = extern struct {
    address: u64,
    length: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
};

const RingOffset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
};

const MmapOffsets = extern struct {
    rx: RingOffset,
    tx: RingOffset,
    fill: RingOffset,
    completion: RingOffset,
};

const XdpDesc = extern struct {
    address: u64,
    length: u32,
    options: u32,
};

const PollFd = extern struct {
    fd: CInt,
    events: i16,
    revents: i16,
};

pub const BindMode = enum(u32) {
    zero_copy = 0,
    copy = 1,
};

/// C-compatible configuration. Zero values select bounded defaults.
pub const Config = extern struct {
    ifindex: u32,
    queue_count: u32,
    ring_size: u32,
    frame_size: u32,
    frame_count: u32,
    mode: u32,
};

pub const CFrame = extern struct {
    /// Queue that delivered the descriptor (not a UMEM partition owner).
    /// Shared-UMEM frames may be received by any bound queue.
    queue: u32,
    address: u64,
    length: u32,
    options: u32,
};

pub const Stats = extern struct {
    rx: u64 = 0,
    tx: u64 = 0,
    recycled: u64 = 0,
    completed: u64 = 0,
    fill_starved: u64 = 0,
    tx_full: u64 = 0,
    invalid_descriptor: u64 = 0,
};

pub const BindResult = enum(u32) {
    failed = 0,
    zero_copy_ok = 1,
    copy_ok = 2,
};

const AdapterError = error{
    InvalidConfig,
    UnsupportedPlatform,
    SingleQueue,
    FrameBudget,
    SystemCallFailed,
    RingMapFailed,
    BindFailed,
    FillRingFull,
    TxRingFull,
    InvalidFrame,
};

const FrameState = enum(u8) {
    in_kernel = 0,
    rx_owned = 1,
    tx_owned = 2,
};

const RingView = struct {
    mapping: ?[]u8 = null,
    producer: ?*u32 = null,
    consumer: ?*u32 = null,
    flags: ?*u32 = null,
    descriptors: ?*u8 = null,
    entries: u32 = 0,
    stride: u32 = 0,

    fn mappingLength(offset: RingOffset, entries: u32, stride: u32) AdapterError!usize {
        if (entries == 0 or stride == 0 or (entries & (entries - 1)) != 0) return error.InvalidConfig;

        const desc_bytes = std.math.mul(u64, @as(u64, @intCast(entries)), @as(u64, @intCast(stride))) catch return error.RingMapFailed;
        var length_u64 = std.math.add(u64, offset.desc, desc_bytes) catch return error.RingMapFailed;
        const control_offsets = [_]u64{ offset.producer, offset.consumer, offset.flags };
        for (control_offsets) |control| {
            if ((control & 3) != 0) return error.RingMapFailed;
            const control_end = std.math.add(u64, control, @sizeOf(u32)) catch return error.RingMapFailed;
            if (control_end > length_u64) length_u64 = control_end;
        }
        if (length_u64 > @as(u64, @intCast(max_usize))) return error.RingMapFailed;
        return @intCast(length_u64);
    }

    fn map(fd: CInt, offset: RingOffset, mmap_offset: i64, entries: u32, stride: u32) AdapterError!RingView {
        if (mmap_offset < 0) return error.RingMapFailed;
        const length = try mappingLength(offset, entries, stride);
        const pointer = mmap(null, length, prot_read | prot_write, map_shared, fd, mmap_offset);
        if (pointer == null or @intFromPtr(pointer.?) == max_usize) return error.RingMapFailed;
        const bytes = @as([*]u8, @ptrCast(pointer.?))[0..length];
        const base = @intFromPtr(bytes.ptr);
        const producer = std.math.add(usize, base, @intCast(offset.producer)) catch {
            _ = munmap(bytes.ptr, bytes.len);
            return error.RingMapFailed;
        };
        const consumer = std.math.add(usize, base, @intCast(offset.consumer)) catch {
            _ = munmap(bytes.ptr, bytes.len);
            return error.RingMapFailed;
        };
        const flags = std.math.add(usize, base, @intCast(offset.flags)) catch {
            _ = munmap(bytes.ptr, bytes.len);
            return error.RingMapFailed;
        };
        const descriptors = std.math.add(usize, base, @intCast(offset.desc)) catch {
            _ = munmap(bytes.ptr, bytes.len);
            return error.RingMapFailed;
        };
        return .{
            .mapping = bytes,
            .producer = @ptrFromInt(producer),
            .consumer = @ptrFromInt(consumer),
            .flags = @ptrFromInt(flags),
            .descriptors = @ptrFromInt(descriptors),
            .entries = entries,
            .stride = stride,
        };
    }

    fn unmap(self: *RingView) void {
        if (self.mapping) |mapping| {
            _ = munmap(mapping.ptr, mapping.len);
        }
        self.* = .{};
    }

    fn pending(self: *const RingView) u32 {
        return @atomicLoad(u32, self.producer.?, .acquire) -% @atomicLoad(u32, self.consumer.?, .monotonic);
    }

    fn free(self: *const RingView) u32 {
        const used = self.pending();
        return if (used >= self.entries) 0 else self.entries - used;
    }

    fn descriptor(self: *const RingView, index: u32) *XdpDesc {
        const ptr_address = @intFromPtr(self.descriptors.?) + @as(usize, @intCast((index & (self.entries - 1)) * self.stride));
        return @ptrFromInt(ptr_address);
    }

    fn address(self: *const RingView, index: u32) *u64 {
        const ptr_address = @intFromPtr(self.descriptors.?) + @as(usize, @intCast((index & (self.entries - 1)) * self.stride));
        return @ptrFromInt(ptr_address);
    }
};

const Queue = struct {
    fd: CInt = -1,
    rx: RingView = .{},
    tx: RingView = .{},
    fill: RingView = .{},
    completion: RingView = .{},
    frame_base: u32 = 0,
    frame_limit: u32 = 0,
    bound: bool = false,
    owns_shared_rings: bool = false,

    fn release(self: *Queue) void {
        self.rx.unmap();
        self.tx.unmap();
        // The fill/completion rings are UMEM-wide and are aliased by every
        // queue after XDP_SHARED_UMEM bind.  Only queue 0 owns their mmap;
        // unmapping an alias here would invalidate queue 0 and make close
        // double-unmap the same virtual range.
        if (self.owns_shared_rings) {
            self.fill.unmap();
            self.completion.unmap();
        } else {
            self.fill = .{};
            self.completion = .{};
        }
        if (self.fd >= 0) _ = close(self.fd);
        self.* = .{};
    }
};

pub const Adapter = struct {
    allocator: std.mem.Allocator,
    config: Config,
    bind_mode: BindMode,
    frame_size: u32,
    frame_count: u32,
    ring_size: u32,
    umem_ring_size: u32,
    frames_per_queue: u32,
    umem: ?[]u8 = null,
    queues: [model.max_queues]Queue = undefined,
    queue_count: u32 = 0,
    offsets: MmapOffsets = undefined,
    frame_states: ?[]FrameState = null,
    ready: bool = false,
    stats: Stats = .{},

    pub fn init(allocator: std.mem.Allocator, input: Config) AdapterError!Adapter {
        var self = Adapter{
            .allocator = allocator,
            .config = input,
            .bind_mode = undefined,
            .frame_size = 0,
            .frame_count = 0,
            .ring_size = 0,
            .umem_ring_size = 0,
            .frames_per_queue = 0,
            .queue_count = 0,
        };
        for (&self.queues) |*queue| queue.* = .{};
        try self.normalize(input);
        errdefer self.close();
        try self.allocateUmem();
        self.frame_states = allocator.alloc(FrameState, self.frame_count) catch return error.SystemCallFailed;
        @memset(self.frame_states.?, .in_kernel);
        try self.openQueues();
        return self;
    }

    fn normalize(self: *Adapter, input: Config) AdapterError!void {
        if (input.ifindex == 0) return error.InvalidConfig;
        const queues = if (input.queue_count == 0) @as(u32, 1) else input.queue_count;
        if (queues > model.max_queues) return error.InvalidConfig;
        self.queue_count = queues;
        self.bind_mode = switch (input.mode) {
            0 => .zero_copy,
            1 => .copy,
            else => return error.InvalidConfig,
        };
        if (self.bind_mode == .zero_copy and queues < 2) return error.SingleQueue;
        const mem = model.clampUmem(
            if (input.frame_size == 0) model.umem_frame_size else input.frame_size,
            if (input.frame_count == 0) model.umem_frame_count else input.frame_count,
        );
        self.frame_size = mem.size;
        self.frame_count = mem.count;
        self.frames_per_queue = self.frame_count / queues;
        if (self.frames_per_queue < afxdp.min_ring_size) return error.FrameBudget;
        self.frame_count = self.frames_per_queue * queues;
        self.ring_size = afxdp.clampRingSize(if (input.ring_size == 0) 2048 else input.ring_size);
        // Fill/completion are UMEM-wide.  Size them for the total bounded
        // frame budget, while keeping per-queue RX/TX rings at ring_size.
        // Without this, a multi-queue adapter can advertise 4096 frames but
        // initially expose only one queue's 2048 descriptors to the kernel.
        const total_ring_target = @min(self.frame_count, self.ring_size * queues);
        self.umem_ring_size = afxdp.clampRingSize(total_ring_target);
        self.config = input;
        self.config.queue_count = queues;
        self.config.frame_size = self.frame_size;
        self.config.frame_count = self.frame_count;
        self.config.ring_size = self.ring_size;
    }

    fn setOptionU32(fd: CInt, option: CInt, value: u32) AdapterError!void {
        if (setsockopt(fd, sol_xdp, option, @ptrCast(&value), @intCast(@sizeOf(u32))) != 0) return error.SystemCallFailed;
    }

    fn getOffsets(fd: CInt) AdapterError!MmapOffsets {
        var offsets: MmapOffsets = undefined;
        var length: CUint = @sizeOf(MmapOffsets);
        if (getsockopt(fd, sol_xdp, xdp_mmap_offsets, @ptrCast(&offsets), &length) != 0) return error.SystemCallFailed;
        if (length < @as(CUint, @intCast(@sizeOf(MmapOffsets)))) return error.SystemCallFailed;
        return offsets;
    }

    fn allocateUmem(self: *Adapter) AdapterError!void {
        const length_u64 = @as(u64, @intCast(self.frame_size)) * @as(u64, @intCast(self.frame_count));
        if (length_u64 == 0 or length_u64 > @as(u64, @intCast(max_usize))) return error.InvalidConfig;
        const length: usize = @intCast(length_u64);
        const pointer = mmap(null, length, prot_read | prot_write, map_private | map_anonymous, -1, 0);
        if (pointer == null or @intFromPtr(pointer.?) == max_usize) return error.SystemCallFailed;
        self.umem = @as([*]u8, @ptrCast(pointer.?))[0..length];
    }

    fn openQueues(self: *Adapter) AdapterError!void {
        var first_fd: CInt = -1;
        var queue_index: u32 = 0;
        while (queue_index < self.queue_count) : (queue_index += 1) {
            const fd = socket(af_xdp, sock_raw | sock_cloexec, 0);
            if (fd < 0) return error.SystemCallFailed;
            self.queues[queue_index].fd = fd;
            if (queue_index == 0) {
                first_fd = fd;
                const memory = self.umem.?;
                const registration = UmemReg{
                    .address = @intFromPtr(memory.ptr),
                    .length = memory.len,
                    .chunk_size = self.frame_size,
                    .headroom = 0,
                    .flags = 0,
                    .tx_metadata_len = 0,
                };
                if (setsockopt(fd, sol_xdp, xdp_umem_reg, @ptrCast(&registration), @intCast(@sizeOf(UmemReg))) != 0) return error.SystemCallFailed;
                self.offsets = try getOffsets(fd);
            }
            // Fill/completion rings belong to the UMEM, not to each XSK.
            // With XDP_SHARED_UMEM only the first socket creates/maps them;
            // subsequent sockets get their own RX/TX rings and alias the
            // first socket's UMEM rings below.
            if (queue_index == 0) {
                try setOptionU32(fd, xdp_umem_fill_ring, self.umem_ring_size);
                try setOptionU32(fd, xdp_umem_completion_ring, self.umem_ring_size);
            }
            try setOptionU32(fd, xdp_rx_ring, self.ring_size);
            try setOptionU32(fd, xdp_tx_ring, self.ring_size);

            const queue = &self.queues[queue_index];
            queue.rx = try RingView.map(fd, self.offsets.rx, xdp_pgoff_rx_ring, self.ring_size, @sizeOf(XdpDesc));
            queue.tx = try RingView.map(fd, self.offsets.tx, xdp_pgoff_tx_ring, self.ring_size, @sizeOf(XdpDesc));
            if (queue_index == 0) {
                // Mark ownership before either mmap call. If the second map
                // fails after the first succeeds, Queue.release must reclaim
                // the partially initialized shared ring as well.
                queue.owns_shared_rings = true;
                queue.fill = try RingView.map(fd, self.offsets.fill, xdp_umem_pgoff_fill_ring, self.umem_ring_size, @sizeOf(u64));
                queue.completion = try RingView.map(fd, self.offsets.completion, xdp_umem_pgoff_completion_ring, self.umem_ring_size, @sizeOf(u64));
            } else {
                queue.fill = self.queues[0].fill;
                queue.completion = self.queues[0].completion;
            }

            var address = SockAddrXdp{
                .family = af_xdp,
                .flags = xdp_use_need_wakeup | if (self.bind_mode == .zero_copy) xdp_zerocopy else xdp_copy,
                .ifindex = self.config.ifindex,
                .queue = queue_index,
                .shared_umem_fd = if (queue_index == 0) 0 else @intCast(first_fd),
            };
            if (queue_index != 0) address.flags |= xdp_shared_umem;
            if (bind(fd, @ptrCast(&address), @intCast(@sizeOf(SockAddrXdp))) != 0) return error.BindFailed;
            queue.frame_base = queue_index * self.frames_per_queue;
            queue.frame_limit = queue.frame_base + self.frames_per_queue;
            queue.bound = true;
        }
        // There is one shared fill ring.  Prefill it once, round-robin across
        // queue partitions, and never attempt to push queue_count * ring_size
        // descriptors into a ring whose capacity is only ring_size.
        try self.prefillAll();
        self.ready = true;
    }

    fn prefillAll(self: *Adapter) AdapterError!void {
        const fill = &self.queues[0].fill;
        const count = @min(self.frame_count, fill.entries);
        if (fill.free() < count) return error.FillRingFull;
        const producer = @atomicLoad(u32, fill.producer.?, .monotonic);
        var index: u32 = 0;
        while (index < count) : (index += 1) {
            const queue_index = index % self.queue_count;
            const frame = self.queues[queue_index].frame_base + (index / self.queue_count);
            if (frame >= self.queues[queue_index].frame_limit) break;
            fill.address(producer + index).* = @as(u64, @intCast(frame)) * @as(u64, @intCast(self.frame_size));
        }
        @atomicStore(u32, fill.producer.?, producer + index, .release);
    }

    pub fn deinit(self: *Adapter) void {
        self.close();
    }

    pub fn close(self: *Adapter) void {
        self.ready = false;
        var index: u32 = 0;
        while (index < self.queue_count) : (index += 1) self.queues[index].release();
        if (self.frame_states) |states| self.allocator.free(states);
        self.frame_states = null;
        if (self.umem) |memory| _ = munmap(memory.ptr, memory.len);
        self.umem = null;
        self.queue_count = 0;
    }

    pub fn queueFd(self: *const Adapter, queue: u32) CInt {
        if (queue >= self.queue_count) return -1;
        return self.queues[queue].fd;
    }

    pub fn isReady(self: *const Adapter) bool {
        return self.ready;
    }

    pub fn frameBytes(self: *Adapter, frame: CFrame) ?[]u8 {
        const memory = self.umem orelse return null;
        const states = self.frame_states orelse return null;
        if (frame.queue >= self.queue_count or frame.options != 0) return null;
        const frame_size = @as(u64, @intCast(self.frame_size));
        if (frame.address % frame_size != 0) return null;
        const frame_index = frame.address / frame_size;
        if (frame_index >= self.frame_count) return null;
        if (frame.length > self.frame_size) return null;
        if (states[@intCast(frame_index)] != .rx_owned and states[@intCast(frame_index)] != .tx_owned) return null;
        if (frame.address >= @as(u64, @intCast(memory.len))) return null;
        const end = std.math.add(usize, @intCast(frame.address), @as(usize, @intCast(frame.length))) catch return null;
        if (end > memory.len) return null;
        if (frame.length == 0) return &[_]u8{};
        const base = @intFromPtr(memory.ptr) + @as(usize, @intCast(frame.address));
        return @as([*]u8, @ptrFromInt(base))[0..@as(usize, @intCast(frame.length))];
    }

    pub fn pollQueues(self: *Adapter, timeout_ms: CInt) AdapterError!u64 {
        if (!self.ready) return error.InvalidConfig;
        var fds: [model.max_queues]PollFd = undefined;
        var index: u32 = 0;
        while (index < self.queue_count) : (index += 1) {
            fds[index] = .{ .fd = self.queues[index].fd, .events = poll_in, .revents = 0 };
        }
        const result = poll(&fds, @intCast(self.queue_count), timeout_ms);
        if (result < 0) return error.SystemCallFailed;
        var ready_mask: u64 = 0;
        index = 0;
        while (index < self.queue_count) : (index += 1) {
            if ((fds[index].revents & (poll_in | poll_err | poll_hup | poll_nval)) != 0)
                ready_mask |= @as(u64, 1) << @intCast(index);
        }
        return ready_mask;
    }

    pub fn receive(self: *Adapter, queue_index: u32) ?CFrame {
        if (!self.ready or queue_index >= self.queue_count) return null;
        const queue = &self.queues[queue_index];
        const producer = @atomicLoad(u32, queue.rx.producer.?, .acquire);
        const consumer = @atomicLoad(u32, queue.rx.consumer.?, .monotonic);
        if (consumer == producer) return null;
        const descriptor = queue.rx.descriptor(consumer).*;
        @atomicStore(u32, queue.rx.consumer.?, consumer + 1, .release);
        const frame_index = self.frameIndex(descriptor.address) orelse {
            self.stats.invalid_descriptor += 1;
            return null;
        };
        if (self.frame_states.?[frame_index] != .in_kernel) {
            self.stats.invalid_descriptor += 1;
            return null;
        }
        self.frame_states.?[frame_index] = .rx_owned;
        const end = std.math.add(u64, descriptor.address, @as(u64, @intCast(descriptor.length))) catch {
            self.stats.invalid_descriptor += 1;
            self.recycleAddress(descriptor.address, .rx_owned) catch {};
            return null;
        };
        if (end > @as(u64, @intCast(self.umem.?.len)) or descriptor.length > self.frame_size or descriptor.options != 0 or descriptor.address % @as(u64, @intCast(self.frame_size)) != 0) {
            self.stats.invalid_descriptor += 1;
            self.recycleAddress(descriptor.address, .rx_owned) catch {};
            return null;
        }
        self.stats.rx += 1;
        return .{ .queue = queue_index, .address = descriptor.address, .length = descriptor.length, .options = descriptor.options };
    }

    fn frameIndex(self: *const Adapter, address: u64) ?u32 {
        const frame_size = @as(u64, @intCast(self.frame_size));
        if (frame_size == 0 or address % frame_size != 0) return null;
        const frame_index = address / frame_size;
        if (frame_index >= self.frame_count) return null;
        return @intCast(frame_index);
    }

    fn recycleAddress(self: *Adapter, address: u64, expected: FrameState) AdapterError!void {
        const memory = self.umem orelse return error.InvalidFrame;
        const states = self.frame_states orelse return error.InvalidFrame;
        const frame_index = self.frameIndex(address) orelse return error.InvalidFrame;
        const frame_size = @as(u64, @intCast(self.frame_size));
        const end = std.math.add(u64, address, frame_size) catch return error.InvalidFrame;
        if (end > @as(u64, @intCast(memory.len))) return error.InvalidFrame;
        if (states[frame_index] != expected) return error.InvalidFrame;
        // A shared UMEM has one fill ring.  A frame received on queue N may
        // originate from any partition, so queue ownership is not encoded in
        // the address and all recycling goes through queue 0's UMEM ring.
        const fill = &self.queues[0].fill;
        if (fill.free() == 0) {
            self.stats.fill_starved += 1;
            return error.FillRingFull;
        }
        const producer = @atomicLoad(u32, fill.producer.?, .monotonic);
        fill.address(producer).* = address;
        @atomicStore(u32, fill.producer.?, producer + 1, .release);
        states[frame_index] = .in_kernel;
        self.stats.recycled += 1;
        self.wakeRxIfNeeded();
    }

    /// XDP_USE_NEED_WAKEUP applies to the FILL ring as well as TX.  Once the
    /// kernel has stopped polling RX because the fill ring was empty, merely
    /// returning a descriptor is not sufficient; poll() must be issued to
    /// restart the driver.  Only do this on the flagged slow path so normal
    /// recycling remains syscall-free.
    fn wakeRxIfNeeded(self: *Adapter) void {
        if (self.queue_count == 0) return;
        const fill = &self.queues[0].fill;
        if ((@atomicLoad(u32, fill.flags.?, .acquire) & xdp_need_wakeup) == 0) return;
        var fd = PollFd{ .fd = self.queues[0].fd, .events = poll_in, .revents = 0 };
        _ = poll(@ptrCast(&fd), 1, 0);
    }

    pub fn recycle(self: *Adapter, frame: CFrame) AdapterError!void {
        if (frame.queue >= self.queue_count) return error.InvalidFrame;
        try self.recycleAddress(frame.address, .rx_owned);
    }

    pub fn transmit(self: *Adapter, frame: CFrame, queue_index: u32) AdapterError!void {
        if (!self.ready or queue_index >= self.queue_count) return error.InvalidFrame;
        const frame_index = self.frameIndex(frame.address) orelse return error.InvalidFrame;
        const states = self.frame_states orelse return error.InvalidFrame;
        if (states[frame_index] != .rx_owned) return error.InvalidFrame;
        if (self.frameBytes(frame) == null) return error.InvalidFrame;
        const queue = &self.queues[queue_index];
        const producer = @atomicLoad(u32, queue.tx.producer.?, .monotonic);
        const consumer = @atomicLoad(u32, queue.tx.consumer.?, .acquire);
        if (producer -% consumer >= queue.tx.entries) {
            self.stats.tx_full += 1;
            return error.TxRingFull;
        }
        const descriptor = queue.tx.descriptor(producer);
        descriptor.* = .{ .address = frame.address, .length = frame.length, .options = frame.options };
        @atomicStore(u32, queue.tx.producer.?, producer + 1, .release);
        states[frame_index] = .tx_owned;
        self.stats.tx += 1;
        const flags = @atomicLoad(u32, queue.tx.flags.?, .acquire);
        if ((flags & 1) != 0) _ = send(queue.fd, null, 0, msg_dontwait);
    }

    pub fn drainCompletions(self: *Adapter, queue_index: u32, limit: u32) AdapterError!u32 {
        if (!self.ready or queue_index >= self.queue_count) return error.InvalidConfig;
        const queue = &self.queues[queue_index];
        const producer = @atomicLoad(u32, queue.completion.producer.?, .acquire);
        var consumer = @atomicLoad(u32, queue.completion.consumer.?, .monotonic);
        var drained: u32 = 0;
        const max_count = @min(limit, producer -% consumer);
        while (drained < max_count) : (drained += 1) {
            const address = queue.completion.address(consumer).*;
            if (self.frameIndex(address) == null) {
                self.stats.invalid_descriptor += 1;
                self.stats.fill_starved += 1;
                break;
            }
            self.recycleAddress(address, .tx_owned) catch {
                self.stats.invalid_descriptor += 1;
                self.stats.fill_starved += 1;
                break;
            };
            // Do not release the completion entry until its frame is safely
            // back in a fill ring.  This makes fill-ring backpressure a
            // retryable condition instead of silently losing a UMEM frame.
            @atomicStore(u32, queue.completion.consumer.?, consumer + 1, .release);
            consumer += 1;
            self.stats.completed += 1;
        }
        return drained;
    }

    pub fn getStats(self: *const Adapter) Stats {
        return self.stats;
    }

};

/// Probe the real XSK socket/bind path without attaching an XDP program.  The
/// adapter is opened and closed inside this call, so no socket or UMEM is
/// retained.  The caller still has to run the mode-specific BPF verifier/
/// attach probe before publishing the XDP control record.
pub fn probeBind(allocator: std.mem.Allocator, config: Config) BindResult {
    var adapter = Adapter.init(allocator, config) catch return .failed;
    adapter.close();
    return if (config.mode == @intFromEnum(BindMode.zero_copy)) .zero_copy_ok else .copy_ok;
}

pub export fn sb_xdp_adapter_open(config: ?*const Config) callconv(.c) ?*Adapter {
    if (config == null) return null;
    const allocator = std.heap.c_allocator;
    const adapter = allocator.create(Adapter) catch return null;
    adapter.* = Adapter.init(allocator, config.?.*) catch {
        allocator.destroy(adapter);
        return null;
    };
    return adapter;
}

pub export fn sb_xdp_adapter_probe_bind(config: ?*const Config) callconv(.c) BindResult {
    if (config == null) return .failed;
    return probeBind(std.heap.c_allocator, config.?.*);
}

pub export fn sb_xdp_adapter_queue_fd(adapter: ?*Adapter, queue: u32) callconv(.c) CInt {
    return if (adapter) |value| value.queueFd(queue) else -1;
}

pub export fn sb_xdp_adapter_ready(adapter: ?*const Adapter) callconv(.c) bool {
    return if (adapter) |value| value.isReady() else false;
}

pub export fn sb_xdp_adapter_poll(adapter: ?*Adapter, timeout_ms: CInt, ready_mask: ?*u64) callconv(.c) CInt {
    if (adapter == null or ready_mask == null) return -1;
    ready_mask.?.* = adapter.?.pollQueues(timeout_ms) catch return -1;
    return 0;
}

pub export fn sb_xdp_adapter_rx(adapter: ?*Adapter, queue: u32, frame: ?*CFrame) callconv(.c) CInt {
    if (adapter == null or frame == null) return -1;
    if (adapter.?.receive(queue)) |value| {
        frame.?.* = value;
        return 1;
    }
    return 0;
}

pub export fn sb_xdp_adapter_frame_data(adapter: ?*Adapter, frame: ?*const CFrame, length: ?*u32) callconv(.c) ?*u8 {
    if (adapter == null or frame == null or length == null) return null;
    const bytes = adapter.?.frameBytes(frame.?.*) orelse return null;
    length.?.* = @intCast(bytes.len);
    if (bytes.len == 0) return null;
    return &bytes[0];
}

pub export fn sb_xdp_adapter_recycle(adapter: ?*Adapter, frame: ?*const CFrame) callconv(.c) CInt {
    if (adapter == null or frame == null) return -1;
    adapter.?.recycle(frame.?.*) catch return -1;
    return 0;
}

pub export fn sb_xdp_adapter_tx(adapter: ?*Adapter, frame: ?*const CFrame, queue: u32) callconv(.c) CInt {
    if (adapter == null or frame == null) return -1;
    adapter.?.transmit(frame.?.*, queue) catch return -1;
    return 0;
}

pub export fn sb_xdp_adapter_drain_completions(adapter: ?*Adapter, queue: u32, limit: u32) callconv(.c) CInt {
    if (adapter == null) return -1;
    return @intCast(adapter.?.drainCompletions(queue, limit) catch return -1);
}

pub export fn sb_xdp_adapter_stats(adapter: ?*const Adapter, stats: ?*Stats) callconv(.c) CInt {
    if (adapter == null or stats == null) return -1;
    stats.?.* = adapter.?.getStats();
    return 0;
}

pub export fn sb_xdp_adapter_close(adapter: ?*Adapter) callconv(.c) void {
    if (adapter) |value| {
        const allocator = value.allocator;
        value.deinit();
        allocator.destroy(value);
    }
}

test "adapter config clamps memory and partitions frames" {
    var adapter = Adapter{
        .allocator = std.testing.allocator,
        .config = .{ .ifindex = 0, .queue_count = 0, .ring_size = 0, .frame_size = 0, .frame_count = 0, .mode = 0 },
        .bind_mode = .copy,
        .frame_size = 0,
        .frame_count = 0,
        .ring_size = 0,
        .umem_ring_size = 0,
        .frames_per_queue = 0,
        .queue_count = 0,
    };
    for (&adapter.queues) |*queue| queue.* = .{};
    try adapter.normalize(.{ .ifindex = 2, .queue_count = 2, .ring_size = 1025, .frame_size = 1025, .frame_count = 513, .mode = 1 });
    try std.testing.expectEqual(@as(u32, model.umem_frame_size_min), adapter.frame_size);
    try std.testing.expectEqual(@as(u32, 256), adapter.frames_per_queue);
    try std.testing.expectEqual(@as(u32, 512), adapter.frame_count);
    try std.testing.expectEqual(@as(u32, 1024), adapter.ring_size);
    try std.testing.expectEqual(@as(u32, 512), adapter.umem_ring_size);
}

test "ring mapping validates control offsets and checked arithmetic" {
    const offset = RingOffset{ .producer = 0, .consumer = 4, .desc = 64, .flags = 8 };
    try std.testing.expectEqual(@as(usize, 128), try RingView.mappingLength(offset, 4, @sizeOf(XdpDesc)));

    try std.testing.expectError(
        error.RingMapFailed,
        RingView.mappingLength(.{ .producer = 0, .consumer = 4, .desc = std.math.maxInt(u64), .flags = 8 }, 4, @sizeOf(XdpDesc)),
    );
    try std.testing.expectError(
        error.RingMapFailed,
        RingView.mappingLength(.{ .producer = 0, .consumer = 4, .desc = 64, .flags = 2 }, 4, @sizeOf(XdpDesc)),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        RingView.mappingLength(offset, 3, @sizeOf(XdpDesc)),
    );
}

test "C ABI records stay fixed width" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(Config));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(CFrame));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Stats));
}

test "zero copy refuses a single queue" {
    var adapter = Adapter{
        .allocator = std.testing.allocator,
        .config = .{ .ifindex = 0, .queue_count = 0, .ring_size = 0, .frame_size = 0, .frame_count = 0, .mode = 0 },
        .bind_mode = .zero_copy,
        .frame_size = 0,
        .frame_count = 0,
        .ring_size = 0,
        .umem_ring_size = 0,
        .frames_per_queue = 0,
        .queue_count = 0,
    };
    for (&adapter.queues) |*queue| queue.* = .{};
    try std.testing.expectError(error.SingleQueue, adapter.normalize(.{ .ifindex = 2, .queue_count = 1, .ring_size = 0, .frame_size = 0, .frame_count = 0, .mode = 0 }));
}

test "copy mode may use one queue but remains explicit" {
    var adapter = Adapter{
        .allocator = std.testing.allocator,
        .config = .{ .ifindex = 0, .queue_count = 0, .ring_size = 0, .frame_size = 0, .frame_count = 0, .mode = 0 },
        .bind_mode = .copy,
        .frame_size = 0,
        .frame_count = 0,
        .ring_size = 0,
        .umem_ring_size = 0,
        .frames_per_queue = 0,
        .queue_count = 0,
    };
    for (&adapter.queues) |*queue| queue.* = .{};
    try adapter.normalize(.{ .ifindex = 2, .queue_count = 1, .ring_size = 0, .frame_size = 0, .frame_count = 0, .mode = 1 });
    try std.testing.expectEqual(BindMode.copy, adapter.bind_mode);
    try std.testing.expectEqual(@as(u32, 1), adapter.queue_count);
}

test "need wakeup flag is a single bit" {
    try std.testing.expectEqual(@as(u32, 1), xdp_need_wakeup);
    try std.testing.expect((xdp_need_wakeup & 1) != 0);
}
