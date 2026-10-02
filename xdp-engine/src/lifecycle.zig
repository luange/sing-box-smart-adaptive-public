//! Allocation-free XDP session state. The host must serialize every method.
//! The core is not thread-safe and holds no global mutable state.

const probe = @import("probe.zig");

pub const State = enum(u8) {
    disabled = 0,
    probing = 1,
    attached_zc = 2,
    attached_copy = 3,
    fallback_tc = 4,
    detaching = 5,
};

pub const Session = struct {
    state: State = .disabled,
    reason: probe.FallbackReason = .none,
    queues: u32 = 0,
    zerocopy: bool = false,
    need_multibuffer_pass: bool = false,
    allow_copy_mode: bool = false,

    pub fn beginProbe(self: *Session) void {
        if (self.state == .disabled or self.state == .fallback_tc or self.state == .detaching) {
            self.state = .probing;
        }
    }

    pub fn applyProbe(self: *Session, sample: probe.Sample, result: probe.Result) void {
        // A late probe result must not attach a session that has already been
        // closed or superseded by a link change.  The host serializes calls,
        // so this guard is sufficient without adding a lock to the core.
        if (self.state != .probing) return;
        self.queues = sample.rx_queues;
        self.need_multibuffer_pass = result.need_multibuffer_pass;
        self.reason = result.reason;
        self.zerocopy = false;
        switch (result.outcome) {
            .attach_zerocopy => {
                self.state = .attached_zc;
                self.zerocopy = true;
            },
            .attach_copy => {
                if (self.allow_copy_mode and sample.allow_copy_mode) {
                    self.state = .attached_copy;
                } else {
                    self.state = .fallback_tc;
                    self.reason = .copy_disallowed;
                }
            },
            .fallback_tc => {
                self.state = .fallback_tc;
            },
        }
    }

    pub fn attached(self: Session) bool {
        return self.state == .attached_zc or self.state == .attached_copy;
    }

    pub fn onLinkChange(self: *Session) void {
        if (self.state == .attached_zc or self.state == .attached_copy or self.state == .probing) {
            self.state = .detaching;
            self.zerocopy = false;
        }
        self.fallbackFromDetach();
    }

    pub fn fallbackFromDetach(self: *Session) void {
        if (self.state == .detaching) {
            self.state = .fallback_tc;
            self.reason = .none;
            self.zerocopy = false;
        }
    }

    pub fn close(self: *Session) void {
        self.* = .{ .allow_copy_mode = self.allow_copy_mode };
        self.state = .disabled;
    }
};

const std = @import("std");

const capable = probe.feat_basic | probe.feat_redirect | probe.feat_xsk_zerocopy;

test "probe fail moves probing to fallback_tc" {
    var session = Session{};
    session.beginProbe();
    try std.testing.expectEqual(State.probing, session.state);
    session.applyProbe(
        .{ .features = capable, .rx_queues = 1, .bind = .zerocopy_ok },
        probe.evaluate(.{ .features = capable, .rx_queues = 1, .bind = .zerocopy_ok }),
    );
    try std.testing.expectEqual(State.fallback_tc, session.state);
    try std.testing.expect(!session.attached());
}

test "link change from attached falls back to tc" {
    var session = Session{};
    session.beginProbe();
    const sample = probe.Sample{ .features = capable, .rx_queues = 4, .bind = .zerocopy_ok };
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expectEqual(State.attached_zc, session.state);
    try std.testing.expect(session.attached());
    session.onLinkChange();
    try std.testing.expectEqual(State.fallback_tc, session.state);
    try std.testing.expect(!session.attached());
    try std.testing.expect(!session.zerocopy);
}

test "close always ends disabled" {
    var session = Session{};
    session.beginProbe();
    const sample = probe.Sample{ .features = capable, .rx_queues = 4, .bind = .zerocopy_ok };
    session.applyProbe(sample, probe.evaluate(sample));
    session.close();
    try std.testing.expectEqual(State.disabled, session.state);
    try std.testing.expect(!session.attached());
    try std.testing.expectEqual(@as(u32, 0), session.queues);
}

test "copy attach refused unless allow_copy_mode" {
    var session = Session{ .allow_copy_mode = false };
    session.beginProbe();
    const sample = probe.Sample{ .features = capable, .rx_queues = 4, .bind = .copy_ok, .allow_copy_mode = true };
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expectEqual(State.fallback_tc, session.state);

    session.allow_copy_mode = true;
    session.beginProbe();
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expectEqual(State.attached_copy, session.state);
}

test "late probe result cannot attach a closed session" {
    var session = Session{};
    const sample = probe.Sample{ .features = capable, .rx_queues = 4, .bind = .zerocopy_ok };
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expectEqual(State.disabled, session.state);

    session.beginProbe();
    session.close();
    session.applyProbe(sample, probe.evaluate(sample));
    try std.testing.expectEqual(State.disabled, session.state);
    try std.testing.expect(!session.attached());
}
