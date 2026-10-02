//! Pure packet classify + XDP action mapping.
//! Proxy / unseen / must-control never redirect. DIRECT redirects only when attached.

const model = @import("model.zig");

pub const Packet = struct {
    family: u8 = model.af_inet,
    protocol: u8 = model.proto_tcp,
    sport: u16 = 0,
    dport: u16 = 0,
    parse_ok: bool = true,
    fragmented: bool = false,
    multicast: bool = false,
    broadcast: bool = false,
    /// The on-wire TCP flags byte.  XDP can only accelerate a clean SYN;
    /// ACK/FIN/RST and an absent parse stay in the kernel.  UDP ignores it.
    tcp_flags: u8 = 0,
};

pub const StaticHit = struct {
    verdict: model.Verdict,
    generation: u32,
};

pub const FlowHit = struct {
    verdict: model.Verdict,
    generation: u32,
};

pub const DnsHint = struct {
    direct_refs: u32 = 0,
    proxy_refs: u32 = 0,
    generation: u32 = 0,
    expires_ns: u64 = 0,
    evidence: model.Evidence = .none,
};

pub const Input = struct {
    enabled: bool = true,
    abi_ok: bool = true,
    generation: u32 = 1,
    now_ns: u64 = 0,
    xdp_attached: bool = false,
    /// Whether the per-queue XSKMAP slot is populated.  An attached program
    /// with an empty slot must fail open to the kernel.
    xsk_slot_present: bool = false,
    drop_udp_443: bool = false,
    packet: Packet = .{},
    static_hit: ?StaticHit = null,
    flow_hit: ?FlowHit = null,
    dns: ?DnsHint = null,
    established_tcp: bool = false,
};

pub const Decision = struct {
    verdict: model.Verdict,
    action: model.XdpAction,
    reason: model.Reason,
};

fn xdpAction(verdict: model.Verdict, attached: bool, slot_present: bool) model.XdpAction {
    return switch (verdict) {
        .direct => if (attached and slot_present) .redirect else .pass,
        .block => .drop,
        .unseen, .proxy, .must_control => .pass,
    };
}

fn decide(verdict: model.Verdict, reason: model.Reason, attached: bool, slot_present: bool) Decision {
    return .{
        .verdict = verdict,
        .action = xdpAction(verdict, attached, slot_present),
        .reason = reason,
    };
}

fn pass(verdict: model.Verdict, reason: model.Reason) Decision {
    return .{ .verdict = verdict, .action = .pass, .reason = reason };
}

fn securityBypass(p: Packet) bool {
    if (p.protocol == model.proto_icmp or p.protocol == model.proto_icmpv6) return true;
    if (p.multicast or p.broadcast) return true;
    if (p.protocol == model.proto_udp) {
        switch (p.sport) {
            67, 68, 546, 547 => return true,
            else => {},
        }
        switch (p.dport) {
            67, 68, 546, 547 => return true,
            else => {},
        }
    }
    return false;
}

fn generationOk(hit_generation: u32, active: u32) bool {
    return hit_generation != 0 and hit_generation == active;
}

fn tcpFirstPacket(p: Packet) bool {
    if (p.protocol != model.proto_tcp) return true;
    return (p.tcp_flags & 0x02) != 0 and (p.tcp_flags & 0x15) == 0;
}

fn dnsAllowsDirect(hint: DnsHint, generation: u32, now_ns: u64) bool {
    if (!generationOk(hint.generation, generation)) return false;
    if (hint.expires_ns != 0 and now_ns >= hint.expires_ns) return false;
    if (hint.direct_refs == 0 or hint.proxy_refs != 0) return false;
    return switch (hint.evidence) {
        .fakeip, .strong => true,
        .none, .weak => false,
    };
}

/// Fixed order matching v3 TC §5, with XDP actions from design §3.1.
pub fn classify(in: Input) Decision {
    if (!in.enabled or !in.abi_ok) {
        return pass(.unseen, .none);
    }

    const p = in.packet;
    if (!p.parse_ok) {
        return pass(.proxy, .parse_fail_proxy);
    }
    if (securityBypass(p)) {
        return pass(.unseen, .security_bypass);
    }
    if (p.fragmented) {
        return pass(.proxy, .parse_fail_proxy);
    }
    // Established TCP belongs to the kernel socket.  This guard must precede
    // static/flow/DNS hits so a stale DIRECT hint cannot redirect an existing
    // connection into AF_XDP.
    if (in.established_tcp and p.protocol == model.proto_tcp) {
        return pass(.unseen, .established_bypass);
    }
    if (!tcpFirstPacket(p)) {
        return pass(.unseen, .established_bypass);
    }
    if (in.drop_udp_443 and p.protocol == model.proto_udp and p.dport == 443) {
        return decide(.block, .blocked, false, false);
    }

    if (in.static_hit) |hit| {
        if (!generationOk(hit.generation, in.generation)) {
            return pass(.proxy, .generation_miss_proxy);
        }
        switch (hit.verdict) {
            .direct => return decide(.direct, .static_direct, in.xdp_attached, in.xsk_slot_present),
            .block => return decide(.block, .static_block, false, false),
            .proxy => return pass(.proxy, .static_proxy),
            .must_control => return pass(.must_control, .must_control),
            .unseen => {},
        }
    }

    if (in.flow_hit) |hit| {
        if (!generationOk(hit.generation, in.generation)) {
            return pass(.proxy, .generation_miss_proxy);
        }
        switch (hit.verdict) {
            .direct => return decide(.direct, .flow_direct, in.xdp_attached, in.xsk_slot_present),
            .block => return decide(.block, .static_block, false, false),
            .proxy => return pass(.proxy, .flow_proxy),
            .must_control => return pass(.must_control, .must_control),
            .unseen => {},
        }
    }

    if (in.dns) |hint| {
        if (hint.direct_refs > 0 and hint.proxy_refs > 0) {
            return pass(.must_control, .dns_hint_conflict);
        }
        if (dnsAllowsDirect(hint, in.generation, in.now_ns)) {
            const reason: model.Reason = if (hint.evidence == .fakeip) .fakeip_direct else .dns_hint_direct;
            return decide(.direct, reason, in.xdp_attached, in.xsk_slot_present);
        }
        if (hint.evidence == .weak and hint.direct_refs > 0 and hint.proxy_refs == 0) {
            return pass(.proxy, .weak_dns_proxy);
        }
    }

    return pass(.proxy, .map_miss_proxy);
}

const std = @import("std");

fn tcp(dport: u16) Packet {
    return .{ .protocol = model.proto_tcp, .sport = 12345, .dport = dport, .tcp_flags = 0x02 };
}

fn base(packet: Packet) Input {
    return .{ .generation = 1, .packet = packet };
}

test "static direct redirects only when attached" {
    const hit = StaticHit{ .verdict = .direct, .generation = 1 };
    const detached = classify(.{ .generation = 1, .packet = tcp(443), .static_hit = hit, .xdp_attached = false });
    try std.testing.expectEqual(model.Verdict.direct, detached.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, detached.action);
    try std.testing.expectEqual(model.Reason.static_direct, detached.reason);

    const attached = classify(.{ .generation = 1, .packet = tcp(443), .static_hit = hit, .xdp_attached = true, .xsk_slot_present = true });
    try std.testing.expectEqual(model.XdpAction.redirect, attached.action);
    try std.testing.expectEqual(model.Verdict.direct, attached.verdict);
}

test "map miss never redirects" {
    const d = classify(.{ .generation = 1, .packet = tcp(443), .xdp_attached = true });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.map_miss_proxy, d.reason);
}

test "proxy verdict never redirects" {
    const d = classify(.{
        .generation = 1,
        .packet = tcp(443),
        .xdp_attached = true,
        .xsk_slot_present = true,
        .static_hit = .{ .verdict = .proxy, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.static_proxy, d.reason);
}

test "dns conflict must control" {
    const d = classify(.{
        .generation = 1,
        .packet = tcp(443),
        .xdp_attached = true,
        .xsk_slot_present = true,
        .dns = .{
            .direct_refs = 1,
            .proxy_refs = 1,
            .generation = 1,
            .evidence = .strong,
        },
    });
    try std.testing.expectEqual(model.Verdict.must_control, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.dns_hint_conflict, d.reason);
}

test "parse fail passes to kernel" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = true,
        .packet = .{ .parse_ok = false, .dport = 443 },
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.parse_fail_proxy, d.reason);
}

test "fragment never first-packet direct" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = true,
        .packet = .{ .fragmented = true, .dport = 443 },
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
}

test "udp 443 not dropped by default" {
    const packet = Packet{ .protocol = model.proto_udp, .dport = 443 };
    const open = classify(base(packet));
    try std.testing.expect(open.action != .drop);
    try std.testing.expectEqual(model.Verdict.proxy, open.verdict);

    const blocked = classify(.{ .generation = 1, .packet = packet, .drop_udp_443 = true });
    try std.testing.expectEqual(model.Verdict.block, blocked.verdict);
    try std.testing.expectEqual(model.XdpAction.drop, blocked.action);
}

test "security bypass never redirects" {
    const dhcp = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .packet = .{ .protocol = model.proto_udp, .sport = 68, .dport = 67 },
    });
    try std.testing.expectEqual(model.Reason.security_bypass, dhcp.reason);
    try std.testing.expectEqual(model.XdpAction.pass, dhcp.action);

    const mcast = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .packet = .{ .multicast = true, .dport = 443 },
    });
    try std.testing.expectEqual(model.XdpAction.pass, mcast.action);
}

test "established tcp never redirects" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .packet = tcp(443),
        .established_tcp = true,
    });
    try std.testing.expectEqual(model.Reason.established_bypass, d.reason);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
}

test "weak dns hint is proxy" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .packet = tcp(443),
        .dns = .{
            .direct_refs = 1,
            .proxy_refs = 0,
            .generation = 1,
            .evidence = .weak,
        },
    });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.weak_dns_proxy, d.reason);
}

test "generation miss is proxy" {
    const d = classify(.{
        .generation = 2,
        .xdp_attached = true,
        .packet = tcp(443),
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.proxy, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.generation_miss_proxy, d.reason);
}

test "ipv4 ipv6 tcp udp share mapping" {
    const families = [_]u8{ model.af_inet, model.af_inet6 };
    const protos = [_]u8{ model.proto_tcp, model.proto_udp };
    for (families) |family| {
        for (protos) |protocol| {
            const miss = classify(.{
                .generation = 1,
                .xdp_attached = true,
                .xsk_slot_present = true,
                .packet = .{ .family = family, .protocol = protocol, .dport = 443, .tcp_flags = if (protocol == model.proto_tcp) 0x02 else 0 },
            });
            try std.testing.expectEqual(model.Verdict.proxy, miss.verdict);
            try std.testing.expectEqual(model.XdpAction.pass, miss.action);

            const direct = classify(.{
                .generation = 1,
                .xdp_attached = true,
                .xsk_slot_present = true,
                .packet = .{ .family = family, .protocol = protocol, .dport = 443, .tcp_flags = if (protocol == model.proto_tcp) 0x02 else 0 },
                .static_hit = .{ .verdict = .direct, .generation = 1 },
            });
            try std.testing.expectEqual(model.Verdict.direct, direct.verdict);
            try std.testing.expectEqual(model.XdpAction.redirect, direct.action);
        }
    }
}

test "authoritative fakeip may redirect when attached" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = true,
        .packet = tcp(443),
        .dns = .{
            .direct_refs = 1,
            .proxy_refs = 0,
            .generation = 1,
            .evidence = .fakeip,
        },
    });
    try std.testing.expectEqual(model.Verdict.direct, d.verdict);
    try std.testing.expectEqual(model.XdpAction.redirect, d.action);
    try std.testing.expectEqual(model.Reason.fakeip_direct, d.reason);
}

test "disabled program passes without redirect" {
    const d = classify(.{
        .enabled = false,
        .xdp_attached = true,
        .packet = tcp(443),
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.none, d.reason);
}

test "empty xsk slot fails open" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = false,
        .packet = tcp(443),
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.direct, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
}

test "established tcp wins over direct hit" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = true,
        .packet = tcp(443),
        .established_tcp = true,
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.unseen, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.established_bypass, d.reason);
}

test "tcp ack stays in kernel even with direct policy" {
    const d = classify(.{
        .generation = 1,
        .xdp_attached = true,
        .xsk_slot_present = true,
        .packet = .{ .protocol = model.proto_tcp, .sport = 12345, .dport = 443, .tcp_flags = 0x10 },
        .static_hit = .{ .verdict = .direct, .generation = 1 },
    });
    try std.testing.expectEqual(model.Verdict.unseen, d.verdict);
    try std.testing.expectEqual(model.XdpAction.pass, d.action);
    try std.testing.expectEqual(model.Reason.established_bypass, d.reason);
}
