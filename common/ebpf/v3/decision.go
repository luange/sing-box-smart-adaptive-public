package v3

// Action is the TC-facing outcome after the fixed decision order.
type Action uint8

const (
	ActionContinue Action = iota // TC_ACT_OK without mark (DIRECT / bypass / leave alone)
	ActionProxy                  // NEED_USERSPACE handoff
	ActionBlock                  // TC_ACT_SHOT
)

// Decision is the pure model of tc_ingress §5 — unit-tested without a kernel.
type Decision struct {
	Action Action
	Reason Reason
	Mark   uint32 // must be 0 on Direct/Block/security/parse-fail
}

// StaticPolicy is one compiled LPM hit (already generation-checked by caller).
type StaticPolicy struct {
	Verdict Verdict
}

// MACSourceHit is one source-MAC identity policy hit (generation-checked by
// caller). Verdict follows the kernel sb_v3_source_policy_value semantics.
type MACSourceHit struct {
	Verdict Verdict
}

// FlowHit is one exact-flow hit (already generation/TTL-checked by caller).
type FlowHit struct {
	Verdict Verdict
}

// Input gathers maps/control state for one packet decision.
type Input struct {
	Control Control
	Packet  Packet
	Static  *StaticPolicy
	// Dynamic is a learned DIRECT prefix kept in the separate expiring map.
	// It is consulted after the authoritative static snapshot and before exact
	// flow state, matching tc.bpf.c.
	Dynamic        *StaticPolicy
	Flow           *FlowHit
	MACSource      *MACSourceHit
	DNS            *DNSIPValue
	DNSNowNs       uint64
	EstablishedTCP bool
	// HostAddress mirrors the kernel v3_host4/6 membership consulted by
	// security_bypass; it must be precomputed by the caller.
	HostAddress bool
}

// Decide implements the literal tc.bpf.c ingress order (design §5). The model
// and the kernel must agree step for step; when the kernel order changes, this
// function and its tests change with it.
func Decide(in Input) Decision {
	c := in.Control
	p := in.Packet

	if c.Enabled == 0 || c.ABIVersion != ABIVersion {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}

	// tc step 1: parse failure. A malformed/non-IP frame has no trustworthy
	// tuple with which to assign a listener, so fail open without mark.
	if p.ParseRC < 0 {
		return Decision{Action: ActionContinue, Reason: ReasonParseFailProxy, Mark: 0}
	}

	// tc step 2: DNS interception precedes host-address bypass. PBR deployments
	// send DNS to an address owned by this host; if security_bypass ran first,
	// those packets would reach the local stack with no :53 listener.
	if p.ParseRC == 0 && c.Flags&FlagDNSHijack != 0 &&
		(p.Protocol == ProtocolTCP || p.Protocol == ProtocolUDP) && p.DPort == 53 {
		return proxyDecision(c, ReasonDNSHijackProxy)
	}

	// tc step 3: security bypass (parse_rc==1, ICMP, DHCP, multicast,
	// broadcast, host-owned addresses).
	if p.ParseRC == 1 || securityBypass(p) || in.HostAddress {
		return Decision{Action: ActionContinue, Reason: ReasonSecurityBypass, Mark: 0}
	}

	// tc step 4: IP fragments — never static/flow/MAC DIRECT; NEED_USERSPACE.
	if p.Fragmented {
		return proxyDecision(c, ReasonParseFailProxy)
	}

	// tc step 5: family/protocol feature gates.
	if p.Family == AFInet && c.Flags&FlagIPv4 == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Family == AFInet6 && c.Flags&FlagIPv6 == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol == ProtocolTCP && c.Flags&FlagTCP == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol == ProtocolUDP && c.Flags&FlagUDP == 0 {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}
	if p.Protocol != ProtocolTCP && p.Protocol != ProtocolUDP {
		return Decision{Action: ActionContinue, Reason: ReasonNone, Mark: 0}
	}

	// tc step 6: explicit block only.
	if c.Flags&FlagDropUDP443 != 0 && p.Protocol == ProtocolUDP && p.DPort == 443 {
		return Decision{Action: ActionBlock, Reason: ReasonBlocked, Mark: 0}
	}

	// tc step 7: source-MAC identity policy overrides destination defaults.
	if in.MACSource != nil {
		switch in.MACSource.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonStaticDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonStaticBlock, Mark: 0}
		case VerdictProxy, VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// tc step 8: static policy.
	if in.Static != nil {
		switch in.Static.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonStaticDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonStaticBlock, Mark: 0}
		case VerdictProxy:
			return proxyDecision(c, ReasonStaticProxy)
		case VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// tc step 9: exact-flow. It is more specific than a destination-wide
	// learned prefix, so an explicit flow verdict (including PROXY/BLOCK)
	// must win over dynamic DIRECT evidence for the same destination.
	if in.Flow != nil {
		switch in.Flow.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonFlowDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonFlowBlock, Mark: 0}
		case VerdictProxy:
			return proxyDecision(c, ReasonFlowProxy)
		case VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// tc step 10: learned dynamic DIRECT promotions. They never override an
	// authoritative static rule or an exact-flow verdict.
	if in.Dynamic != nil {
		switch in.Dynamic.Verdict {
		case VerdictDirect:
			return Decision{Action: ActionContinue, Reason: ReasonDNSHintDirect, Mark: 0}
		case VerdictBlock:
			return Decision{Action: ActionBlock, Reason: ReasonStaticBlock, Mark: 0}
		case VerdictProxy:
			return proxyDecision(c, ReasonStaticProxy)
		case VerdictMustControl:
			return proxyDecision(c, ReasonMustControl)
		}
	}

	// tc step 11: DNS/FakeIP allows direct. A conflict does NOT proxy in the
	// kernel — it only counts DNS_HINT_CONFLICT and falls through, so the
	// model falls through too.
	if in.DNS != nil {
		if ok, reason := DNSHintAllowsDirect(*in.DNS, c.PolicyGeneration, in.DNSNowNs); ok {
			return Decision{Action: ActionContinue, Reason: reason, Mark: 0}
		}
	}

	// tc step 12: established-TCP socket assignment bypass.
	if in.EstablishedTCP {
		return Decision{Action: ActionContinue, Reason: ReasonEstablishedBypass, Mark: 0}
	}

	// tc step 13: default NEED_USERSPACE.
	return proxyDecision(c, ReasonMapMissProxy)
}

func proxyDecision(c Control, reason Reason) Decision {
	mark := uint32(0)
	// Mark only on successful handoff path intent; model assumes assign will set it.
	// Parse-fail/security already returned Mark 0. For proxy we expose routing mark
	// as the intended mark *after* listener is known — unit tests check failure paths
	// keep 0 via separate FailureMark helpers.
	if c.Flags&FlagSocketAssign != 0 && c.RoutingMark != 0 {
		mark = c.RoutingMark
	}
	return Decision{Action: ActionProxy, Reason: reason, Mark: mark}
}

// FailureMarkMustBeZero documents branches that must never pollute fwmark.
func FailureMarkMustBeZero(reason Reason) bool {
	switch reason {
	case ReasonParseFailProxy, ReasonSecurityBypass, ReasonStaticDirect, ReasonFlowDirect,
		ReasonFakeIPDirect, ReasonDNSHintDirect, ReasonBlocked, ReasonStaticBlock,
		ReasonFlowBlock, ReasonEstablishedBypass, ReasonNone:
		return true
	default:
		return false
	}
}

func securityBypass(p Packet) bool {
	if p.Protocol == 1 || p.Protocol == 58 { // ICMP / ICMPv6
		return true
	}
	if p.Protocol == ProtocolUDP {
		switch p.SPort {
		case 67, 68, 546, 547:
			return true
		}
		switch p.DPort {
		case 67, 68, 546, 547:
			return true
		}
	}
	if p.Family == AFInet {
		if p.DAddr[0]&0xf0 == 0xe0 {
			return true
		}
		if p.DAddr[0] == 255 && p.DAddr[1] == 255 && p.DAddr[2] == 255 && p.DAddr[3] == 255 {
			return true
		}
	}
	if p.Family == AFInet6 && p.DAddr[0] == 0xff {
		return true
	}
	return false
}
