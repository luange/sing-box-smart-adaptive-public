package v3

import "testing"

func baseControl() Control {
	return Control{
		ABIVersion:       ABIVersion,
		Enabled:          1,
		Flags:            FlagIPv4 | FlagIPv6 | FlagTCP | FlagUDP | FlagSocketAssign | FlagStaticPolicy | FlagExactFlow | FlagDNSHint | FlagFakeIP,
		ActiveBank:       0,
		PolicyGeneration: 1,
		RoutingMark:      0x2b00,
	}
}

func tcpPacket(dport uint16) Packet {
	return Packet{
		Family:   AFInet,
		Protocol: ProtocolTCP,
		SPort:    12345,
		DPort:    dport,
		SAddr:    [16]byte{10, 0, 0, 2},
		DAddr:    [16]byte{1, 1, 1, 1},
		ParseRC:  0,
	}
}

func TestDecisionOrderStaticDirectFirstPacket(t *testing.T) {
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Static:  &StaticPolicy{Verdict: VerdictDirect},
	})
	if d.Action != ActionContinue || d.Reason != ReasonStaticDirect || d.Mark != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionOrderFlowAfterStaticMiss(t *testing.T) {
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Flow:    &FlowHit{Verdict: VerdictDirect},
	})
	if d.Action != ActionContinue || d.Reason != ReasonFlowDirect || d.Mark != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionOrderFlowBeforeDynamicDirect(t *testing.T) {
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Dynamic: &StaticPolicy{Verdict: VerdictDirect},
		Flow:    &FlowHit{Verdict: VerdictProxy},
	})
	if d.Action != ActionProxy || d.Reason != ReasonFlowProxy {
		t.Fatalf("exact flow must precede dynamic direct: %+v", d)
	}
	d = Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Dynamic: &StaticPolicy{Verdict: VerdictDirect},
		Flow:    &FlowHit{Verdict: VerdictBlock},
	})
	if d.Action != ActionBlock || d.Reason != ReasonFlowBlock || d.Mark != 0 {
		t.Fatalf("exact flow block must precede dynamic direct: %+v", d)
	}
}

func TestDecisionOrderStaticProxyStillBeatsDynamicDirect(t *testing.T) {
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Static:  &StaticPolicy{Verdict: VerdictProxy},
		Dynamic: &StaticPolicy{Verdict: VerdictDirect},
	})
	if d.Action != ActionProxy || d.Reason != ReasonStaticProxy {
		t.Fatalf("static proxy must beat dynamic direct: %+v", d)
	}
}

func TestDecisionMapMissNeverDirect(t *testing.T) {
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
	})
	if d.Action != ActionProxy || d.Reason != ReasonMapMissProxy {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionParseFailMarkZero(t *testing.T) {
	p := tcpPacket(443)
	p.ParseRC = -1
	d := Decide(Input{Control: baseControl(), Packet: p})
	if d.Mark != 0 || d.Reason != ReasonParseFailProxy {
		t.Fatalf("got %+v", d)
	}
	if !FailureMarkMustBeZero(d.Reason) {
		t.Fatal("parse fail must require zero mark")
	}
}

func TestDecisionFragmentNeverStaticDirect(t *testing.T) {
	p := tcpPacket(443)
	p.Fragmented = true
	d := Decide(Input{
		Control: baseControl(),
		Packet:  p,
		Static:  &StaticPolicy{Verdict: VerdictDirect},
	})
	if d.Action != ActionProxy || d.Reason != ReasonParseFailProxy {
		t.Fatalf("fragment must NEED_USERSPACE, got %+v", d)
	}
}

func TestDecisionDHCPSecurityBypass(t *testing.T) {
	p := Packet{Family: AFInet, Protocol: ProtocolUDP, SPort: 68, DPort: 67, ParseRC: 0}
	d := Decide(Input{Control: baseControl(), Packet: p})
	if d.Reason != ReasonSecurityBypass || d.Mark != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionUDP443NotDefaultDrop(t *testing.T) {
	p := Packet{Family: AFInet, Protocol: ProtocolUDP, SPort: 1234, DPort: 443, ParseRC: 0,
		SAddr: [16]byte{10, 0, 0, 2}, DAddr: [16]byte{1, 1, 1, 1}}
	d := Decide(Input{Control: baseControl(), Packet: p})
	if d.Action == ActionBlock {
		t.Fatal("UDP/443 must not default block")
	}
}

func TestDecisionExplicitUDP443Drop(t *testing.T) {
	c := baseControl()
	c.Flags |= FlagDropUDP443
	p := Packet{Family: AFInet, Protocol: ProtocolUDP, SPort: 1234, DPort: 443, ParseRC: 0}
	d := Decide(Input{Control: c, Packet: p})
	if d.Action != ActionBlock || d.Mark != 0 {
		t.Fatalf("got %+v", d)
	}
}

func TestDecisionDNSWeakNeverDirect(t *testing.T) {
	hint := DNSIPValue{
		DirectRefs: 1, ProxyRefs: 0, Generation: 1, Evidence: DNSEvidenceWeak, ExpiresNs: 100,
	}
	d := Decide(Input{
		Control:  baseControl(),
		Packet:   tcpPacket(443),
		DNS:      &hint,
		DNSNowNs: 50,
	})
	if d.Action == ActionContinue && (d.Reason == ReasonDNSHintDirect || d.Reason == ReasonFakeIPDirect) {
		t.Fatalf("weak must not direct: %+v", d)
	}
}

func TestDecisionDNSConflictMustControl(t *testing.T) {
	hint := DNSIPValue{
		DirectRefs: 1, ProxyRefs: 1, Generation: 1, Evidence: DNSEvidenceWeak, ExpiresNs: 100,
	}
	d := Decide(Input{
		Control:  baseControl(),
		Packet:   tcpPacket(443),
		DNS:      &hint,
		DNSNowNs: 50,
	})
	if d.Action != ActionProxy {
		t.Fatalf("conflict must proxy: %+v", d)
	}
}

func TestDecisionIPv6Symmetric(t *testing.T) {
	p := Packet{
		Family: AFInet6, Protocol: ProtocolTCP, SPort: 1, DPort: 443, ParseRC: 0,
		SAddr: [16]byte{0xfe, 0x80}, DAddr: [16]byte{0x20, 0x01},
	}
	d := Decide(Input{
		Control: baseControl(),
		Packet:  p,
		Static:  &StaticPolicy{Verdict: VerdictDirect},
	})
	if d.Reason != ReasonStaticDirect {
		t.Fatalf("ipv6 static: %+v", d)
	}
}

func TestDecisionStaticBeforeFlow(t *testing.T) {
	// Static BLOCK must win over flow DIRECT.
	d := Decide(Input{
		Control: baseControl(),
		Packet:  tcpPacket(443),
		Static:  &StaticPolicy{Verdict: VerdictBlock},
		Flow:    &FlowHit{Verdict: VerdictDirect},
	})
	if d.Action != ActionBlock {
		t.Fatalf("static must precede flow: %+v", d)
	}
}

func TestDecideMatchesKernelOrderDNSHijackBeforeSecurity(t *testing.T) {
	// The kernel hijacks dport 53 before host-address/multicast bypass: a
	// query aimed at the router's own DNS must reach the hijack path.
	c := baseControl()
	c.Flags |= FlagDNSHijack
	p := tcpPacket(53)
	p.Protocol = ProtocolUDP
	d := Decide(Input{Control: c, Packet: p, HostAddress: true})
	if d.Action != ActionProxy || d.Reason != ReasonDNSHijackProxy {
		t.Fatalf("got action=%d reason=%d", d.Action, d.Reason)
	}
}

func TestDecideMACSourceOverridesDestinationPolicy(t *testing.T) {
	c := baseControl()
	p := tcpPacket(443)
	d := Decide(Input{
		Control:   c,
		Packet:    p,
		MACSource: &MACSourceHit{Verdict: VerdictDirect},
		Static:    &StaticPolicy{Verdict: VerdictProxy},
	})
	if d.Action != ActionContinue || d.Reason != ReasonStaticDirect {
		t.Fatalf("mac direct: action=%d reason=%d", d.Action, d.Reason)
	}
	d = Decide(Input{
		Control:   c,
		Packet:    p,
		MACSource: &MACSourceHit{Verdict: VerdictBlock},
		Static:    &StaticPolicy{Verdict: VerdictDirect},
	})
	if d.Action != ActionBlock {
		t.Fatalf("mac block: action=%d", d.Action)
	}
}

func TestDecideDNSConflictFallsThroughLikeKernel(t *testing.T) {
	c := baseControl()
	p := tcpPacket(443)
	d := Decide(Input{
		Control: c,
		Packet:  p,
		DNS:     &DNSIPValue{DirectRefs: 1, ProxyRefs: 1, Evidence: DNSEvidenceStrong},
	})
	// Kernel counts DNS_HINT_CONFLICT and keeps walking: no static/flow/MAC
	// hit and no established socket means the packet proxies as map miss.
	if d.Action != ActionProxy || d.Reason != ReasonMapMissProxy {
		t.Fatalf("action=%d reason=%d", d.Action, d.Reason)
	}
}
