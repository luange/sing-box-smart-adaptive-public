package v3

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
	"github.com/sagernet/sing-box/option"
)

func TestNormalizeEngineDefaultV2(t *testing.T) {
	o, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if o.Engine != EngineV2 {
		t.Fatalf("engine=%s", o.Engine)
	}
	if IsV3(o) {
		t.Fatal("not v3")
	}
}

func TestNormalizeV3RequiresSocketAssign(t *testing.T) {
	f := true
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Enabled:    true,
		Engine:     EngineV3,
		DataPlane:  "token",
		DropUDP443: &f,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLifecycleLearnAndStatic(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled:     true,
		Engine:      EngineV3,
		DataPlane:   "socket_assign",
		DropUDP443:  &drop,
		FailureMode: "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled:           true,
			StaticRules:       true,
			ExactFlowLearning: true,
			DNSIPHint:         "safe",
			FakeIP:            true,
		},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.ApplyControlFlags(true, true, true, true, true, 0x2b00)

	n, rej, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil || n != 1 || rej != 0 {
		t.Fatalf("n=%d rej=%d err=%v", n, rej, err)
	}
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), true, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), false, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	key := ebpfv3.DNSIPKey{Family: ebpfv3.AFInet, Addr: [16]byte{9, 9, 9, 9}}
	v, ok := lc.backend.DNS.Lookup(key)
	if !ok || v.ProxyRefs == 0 || v.DirectRefs == 0 {
		t.Fatalf("conflict state %+v ok=%v", v, ok)
	}
	okDirect, _ := ebpfv3.DNSHintAllowsDirect(v, lc.backend.Control.PolicyGeneration, uint64(time.Now().UnixNano()))
	if okDirect {
		t.Fatal("cdn conflict must not direct")
	}
}

type memSink struct {
	static  int
	flows   int
	dns     int
	merged  int
	invalid int
	deleted int
	mac     int
	gen     uint32
	revoked []netip.Prefix

	controlWrites int
	enabled       bool
	flags         uint32
	controlErr    error
	macErr        error
	deleteErr     error
	invalidateErr error
	disableErr    error
	disabled      int
}

func (m *memSink) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	m.static += len(prefixes)
	if generation == 0 {
		m.gen++
	} else {
		m.gen = generation
	}
	return nil
}
func (m *memSink) MergeDynamicDirect(prefix netip.Prefix, _ time.Duration) error {
	if prefix.IsValid() {
		m.merged++
	}
	return nil
}
func (m *memSink) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	m.flows++
	return nil
}
func (m *memSink) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	m.deleted++
	return m.deleteErr
}
func (m *memSink) PublishMACPolicies(entries []ebpfv3.MACPolicyEntry) error {
	m.mac += len(entries)
	return m.macErr
}
func (m *memSink) DeleteMergedStaticDirect(prefix netip.Prefix) error {
	m.revoked = append(m.revoked, prefix)
	return nil
}
func (m *memSink) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	m.controlWrites++
	if m.controlErr != nil {
		return m.controlErr
	}
	m.enabled = enabled
	m.flags = flags
	return nil
}
func (m *memSink) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	m.dns++
	return nil
}
func (m *memSink) InvalidateFlowDirect() error {
	m.invalid++
	if m.invalidateErr != nil {
		return m.invalidateErr
	}
	m.gen++
	return nil
}
func (m *memSink) Disable() error {
	m.disabled++
	return m.disableErr
}
func (m *memSink) PolicyGeneration() uint32 { return m.gen }

func TestLifecycleBindSinkMirrorsKernel(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		FailureMode: "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled: true, StaticRules: true, ExactFlowLearning: true, DNSIPHint: "safe", FakeIP: true,
		},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	_, _, err = lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("1.1.1.1/32"),
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil || sink.static != 1 {
		t.Fatalf("static sink=%d err=%v", sink.static, err)
	}
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil || sink.flows != 1 {
		t.Fatalf("flow sink=%d err=%v", sink.flows, err)
	}
	lc.ObserveDNS(netip.MustParseAddr("9.9.9.9"), true, ebpfv3.DNSEvidenceStrong, time.Minute, time.Now())
	if sink.dns != 1 {
		t.Fatalf("dns sink=%d", sink.dns)
	}
	if err := lc.RevokeFlow(client, dest, ebpfv3.ProtocolTCP); err != nil || sink.deleted != 1 {
		t.Fatalf("revoke deleted=%d err=%v", sink.deleted, err)
	}
	if err := lc.InvalidateGeneration(); err != nil || sink.invalid != 1 {
		t.Fatalf("invalidate=%d err=%v", sink.invalid, err)
	}
}

func TestLifecycleBackendReturnsReadOnlyStatusSnapshot(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	snapshot := lc.Backend()
	snapshot.Control.Enabled = 0
	if lc.backend.Control.Enabled == 0 {
		t.Fatal("backend status snapshot aliases mutable control state")
	}
}

func TestLifecycleApplyControlFlagsKeepsModelWhenKernelWriteFails(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, ExactFlowLearning: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, controlErr: errors.New("kernel control write failed")}
	lc.BindSink(sink)
	before := lc.backend.Control
	if err := lc.ApplyControlFlags(true, true, true, true, true, 0x2b00); err == nil {
		t.Fatal("expected kernel control write error")
	}
	if got := lc.backend.Control; got != before {
		t.Fatalf("model control changed after kernel failure: before=%+v after=%+v", before, got)
	}
}

func TestLifecycleLearnFlowValidatesBeforeKernelWrite(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, ExactFlowLearning: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, 99, true, time.Now()); err == nil {
		t.Fatal("expected invalid protocol error")
	}
	if sink.flows != 0 {
		t.Fatalf("kernel was mutated before validation: puts=%d", sink.flows)
	}
}

func TestLifecycleMACPublishFailureQuarantinesOnlyMACFastPath(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, macErr: errors.New("partial MAC snapshot")}
	lc.BindSink(sink)
	lc.backend.Control.Flags = ebpfv3.FlagMACSource | ebpfv3.FlagExactFlow
	before := lc.backend.Control.PolicyGeneration
	err = lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{
		Key: ebpfv3.MACKey{Addr: [6]byte{1, 2, 3, 4, 5, 6}},
	}})
	if err == nil {
		t.Fatal("expected MAC publish error")
	}
	if sink.invalid != 0 || sink.gen != before {
		t.Fatalf("MAC failure unnecessarily invalidated generation: invalid=%d before=%d after=%d", sink.invalid, before, sink.gen)
	}
	if lc.backend.Control.Flags&ebpfv3.FlagMACSource != 0 {
		t.Fatal("MAC fast path remained enabled after uncertain publish")
	}
	if lc.backend.Control.Flags&ebpfv3.FlagExactFlow == 0 {
		t.Fatal("unrelated exact-flow flag was cleared")
	}
	if len(lc.backend.MACPolicies) != 0 {
		t.Fatal("model MAC snapshot changed after kernel publish failure")
	}
	if err := lc.ApplyControlFlags(true, true, true, true, true, 0); err != nil {
		t.Fatal(err)
	}
	if sink.flags&ebpfv3.FlagMACSource != 0 {
		t.Fatal("quarantined MAC fast path was re-enabled by control refresh")
	}
	// A later complete snapshot clears the quarantine and permits the flag
	// again; recovery must not require a process restart.
	sink.macErr = nil
	if err := lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{Key: ebpfv3.MACKey{Addr: [6]byte{1, 2, 3, 4, 5, 6}}}}); err != nil {
		t.Fatal(err)
	}
	if sink.flags&ebpfv3.FlagMACSource == 0 {
		t.Fatal("successful replacement did not immediately re-enable MAC fast path")
	}
	if lc.backend.Control.Flags&ebpfv3.FlagMACSource == 0 {
		t.Fatal("model MAC flag was not restored after successful replacement")
	}
	if err := lc.ApplyControlFlags(true, true, true, true, true, 0); err != nil {
		t.Fatal(err)
	}
	if sink.flags&ebpfv3.FlagMACSource == 0 {
		t.Fatal("successful snapshot did not clear MAC quarantine")
	}
}

func TestLifecycleMACPublishKeepsQuarantineLocalWhenEscalationIsNotNeeded(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, macErr: errors.New("partial MAC snapshot"), invalidateErr: errors.New("generation bump failed")}
	lc.BindSink(sink)
	lc.backend.Control.Flags |= ebpfv3.FlagMACSource
	err = lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{
		Key: ebpfv3.MACKey{Addr: [6]byte{6, 5, 4, 3, 2, 1}},
	}})
	if err == nil {
		t.Fatal("expected MAC publish recovery error")
	}
	if lc.backend.Control.Flags&ebpfv3.FlagMACSource != 0 {
		t.Fatal("MAC fast path remained enabled after recovery failure")
	}
	if sink.invalid != 0 {
		t.Fatalf("local MAC quarantine should not escalate when control write succeeds: invalid=%d", sink.invalid)
	}
}

func TestLifecycleMACPublishEscalatesToGenerationOnControlFailure(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, macErr: errors.New("partial MAC snapshot"), controlErr: errors.New("control write failed")}
	lc.BindSink(sink)
	lc.backend.Control.Flags = ebpfv3.FlagMACSource | ebpfv3.FlagExactFlow
	before := lc.backend.Control.PolicyGeneration
	if err := lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{Key: ebpfv3.MACKey{Addr: [6]byte{1, 1, 1, 1, 1, 1}}}}); err == nil {
		t.Fatal("expected MAC publish recovery error")
	}
	if sink.invalid != 1 || sink.gen == before {
		t.Fatalf("control failure did not escalate to generation invalidation: invalid=%d before=%d after=%d", sink.invalid, before, sink.gen)
	}
}

func TestLifecycleMACPublishDisablesWholeDataplaneAsLastResort(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{
		gen: 1, macErr: errors.New("partial MAC snapshot"),
		controlErr: errors.New("control write failed"), invalidateErr: errors.New("generation bump failed"),
	}
	lc.BindSink(sink)
	lc.backend.Control.Flags = ebpfv3.FlagMACSource
	if err := lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{Key: ebpfv3.MACKey{Addr: [6]byte{2, 2, 2, 2, 2, 2}}}}); err == nil {
		t.Fatal("expected MAC publish recovery error")
	}
	if sink.disabled != 1 {
		t.Fatalf("whole dataplane fuse not used: disabled=%d", sink.disabled)
	}
	if lc.backend.Control.Enabled != 0 {
		t.Fatal("model still reports dataplane enabled after last-resort fuse")
	}
	_ = lc.ApplyControlFlags(true, true, true, true, true, 0)
	if sink.enabled || lc.backend.Control.Enabled != 0 {
		t.Fatal("ordinary control refresh resurrected a quarantined dataplane")
	}
}

func TestLifecycleFailedWholeDataplaneFuseRemainsQuarantined(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{
		gen: 1, macErr: errors.New("partial MAC snapshot"),
		controlErr: errors.New("control write failed"), invalidateErr: errors.New("generation bump failed"),
		disableErr: errors.New("dataplane disable failed"),
	}
	lc.BindSink(sink)
	if err := lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{Key: ebpfv3.MACKey{Addr: [6]byte{4, 4, 4, 4, 4, 4}}}}); err == nil {
		t.Fatal("expected MAC publish recovery error")
	}
	_ = lc.ApplyControlFlags(true, true, true, true, true, 0)
	if sink.enabled || lc.backend.Control.Enabled != 0 {
		t.Fatal("failed whole-dataplane fuse was not sticky")
	}
}

func TestLifecycleMACQuarantinePreservesDisabledDataplane(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, MACSourcePolicy: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, macErr: errors.New("partial MAC snapshot")}
	lc.BindSink(sink)
	lc.backend.Control.Enabled = 0
	if err := lc.PublishMACSourcePolicies([]ebpfv3.MACPolicyEntry{{Key: ebpfv3.MACKey{Addr: [6]byte{3, 3, 3, 3, 3, 3}}}}); err == nil {
		t.Fatal("expected MAC publish error")
	}
	if sink.enabled {
		t.Fatal("MAC recovery unexpectedly re-enabled a disabled dataplane")
	}
}

func TestLifecycleRevokeFlowKeepsModelWhenKernelDeleteFails(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, ExactFlowLearning: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, deleteErr: errors.New("kernel delete failed")}
	lc.BindSink(sink)
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := lc.RevokeFlow(client, dest, ebpfv3.ProtocolTCP); err == nil {
		t.Fatal("expected kernel revoke error")
	}
	pair, err := ebpfv3.BuildFlowPair(ebpfv3.FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ebpfv3.ProtocolTCP,
		Verdict: ebpfv3.VerdictProxy,
	}, lc.backend.Control.PolicyGeneration, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lc.backend.Flows[pair.Forward]; !ok {
		t.Fatal("model flow was removed after kernel revoke failure")
	}
}

func TestLifecycleInvalidateGenerationKeepsModelWhenKernelBumpFails(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, ExactFlowLearning: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1, invalidateErr: errors.New("kernel generation bump failed")}
	lc.BindSink(sink)
	client := netip.MustParseAddrPort("10.0.0.2:1111")
	dest := netip.MustParseAddrPort("8.8.8.8:443")
	if err := lc.LearnFlow(client, dest, ebpfv3.ProtocolTCP, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := lc.backend.Control.PolicyGeneration
	if err := lc.InvalidateGeneration(); err == nil {
		t.Fatal("expected kernel generation bump error")
	}
	if got := lc.backend.Control.PolicyGeneration; got != before {
		t.Fatalf("model generation changed after kernel failure: before=%d after=%d", before, got)
	}
	pair, err := ebpfv3.BuildFlowPair(ebpfv3.FlowPublishRequest{
		Client: client, Destination: dest, Protocol: ebpfv3.ProtocolTCP,
		Verdict: ebpfv3.VerdictProxy,
	}, before, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lc.backend.Flows[pair.Forward]; !ok {
		t.Fatal("model flow was removed after kernel generation failure")
	}
}

func TestLifecyclePublishStaticRulesKeepsScopedDirectInUserspace(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	accepted, rejected, err := lc.PublishStaticRules([]ebpfv3.CompileInput{{
		Destination: netip.MustParsePrefix("203.0.113.0/24"),
		Protocol:    ebpfv3.ProtocolTCP,
		DPortMin:    443,
		DPortMax:    443,
		Verdict:     ebpfv3.VerdictDirect,
		Kind:        ebpfv3.RuleKindStatic,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 || rejected != 1 {
		t.Fatalf("accepted=%d rejected=%d want 0/1", accepted, rejected)
	}
	if sink.static != 0 {
		t.Fatalf("scoped direct rule reached broad static sink: %d prefixes", sink.static)
	}
}

func TestLifecyclePublishStaticDirectMirrorsMemorySnapshot(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		FailureMode:   "proxy",
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	prefix := netip.MustParsePrefix("203.0.113.7/32")
	if err := lc.PublishStaticDirect([]netip.Prefix{prefix, prefix}); err != nil {
		t.Fatal(err)
	}
	if sink.static != 1 {
		t.Fatalf("kernel snapshot received %d prefixes", sink.static)
	}
	if got := lc.backend.LookupStatic(prefix.Addr(), ebpfv3.ProtocolTCP, 443); got == nil {
		t.Fatal("memory snapshot did not receive direct prefix")
	} else if got.Verdict != uint8(ebpfv3.VerdictDirect) || got.Source != uint8(ebpfv3.SourceStatic) {
		t.Fatalf("unexpected memory policy: %+v", *got)
	}
	if lc.backend.Control.PolicyGeneration != sink.gen {
		t.Fatalf("generation diverged: memory=%d kernel=%d", lc.backend.Control.PolicyGeneration, sink.gen)
	}
}

func TestLifecycleStaticPreparationBlocksKernelOnModelConflict(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	if _, ok := lc.backend.Publisher.BeginCompile(); !ok {
		t.Fatal("failed to reserve model compile")
	}
	defer lc.backend.Publisher.AbortCompile()
	if err := lc.PublishStaticDirect([]netip.Prefix{netip.MustParsePrefix("203.0.113.8/32")}); err == nil {
		t.Fatal("expected model preparation conflict")
	}
	if sink.static != 0 {
		t.Fatalf("kernel was mutated before model preparation completed: %d prefixes", sink.static)
	}
}

func TestLifecycleGenerationSyncKeepsPublisherMonotonic(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	lc.SyncPolicyGeneration(10)
	lc.SyncPolicyGeneration(12)
	if got := lc.backend.Publisher.Generation(); got != 12 {
		t.Fatalf("publisher generation=%d want 12", got)
	}
	if err := lc.backend.PublishStatic(nil); err != nil {
		t.Fatal(err)
	}
	if got := lc.backend.Control.PolicyGeneration; got != 13 {
		t.Fatalf("control generation=%d want 13", got)
	}
}

func TestLifecycleMergeStaticDirectMirrorsSinkAndModel(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled: true, Engine: EngineV3, DataPlane: "socket_assign", DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{gen: 1}
	lc.BindSink(sink)
	prefix := netip.MustParsePrefix("203.0.113.10/32")
	if err := lc.MergeStaticDirect(prefix); err != nil {
		t.Fatal(err)
	}
	if sink.merged != 1 {
		t.Fatalf("sink merges=%d", sink.merged)
	}
	if got := lc.backend.LookupDynamicDirect(prefix.Addr(), ebpfv3.ProtocolTCP, 443); got == nil {
		t.Fatal("memory model did not receive merged policy")
	}
}

func TestControlFlagsNoDefaultQUICDrop(t *testing.T) {
	f := false
	flags := ControlFlags(option.EBPFSharedNetworkOptions{
		DataPlane:     "socket_assign",
		DropUDP443:    &f,
		PolicyOffload: option.EBPFPolicyOffloadOptions{Enabled: true, StaticRules: true},
	}, true, true, true, true, true, 0)
	if flags&ebpfv3.FlagDropUDP443 != 0 {
		t.Fatal("quic drop must be off")
	}
	if flags&ebpfv3.FlagStaticPolicy == 0 || flags&ebpfv3.FlagSocketAssign == 0 {
		t.Fatalf("flags=%x", flags)
	}
}

func TestControlFlagsDNSSniffFollowsDNSHintOnly(t *testing.T) {
	base := option.EBPFSharedNetworkOptions{
		DataPlane: "socket_assign",
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled: true,
		},
	}
	if flags := ControlFlags(base, true, true, true, true, true, 0); flags&ebpfv3.FlagDNSSniff != 0 {
		t.Fatalf("dns_ip_hint=off must not set DNS sniffer flag: %#x", flags)
	}

	fakeOnly := base
	fakeOnly.PolicyOffload.FakeIP = true
	if flags := ControlFlags(fakeOnly, true, true, true, true, true, 0); flags&ebpfv3.FlagDNSSniff != 0 {
		t.Fatalf("FakeIP-only mode must not set DNS sniffer flag: %#x", flags)
	}

	strong := base
	strong.PolicyOffload.DNSIPHint = "strong"
	if flags := ControlFlags(strong, true, true, true, true, true, 0); flags&ebpfv3.FlagDNSSniff == 0 {
		t.Fatalf("dns_ip_hint=strong must set DNS sniffer flag: %#x", flags)
	}
}

func TestLifecyclePublishMACSourcePolicies(t *testing.T) {
	drop := false
	newLifecycle := func(macSource bool) *Lifecycle {
		t.Helper()
		lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
			Enabled:    true,
			Engine:     EngineV3,
			DataPlane:  "socket_assign",
			DropUDP443: &drop,
			PolicyOffload: option.EBPFPolicyOffloadOptions{
				Enabled:         true,
				MACSourcePolicy: macSource,
			},
		}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return lc
	}
	entries := []ebpfv3.MACPolicyEntry{{
		Key:   ebpfv3.MACKey{Addr: [6]byte{0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03}},
		Value: ebpfv3.MACPolicyValue{Verdict: uint8(ebpfv3.VerdictDirect), Confidence: ebpfv3.ConfidenceAuthoritative},
	}}

	// Disabled policy is a no-op in both representations.
	lc := newLifecycle(false)
	defer lc.Close()
	sink := &memSink{}
	lc.BindSink(sink)
	if err := lc.PublishMACSourcePolicies(entries); err != nil {
		t.Fatal(err)
	}
	if sink.mac != 0 || len(lc.backend.MACPolicies) != 0 {
		t.Fatalf("disabled mac policy published: sink=%d model=%d", sink.mac, len(lc.backend.MACPolicies))
	}

	// Enabled policy mirrors to sink and model with generation tagging.
	lc2 := newLifecycle(true)
	defer lc2.Close()
	sink2 := &memSink{}
	lc2.BindSink(sink2)
	if err := lc2.PublishMACSourcePolicies(entries); err != nil {
		t.Fatal(err)
	}
	if sink2.mac != 1 {
		t.Fatalf("sink entries=%d", sink2.mac)
	}
	if len(lc2.backend.MACPolicies) != 1 {
		t.Fatalf("model entries=%d", len(lc2.backend.MACPolicies))
	}
	for _, value := range lc2.backend.MACPolicies {
		if value.Generation == 0 {
			t.Fatal("mac row not generation-tagged")
		}
		if value.Source != uint8(ebpfv3.SourceStatic) {
			t.Fatalf("unexpected source %d", value.Source)
		}
	}

	// An empty snapshot retires all rows (authoritative replace).
	if err := lc2.PublishMACSourcePolicies(nil); err != nil {
		t.Fatal(err)
	}
	if len(lc2.backend.MACPolicies) != 0 {
		t.Fatalf("stale mac rows survived snapshot replace: %d", len(lc2.backend.MACPolicies))
	}
}

// The shared-IP generalisation guard end-to-end: promote merges a /32 into
// the active banks; a later conflicting observation revokes it from both the
// sink and the memory model.
func TestLifecycleRevokeMergedStaticDirect(t *testing.T) {
	drop := false
	lc, err := NewLifecycle(option.EBPFSharedNetworkOptions{
		Enabled:    true,
		Engine:     EngineV3,
		DataPlane:  "socket_assign",
		DropUDP443: &drop,
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled:     true,
			StaticRules: true,
			FakeIP:      true,
			DNSIPHint:   "safe",
		},
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	sink := &memSink{}
	lc.BindSink(sink)

	promoted := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32)
	if err := lc.MergeStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if got := lc.backend.LookupDynamicDirect(promoted.Addr(), ebpfv3.ProtocolTCP, 443); got == nil {
		t.Fatal("promoted prefix missing after merge")
	}
	if err := lc.RevokeMergedStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if got := lc.backend.LookupDynamicDirect(promoted.Addr(), ebpfv3.ProtocolTCP, 443); got != nil {
		t.Fatal("revoked prefix still in memory bank")
	}
	if len(sink.revoked) != 1 || sink.revoked[0] != promoted {
		t.Fatalf("sink revocations=%v", sink.revoked)
	}
}
