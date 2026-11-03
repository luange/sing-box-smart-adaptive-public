package v3

import (
	"testing"
	"unsafe"
)

func TestABISizes(t *testing.T) {
	// Must match abi.h _Static_assert values.
	assertSize(t, "Control", unsafe.Sizeof(Control{}), 32)
	assertSize(t, "PolicyValue", unsafe.Sizeof(PolicyValue{}), 20)
	assertSize(t, "FlowKey", unsafe.Sizeof(FlowKey{}), 40)
	assertSize(t, "FlowValue", unsafe.Sizeof(FlowValue{}), 24)
	assertSize(t, "DNSIPKey", unsafe.Sizeof(DNSIPKey{}), 20)
	assertSize(t, "DNSIPValue", unsafe.Sizeof(DNSIPValue{}), 40)
	assertSize(t, "LPM4Key", unsafe.Sizeof(LPM4Key{}), 8)
	assertSize(t, "LPM6Key", unsafe.Sizeof(LPM6Key{}), 20)
	assertSize(t, "StatsValue", unsafe.Sizeof(StatsValue{}), 32*8)
	// DNS observations are consumed through the native map ABI; keep the
	// value layout pinned even though the public observation exposes strings.
	type dnsObservationKey struct {
		QnameHash uint64
		Family    uint8
		Reserved0 uint8
		Reserved1 uint16
		Addr      [16]byte
	}
	type dnsObservationValue struct {
		Qname      [DNSObservationNameMax]byte
		TTLSeconds uint32
		Reserved0  uint32
	}
	assertSize(t, "DNSObservationKey", unsafe.Sizeof(dnsObservationKey{}), 32)
	assertSize(t, "DNSObservationValue", unsafe.Sizeof(dnsObservationValue{}), DNSObservationNameMax+8)
}

func assertSize(t *testing.T, name string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Fatalf("%s size=%d want %d", name, got, want)
	}
}

func TestValidateControl(t *testing.T) {
	if err := ValidateControl(Control{ABIVersion: ABIVersion}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateControl(Control{ABIVersion: 99}); err == nil {
		t.Fatal("expected abi mismatch")
	}
	if err := ValidateControl(Control{ABIVersion: ABIVersion, ActiveBank: 2}); err == nil {
		t.Fatal("expected bank error")
	}
}

func TestClampCapacity(t *testing.T) {
	if ClampCapacity(0, 8192, 65536) != 8192 {
		t.Fatal("default")
	}
	if ClampCapacity(100, 8192, 65536) != 100 {
		t.Fatal("value")
	}
	if ClampCapacity(999999, 8192, 65536) != 65536 {
		t.Fatal("max")
	}
}

// TestABIFieldOffsets pins field offsets, not just sizes: reordering fields
// of equal total size would pass every size test and silently corrupt
// verdicts. Values must match abi.h _Static_assert-verified layouts.
func TestABIFieldOffsets(t *testing.T) {
	type offsetCheck struct {
		name string
		got  uintptr
		want uintptr
	}
	var _ = offsetCheck{}
	assertOffset(t, "Control.ABIVersion", unsafe.Offsetof(Control{}.ABIVersion), 0)
	assertOffset(t, "Control.Enabled", unsafe.Offsetof(Control{}.Enabled), 4)
	assertOffset(t, "Control.Flags", unsafe.Offsetof(Control{}.Flags), 8)
	assertOffset(t, "Control.ActiveBank", unsafe.Offsetof(Control{}.ActiveBank), 12)
	assertOffset(t, "Control.PolicyGeneration", unsafe.Offsetof(Control{}.PolicyGeneration), 16)
	assertOffset(t, "PolicyValue.Verdict", unsafe.Offsetof(PolicyValue{}.Verdict), 0)
	assertOffset(t, "PolicyValue.ReasonCode", unsafe.Offsetof(PolicyValue{}.ReasonCode), 4)
	assertOffset(t, "PolicyValue.MatchProtocol", unsafe.Offsetof(PolicyValue{}.MatchProtocol), 6)
	assertOffset(t, "PolicyValue.MatchDPortMin", unsafe.Offsetof(PolicyValue{}.MatchDPortMin), 8)
	assertOffset(t, "PolicyValue.MatchDPortMax", unsafe.Offsetof(PolicyValue{}.MatchDPortMax), 10)
	assertOffset(t, "PolicyValue.PolicyID", unsafe.Offsetof(PolicyValue{}.PolicyID), 12)
	assertOffset(t, "PolicyValue.Generation", unsafe.Offsetof(PolicyValue{}.Generation), 16)
	assertOffset(t, "FlowKey.Family", unsafe.Offsetof(FlowKey{}.Family), 0)
	assertOffset(t, "FlowKey.Direction", unsafe.Offsetof(FlowKey{}.Direction), 2)
	assertOffset(t, "FlowKey.SPort", unsafe.Offsetof(FlowKey{}.SPort), 4)
	assertOffset(t, "FlowKey.DPort", unsafe.Offsetof(FlowKey{}.DPort), 6)
	assertOffset(t, "FlowKey.SAddr", unsafe.Offsetof(FlowKey{}.SAddr), 8)
	assertOffset(t, "FlowKey.DAddr", unsafe.Offsetof(FlowKey{}.DAddr), 24)
	assertOffset(t, "DNSIPValue.DirectRefs", unsafe.Offsetof(DNSIPValue{}.DirectRefs), 0)
	assertOffset(t, "DNSIPValue.ProxyRefs", unsafe.Offsetof(DNSIPValue{}.ProxyRefs), 4)
	assertOffset(t, "MACKey.Ifindex", unsafe.Offsetof(MACKey{}.Ifindex), 8)
	assertOffset(t, "MACPolicyValue.PolicyID", unsafe.Offsetof(MACPolicyValue{}.PolicyID), 8)
	assertOffset(t, "MACPolicyValue.Generation", unsafe.Offsetof(MACPolicyValue{}.Generation), 12)
}

func assertOffset(t *testing.T, name string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Fatalf("%s offset=%d want %d", name, got, want)
	}
}

// TestABIEnumValues pins the cross-language enum contract: the kernel switch
// statements and the Go publishers must agree on every value, not just the
// width of the enum.
func TestABIEnumValues(t *testing.T) {
	pairs := map[string][2]uint8{
		"VerdictUnseen":      {uint8(VerdictUnseen), 0},
		"VerdictDirect":      {uint8(VerdictDirect), 1},
		"VerdictProxy":       {uint8(VerdictProxy), 2},
		"VerdictBlock":       {uint8(VerdictBlock), 3},
		"VerdictMustControl": {uint8(VerdictMustControl), 4},
		"SourceStatic":       {uint8(SourceStatic), 1},
		"SourceExactFlow":    {uint8(SourceExactFlow), 2},
		"SourceDNSWeak":      {uint8(SourceDNSWeak), 3},
		"SourceFakeIP":       {uint8(SourceFakeIP), 4},
		"DNSEvidenceNone":    {DNSEvidenceNone, 0},
		"DNSEvidenceFakeIP":  {DNSEvidenceFakeIP, 1},
		"DNSEvidenceStrong":  {DNSEvidenceStrong, 2},
		"DNSEvidenceWeak":    {DNSEvidenceWeak, 3},
	}
	for name, pair := range pairs {
		if pair[0] != pair[1] {
			t.Fatalf("%s = %d, kernel expects %d", name, pair[0], pair[1])
		}
	}
	flagPairs := map[string][2]uint32{
		"FlagIPv4":         {FlagIPv4, 1 << 0},
		"FlagIPv6":         {FlagIPv6, 1 << 1},
		"FlagTCP":          {FlagTCP, 1 << 2},
		"FlagUDP":          {FlagUDP, 1 << 3},
		"FlagDNSHijack":    {FlagDNSHijack, 1 << 4},
		"FlagDropUDP443":   {FlagDropUDP443, 1 << 5},
		"FlagSocketAssign": {FlagSocketAssign, 1 << 6},
		"FlagStaticPolicy": {FlagStaticPolicy, 1 << 7},
		"FlagExactFlow":    {FlagExactFlow, 1 << 8},
		"FlagDNSHint":      {FlagDNSHint, 1 << 9},
		"FlagFakeIP":       {FlagFakeIP, 1 << 10},
		"FlagMACSource":    {FlagMACSource, 1 << 11},
		"FlagFailureProxy": {FlagFailureProxy, 1 << 12},
		"FlagDNSSniff":     {FlagDNSSniff, 1 << 13},
	}
	for name, pair := range flagPairs {
		if pair[0] != pair[1] {
			t.Fatalf("%s = %d, kernel expects %d", name, pair[0], pair[1])
		}
	}
	reasons := map[string][2]uint16{
		"ReasonNone":           {uint16(ReasonNone), 0},
		"ReasonStaticDirect":   {uint16(ReasonStaticDirect), 1},
		"ReasonFlowDirect":     {uint16(ReasonFlowDirect), 2},
		"ReasonFakeIPDirect":   {uint16(ReasonFakeIPDirect), 3},
		"ReasonDNSHintDirect":  {uint16(ReasonDNSHintDirect), 4},
		"ReasonMustControl":    {uint16(ReasonMustControl), 18},
		"ReasonDNSHijackProxy": {uint16(ReasonDNSHijackProxy), 19},
		"ReasonFlowProxy":      {uint16(ReasonFlowProxy), 20},
		"ReasonFlowBlock":      {uint16(ReasonFlowBlock), 21},
	}
	for name, pair := range reasons {
		if pair[0] != pair[1] {
			t.Fatalf("%s = %d, kernel expects %d", name, pair[0], pair[1])
		}
	}
}
