// Package v3 implements the sing-box smart eBPF data-plane v3 ABI and pure
// control-plane helpers. Kernel programs live beside this package; loading is
// Linux/cgo-only.
package v3

import (
	"fmt"
	"net/netip"
)

// ABIVersion must match SB_V3_ABI_VERSION in abi.h.
const ABIVersion = 4

const (
	AFInet  = 2
	AFInet6 = 10
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

// Verdict is the single kernel/userspace decision type (design §4).
type Verdict uint8

const (
	VerdictUnseen      Verdict = 0
	VerdictDirect      Verdict = 1
	VerdictProxy       Verdict = 2
	VerdictBlock       Verdict = 3
	VerdictMustControl Verdict = 4
)

// Source identifies who published a verdict.
type Source uint8

const (
	SourceStatic    Source = 1
	SourceExactFlow Source = 2
	SourceDNSWeak   Source = 3
	SourceFakeIP    Source = 4
)

// Reason codes mirror SB_V3_REASON_* / stats for observability.
type Reason uint16

const (
	ReasonNone                Reason = 0
	ReasonStaticDirect        Reason = 1
	ReasonFlowDirect          Reason = 2
	ReasonFakeIPDirect        Reason = 3
	ReasonDNSHintDirect       Reason = 4
	ReasonPolicyProxy         Reason = 5
	ReasonMapMissProxy        Reason = 6
	ReasonGenerationMissProxy Reason = 7
	ReasonParseFailProxy      Reason = 8
	ReasonSocketAssignOK      Reason = 9
	ReasonSocketAssignFail    Reason = 10
	ReasonBlocked             Reason = 11
	ReasonDNSHintConflict     Reason = 12
	ReasonMapCapacityReject   Reason = 13
	ReasonSecurityBypass      Reason = 14
	ReasonEstablishedBypass   Reason = 15
	ReasonStaticProxy         Reason = 16
	ReasonStaticBlock         Reason = 17
	ReasonMustControl         Reason = 18
	ReasonDNSHijackProxy      Reason = 19
	ReasonFlowProxy           Reason = 20
	ReasonFlowBlock           Reason = 21
)

const (
	ConfidenceNone          uint8 = 0
	ConfidenceWeak          uint8 = 1
	ConfidenceStrong        uint8 = 2
	ConfidenceAuthoritative uint8 = 3
)

const (
	DNSEvidenceNone   uint8 = 0
	DNSEvidenceFakeIP uint8 = 1
	DNSEvidenceStrong uint8 = 2
	DNSEvidenceWeak   uint8 = 3
)

const (
	FlagIPv4         uint32 = 1 << 0
	FlagIPv6         uint32 = 1 << 1
	FlagTCP          uint32 = 1 << 2
	FlagUDP          uint32 = 1 << 3
	FlagDNSHijack    uint32 = 1 << 4
	FlagDropUDP443   uint32 = 1 << 5
	FlagSocketAssign uint32 = 1 << 6
	FlagStaticPolicy uint32 = 1 << 7
	FlagExactFlow    uint32 = 1 << 8
	FlagDNSHint      uint32 = 1 << 9
	FlagFakeIP       uint32 = 1 << 10
	FlagMACSource    uint32 = 1 << 11
	FlagFailureProxy uint32 = 1 << 12
	FlagDNSSniff     uint32 = 1 << 13
)

const (
	DefaultFlowEntries    = 8192
	DefaultDNSHints       = 8192
	DefaultPolicyLPM      = 16384
	DefaultDynamicDirect  = 8192
	MaxFlowEntries        = 65536
	MaxDNSHints           = 32768
	MaxDNSObservations    = 4096
	DNSObservationNameMax = 128
	MaxPolicyLPM          = 65536
	StatsCount            = 32
	ListenerCount         = 4
)

// StatsValue mirrors the per-CPU telemetry vector used by the kernel ABI.
type StatsValue [StatsCount]uint64

// Control mirrors struct sb_v3_control (32 bytes).
type Control struct {
	ABIVersion       uint32
	Enabled          uint32
	Flags            uint32
	ActiveBank       uint32
	PolicyGeneration uint32
	RoutingMark      uint32
	Reserved0        uint16
	Reserved1        uint16
	Reserved2        uint32
}

// PolicyValue mirrors struct sb_v3_policy_value (20 bytes).
type PolicyValue struct {
	Verdict       uint8
	Source        uint8
	Confidence    uint8
	Reserved0     uint8
	ReasonCode    uint16
	MatchProtocol uint16
	MatchDPortMin uint16
	MatchDPortMax uint16
	PolicyID      uint32
	Generation    uint32
}

// FlowKey mirrors struct sb_v3_flow_key (40 bytes).
type FlowKey struct {
	Family    uint8
	Protocol  uint8
	Direction uint8
	Reserved0 uint8
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

// FlowValue mirrors struct sb_v3_flow_value (24 bytes).
type FlowValue struct {
	Verdict    uint8
	Source     uint8
	Confidence uint8
	Reserved0  uint8
	ReasonCode uint16
	Reserved1  uint16
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
}

// DNSIPKey mirrors struct sb_v3_dns_ip_key (20 bytes).
type DNSIPKey struct {
	Family    uint8
	Reserved0 uint8
	Reserved1 uint16
	Addr      [16]byte
}

// DNSIPValue mirrors struct sb_v3_dns_ip_value (40 bytes).
type DNSIPValue struct {
	DirectRefs uint32
	ProxyRefs  uint32
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
	LastSeenNs uint64
	Evidence   uint8
	Reserved0  uint8
	Reserved1  uint16
	Reserved2  uint32
}

// DNSObservation is a bounded plaintext UDP DNS response captured by the
// TC v3 sniffer. The kernel records the qname, one A/AAAA address, and the
// answer RR TTL; userspace remains the sole authority for applying domain
// rules and deciding whether that address may be promoted to DIRECT.
type DNSObservation struct {
	Name       string
	Address    netip.Addr
	TTLSeconds uint32
}

// LPM4Key / LPM6Key for static policy banks.
type LPM4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

type LPM6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

// Packet is the Go model of a parsed frame for decision-order unit tests.
type Packet struct {
	Family        uint8
	Protocol      uint8
	Fragmented    bool
	VLANDepth     uint8
	SPort         uint16
	DPort         uint16
	SAddr         [16]byte
	DAddr         [16]byte
	SMAC          [6]byte
	DMAC          [6]byte
	IfIndex       uint32
	Mark          uint32
	PayloadOffset uint16
	// ParseRC: 0 ok, 1 ARP-like L2, -1 unclassifiable/truncated frame. Parse
	// failures are passed to the kernel without a mark because no safe tuple
	// exists for socket assignment.
	ParseRC int
}

// ClampCapacity bounds a configured map size.
func ClampCapacity(value, def, max uint32) uint32 {
	if value == 0 {
		return def
	}
	if value > max {
		return max
	}
	return value
}

// ValidateControl rejects ABI mismatches before hot take-over.
func ValidateControl(c Control) error {
	if c.ABIVersion != ABIVersion {
		return fmt.Errorf("ebpf v3 abi mismatch: got %d want %d", c.ABIVersion, ABIVersion)
	}
	if c.ActiveBank > 1 {
		return fmt.Errorf("ebpf v3 invalid active_bank %d", c.ActiveBank)
	}
	return nil
}

// DNSHintAllowsDirect encodes design §8.2 conflict isolation.
// Weak evidence never yields first-packet DIRECT.
func DNSHintAllowsDirect(v DNSIPValue, generation uint32, nowNs uint64) (ok bool, reason Reason) {
	if v.Generation != generation {
		return false, ReasonGenerationMissProxy
	}
	if v.ExpiresNs != 0 && v.ExpiresNs <= nowNs {
		return false, ReasonMapMissProxy
	}
	if v.ProxyRefs != 0 {
		return false, ReasonDNSHintConflict
	}
	if v.DirectRefs == 0 {
		return false, ReasonMapMissProxy
	}
	switch v.Evidence {
	case DNSEvidenceFakeIP:
		return true, ReasonFakeIPDirect
	case DNSEvidenceStrong:
		return true, ReasonDNSHintDirect
	case DNSEvidenceWeak:
		return false, ReasonMustControl
	default:
		return false, ReasonMapMissProxy
	}
}

// MACKey mirrors struct sb_v3_mac_key (12 bytes): one LAN client identity.
type MACKey struct {
	Addr     [6]byte
	Reserved [2]byte
	// Ifindex 0 matches any ingress interface; a nonzero value wins over
	// the wildcard when both exist.
	Ifindex uint32
}

// MACPolicyValue mirrors struct sb_v3_source_policy_value (16 bytes).
type MACPolicyValue struct {
	Verdict    uint8 // VerdictUnseen means "no override"
	Source     uint8
	Confidence uint8
	Reserved0  uint8
	ReasonCode uint16
	Reserved1  uint16
	PolicyID   uint32
	Generation uint32
}

// MACPolicyEntry is one snapshot row published into the v3_source_mac map.
// The C mirror is struct sb_v3_mac_policy_entry (28 bytes, no padding:
// both halves are 4-byte aligned).
type MACPolicyEntry struct {
	Key   MACKey
	Value MACPolicyValue
}

const MaxSourcePolicies = 8192
