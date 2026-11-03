package v3

import (
	"fmt"
	"net/netip"
)

// RuleKind classifies whether a route rule may sink to static kernel policy.
type RuleKind int

const (
	RuleKindStatic RuleKind = iota
	RuleKindNeedsControl
	RuleKindDynamicGroup // selector/smart — never static DIRECT
)

// CompileInput is one userspace route rule after rule-set expansion.
type CompileInput struct {
	Destination netip.Prefix
	Protocol    uint8 // 0 = any
	DPortMin    uint16
	DPortMax    uint16
	Verdict     Verdict
	Kind        RuleKind
	PolicyID    uint32
	// DomainBound is true when the original rule still needs DNS/FakeIP.
	DomainBound bool
	// UsesSniff / UsesProviderRuntime / UsesNetworkType block sinking.
	UsesSniff           bool
	UsesProviderRuntime bool
	UsesNetworkType     bool
	// LeafIsGroup means final outbound is selector/urltest/smart.
	LeafIsGroup bool
}

// CompiledPolicy is ready to write into an inactive LPM bank.
type CompiledPolicy struct {
	Prefix netip.Prefix
	Value  PolicyValue
}

// CanonicalPrefix normalizes prefixes before they become policy keys. Go can
// represent an IPv4 destination as an IPv4-mapped IPv6 address; preserving
// that representation would make the same /32 land in the IPv6 LPM (or use
// the wrong prefix length) and later fail to revoke or look up the IPv4 key.
// Treat mapped prefixes as IPv4 only when their mapped portion is complete.
func CanonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix")
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid ipv4-mapped prefix length")
		}
		addr = addr.Unmap()
		bits -= 96
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// EligibleForStaticSink implements design §7.2.
func EligibleForStaticSink(in CompileInput) error {
	if in.Kind == RuleKindNeedsControl || in.Kind == RuleKindDynamicGroup {
		return fmt.Errorf("rule kind not sinkable")
	}
	if in.DomainBound {
		return fmt.Errorf("domain-bound rule cannot sink without DNS association")
	}
	if in.UsesSniff {
		return fmt.Errorf("sniff-dependent rule cannot sink")
	}
	if in.UsesProviderRuntime {
		return fmt.Errorf("provider-runtime rule cannot sink")
	}
	if in.UsesNetworkType {
		return fmt.Errorf("network-type rule cannot sink")
	}
	if in.LeafIsGroup {
		return fmt.Errorf("group outbound cannot sink as static DIRECT")
	}
	if !in.Destination.IsValid() {
		return fmt.Errorf("invalid destination prefix")
	}
	switch in.Verdict {
	case VerdictDirect, VerdictProxy, VerdictBlock, VerdictMustControl:
	default:
		return fmt.Errorf("unsupported verdict %d", in.Verdict)
	}
	// Smart/selector that happens to pick direct must not publish permanent DIRECT.
	if in.Verdict == VerdictDirect && in.LeafIsGroup {
		return fmt.Errorf("group leaf cannot be static DIRECT")
	}
	return nil
}

// CompileStatic filters and builds PolicyValues for the inactive bank.
func CompileStatic(inputs []CompileInput, generation uint32) ([]CompiledPolicy, []CompileInput, error) {
	out := make([]CompiledPolicy, 0, len(inputs))
	rejected := make([]CompileInput, 0)
	for _, in := range inputs {
		if err := EligibleForStaticSink(in); err != nil {
			rejected = append(rejected, in)
			continue
		}
		confidence := ConfidenceStrong
		if in.Verdict == VerdictMustControl {
			confidence = ConfidenceNone
		}
		out = append(out, CompiledPolicy{
			Prefix: in.Destination.Masked(),
			Value: PolicyValue{
				Verdict:       uint8(in.Verdict),
				Source:        uint8(SourceStatic),
				Confidence:    confidence,
				ReasonCode:    reasonForStatic(in.Verdict),
				MatchProtocol: uint16(in.Protocol),
				MatchDPortMin: in.DPortMin,
				MatchDPortMax: in.DPortMax,
				PolicyID:      in.PolicyID,
				Generation:    generation,
			},
		})
	}
	return out, rejected, nil
}

func reasonForStatic(v Verdict) uint16 {
	switch v {
	case VerdictDirect:
		return uint16(ReasonStaticDirect)
	case VerdictProxy:
		return uint16(ReasonStaticProxy)
	case VerdictBlock:
		return uint16(ReasonStaticBlock)
	case VerdictMustControl:
		return uint16(ReasonMustControl)
	default:
		return uint16(ReasonNone)
	}
}

// PrefixToLPM4 builds an LPM key; bits must be 0–32.
func PrefixToLPM4(p netip.Prefix) (LPM4Key, error) {
	var err error
	p, err = CanonicalPrefix(p)
	if err != nil {
		return LPM4Key{}, err
	}
	addr := p.Addr()
	if !addr.Is4() {
		return LPM4Key{}, fmt.Errorf("not ipv4 prefix")
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return LPM4Key{}, fmt.Errorf("invalid ipv4 bits")
	}
	a := addr.As4()
	return LPM4Key{PrefixLen: uint32(bits), Addr: a}, nil
}

// PrefixToLPM6 builds an LPM key for IPv6.
func PrefixToLPM6(p netip.Prefix) (LPM6Key, error) {
	var err error
	p, err = CanonicalPrefix(p)
	if err != nil {
		return LPM6Key{}, err
	}
	addr := p.Addr()
	if !addr.Is6() || addr.Is4In6() {
		// Allow only pure IPv6; Unmap 4in6 should go to LPM4.
		if addr.Is4() || addr.Is4In6() {
			return LPM6Key{}, fmt.Errorf("not ipv6 prefix")
		}
	}
	if addr.Is4() {
		return LPM6Key{}, fmt.Errorf("not ipv6 prefix")
	}
	bits := p.Bits()
	if bits < 0 || bits > 128 {
		return LPM6Key{}, fmt.Errorf("invalid ipv6 bits")
	}
	return LPM6Key{PrefixLen: uint32(bits), Addr: addr.As16()}, nil
}
