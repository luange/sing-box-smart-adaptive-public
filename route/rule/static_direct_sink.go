package rule

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// IsBareDirectLeaf reports whether an outbound tag is a bare DIRECT leaf
// (no selector/smart/urltest). Empty tag means "use default" — caller decides.
type IsBareDirectLeaf func(outboundTag string) bool

// CollectStaticDirectPrefixes walks route rules and extracts destination CIDRs
// that are safe to sink as first-packet kernel DIRECT (design §7.2):
//
//   - not inverted
//   - action is direct / bypass(kernel) / route→bare DIRECT
//   - match items are IP-only (plus optional network/port — still destination L3/L4)
//   - no domain/process/sniff/provider runtime identity
//
// Rule-set IP extracts are included only when the rule-set metadata is pure IP
// (no domain half). Callers merge with bypass_rule_set and clamp capacity.
func CollectStaticDirectPrefixes(rules []adapter.Rule, bareDirect IsBareDirectLeaf) []netip.Prefix {
	if bareDirect == nil {
		bareDirect = func(string) bool { return false }
	}
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	add := func(prefixes []netip.Prefix) {
		for _, p := range prefixes {
			p = p.Masked()
			if !p.IsValid() {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		switch r := rule.(type) {
		case *DefaultRule:
			add(r.staticDirectPrefixes(bareDirect))
		case *LogicalRule:
			// Logical OR/AND of mixed identity is not sink-safe without full
			// compilation; skip (fail closed to userspace).
			_ = r
		}
	}
	return out
}

// SourceMACOffloadVerdict is the kernel verdict a MAC-source rule sinks to.
type SourceMACOffloadVerdict uint8

const (
	// SourceMACOffloadDirect sinks the rule to first-packet kernel DIRECT.
	SourceMACOffloadDirect SourceMACOffloadVerdict = 1
	// SourceMACOffloadBlock sinks the rule to kernel drop (TC_ACT_SHOT).
	// Only reject-method=drop qualifies; default reject replies ICMP in
	// userspace and must not be turned into a silent kernel drop.
	SourceMACOffloadBlock SourceMACOffloadVerdict = 3
)

// SourceMACPolicy is one MAC-keyed verdict safe to sink into the v3
// source-MAC policy map (design §7.3).
type SourceMACPolicy struct {
	MAC     net.HardwareAddr
	Verdict SourceMACOffloadVerdict
}

// CollectSourceMACPolicies walks route rules and extracts MAC-keyed verdicts
// that are safe to offload:
//
//   - not inverted
//   - action is direct / bypass(kernel-direct) / route→bare DIRECT, or
//     reject with method=drop
//   - every match item is a source-MAC item (the kernel cannot evaluate
//     domain/process/destination conditions, so mixing over-broadens)
//   - no rule-set attachment
//
// MAC rules only narrow identity; they never override a userspace-needed
// decision, so PROXY/MustControl verdicts are intentionally not collected —
// unmatched traffic still reaches userspace by default.
func CollectSourceMACPolicies(rules []adapter.Rule) []SourceMACPolicy {
	var out []SourceMACPolicy
	seen := make(map[string]struct{})
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		defaultRule, ok := rule.(*DefaultRule)
		if !ok {
			// LogicalRule combinations are not kernel-evaluable; fail closed.
			continue
		}
		out = append(out, defaultRule.sourceMACPolicies(seen)...)
	}
	return out
}

func (r *DefaultRule) sourceMACPolicies(seen map[string]struct{}) []SourceMACPolicy {
	if r == nil || r.invert {
		return nil
	}
	var verdict SourceMACOffloadVerdict
	switch a := r.action.(type) {
	case *RuleActionDirect:
		verdict = SourceMACOffloadDirect
	case *RuleActionBypass:
		if a.Outbound == "" {
			verdict = SourceMACOffloadDirect
		} else {
			return nil
		}
	case *RuleActionRoute:
		return nil // route targets need userspace selection; not sinkable
	case *RuleActionReject:
		if a.Method != C.RuleActionRejectMethodDrop {
			return nil
		}
		verdict = SourceMACOffloadBlock
	default:
		return nil
	}
	// Every match item must be a source-MAC item.
	if len(r.allItems) == 0 || len(r.items) != len(r.allItems) {
		return nil
	}
	var policies []SourceMACPolicy
	for _, item := range r.allItems {
		macItem, ok := item.(*SourceMACAddressItem)
		if !ok {
			return nil
		}
		for _, mac := range macItem.MACAddresses() {
			if len(mac) != 6 {
				continue
			}
			key := mac.String()
			if _, loaded := seen[key]; loaded {
				continue
			}
			seen[key] = struct{}{}
			policies = append(policies, SourceMACPolicy{MAC: append(net.HardwareAddr(nil), mac...), Verdict: verdict})
		}
	}
	return policies
}

func (r *DefaultRule) staticDirectPrefixes(bareDirect IsBareDirectLeaf) []netip.Prefix {
	if r == nil || r.invert {
		return nil
	}
	if !actionIsStaticDirect(r.action, bareDirect) {
		return nil
	}
	if !r.matchItemsSinkable() {
		return nil
	}
	var out []netip.Prefix
	for _, item := range r.destinationIPCIDRItems {
		if cidr, ok := item.(*IPCIDRItem); ok {
			out = append(out, cidr.Prefixes()...)
		}
	}
	// Pure IP rule-sets attached as destination matchers.
	if r.ruleSetItem != nil && !r.ruleSetItem.ipCidrMatchSource {
		for _, rs := range r.ruleSetItem.setList {
			meta := rs.Metadata()
			if !meta.ContainsIPCIDRRule || meta.ContainsNonIPCIDRRule {
				continue
			}
			for _, ipSet := range rs.ExtractIPSet() {
				if ipSet != nil {
					out = append(out, ipSet.Prefixes()...)
				}
			}
		}
	}
	return out
}

func actionIsStaticDirect(action adapter.RuleAction, bareDirect IsBareDirectLeaf) bool {
	if action == nil {
		return false
	}
	switch a := action.(type) {
	case *RuleActionDirect:
		return true
	case *RuleActionBypass:
		// Empty outbound = kernel bypass / true direct.
		if a.Outbound == "" {
			return true
		}
		return bareDirect(a.Outbound)
	case *RuleActionRoute:
		return bareDirect(a.Outbound)
	default:
		return false
	}
}

// matchItemsSinkable: destination-IP-only rules (v3 LPM is dst CIDR without port yet).
func (r *DefaultRule) matchItemsSinkable() bool {
	if r == nil {
		return false
	}
	// Port/network/source identity would over-broaden dst-only LPM → skip.
	if len(r.sourceAddressItems) > 0 || len(r.sourcePortItems) > 0 ||
		len(r.destinationPortItems) > 0 {
		return false
	}
	hasDestIP := len(r.destinationIPCIDRItems) > 0
	if r.ruleSetItem != nil && !r.ruleSetItem.ipCidrMatchSource {
		for _, rs := range r.ruleSetItem.setList {
			meta := rs.Metadata()
			if meta.ContainsIPCIDRRule && !meta.ContainsNonIPCIDRRule {
				hasDestIP = true
				break
			}
		}
	}
	if !hasDestIP {
		return false
	}
	var classes adapter.RouteMatchInputs
	for _, item := range r.allItems {
		classes |= itemMatchClass(item)
	}
	if r.ruleSetItem != nil {
		classes |= itemMatchClass(r.ruleSetItem)
	}
	// Strict: only IP class bits (no domain/process/unknown/port/network).
	if classes == 0 || classes&^adapter.RouteMatchIP != 0 {
		return false
	}
	return true
}
