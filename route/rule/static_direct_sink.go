package rule

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

// IsBareDirectLeaf decides whether a route target is a direct leaf.  The
// eBPF compiler deliberately delegates group expansion to its caller: a
// selector, URLTest, or Smart group is never safe to flatten into a kernel
// DIRECT verdict.
type IsBareDirectLeaf func(outboundTag string) bool

// CollectStaticDirectPrefixes exposes only rules whose complete meaning is a
// destination CIDR and a terminal direct decision.  It is intentionally
// conservative: anything requiring userspace state remains in userspace.
func CollectStaticDirectPrefixes(rules []adapter.Rule, bareDirect IsBareDirectLeaf) []netip.Prefix {
	if bareDirect == nil {
		bareDirect = func(string) bool { return false }
	}
	seen := make(map[netip.Prefix]struct{})
	var result []netip.Prefix
	add := func(prefixes []netip.Prefix) {
		for _, prefix := range prefixes {
			prefix = prefix.Masked()
			if !prefix.IsValid() {
				continue
			}
			if _, exists := seen[prefix]; exists {
				continue
			}
			seen[prefix] = struct{}{}
			result = append(result, prefix)
		}
	}
	for _, rawRule := range rules {
		rule, ok := rawRule.(*DefaultRule)
		if !ok || rule.invert || !staticDirectAction(rule.action, bareDirect) || !rule.staticDestinationOnly() {
			continue
		}
		for _, item := range rule.destinationIPCIDRItems {
			if cidr, ok := item.(*IPCIDRItem); ok {
				add(cidr.Prefixes())
			}
		}
	}
	return result
}

func staticDirectAction(action adapter.RuleAction, bareDirect IsBareDirectLeaf) bool {
	switch action := action.(type) {
	case *RuleActionBypass:
		return action.Outbound == "" || bareDirect(action.Outbound)
	case *RuleActionRoute:
		return bareDirect(action.Outbound)
	default:
		return false
	}
}

func (r *DefaultRule) staticDestinationOnly() bool {
	if len(r.destinationIPCIDRItems) == 0 || len(r.allItems) != len(r.destinationIPCIDRItems) {
		return false
	}
	for _, item := range r.allItems {
		if _, ok := item.(*IPCIDRItem); !ok {
			return false
		}
	}
	return true
}

type SourceMACOffloadVerdict uint8

const (
	SourceMACOffloadDirect SourceMACOffloadVerdict = 1
	SourceMACOffloadBlock  SourceMACOffloadVerdict = 3
)

type SourceMACPolicy struct {
	MAC     net.HardwareAddr
	Verdict SourceMACOffloadVerdict
}

// CollectSourceMACPolicies is the MAC equivalent of the CIDR compiler.  A
// source MAC condition can be offloaded only if it is the entire rule and the
// terminal action is kernel-bypass or reject/drop.
func CollectSourceMACPolicies(rules []adapter.Rule) []SourceMACPolicy {
	seen := make(map[string]struct{})
	var result []SourceMACPolicy
	for _, rawRule := range rules {
		rule, ok := rawRule.(*DefaultRule)
		if !ok || rule.invert || len(rule.allItems) == 0 || len(rule.allItems) != len(rule.items) {
			continue
		}
		allMAC := true
		for _, rawItem := range rule.allItems {
			if _, ok := rawItem.(*SourceMACAddressItem); !ok {
				allMAC = false
				break
			}
		}
		if !allMAC {
			continue
		}
		var verdict SourceMACOffloadVerdict
		switch action := rule.action.(type) {
		case *RuleActionBypass:
			if action.Outbound != "" {
				continue
			}
			verdict = SourceMACOffloadDirect
		case *RuleActionReject:
			if action.Method != C.RuleActionRejectMethodDrop {
				continue
			}
			verdict = SourceMACOffloadBlock
		default:
			continue
		}
		for _, rawItem := range rule.allItems {
			item := rawItem.(*SourceMACAddressItem)
			for _, mac := range item.MACAddresses() {
				if len(mac) != 6 {
					continue
				}
				key := mac.String()
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				result = append(result, SourceMACPolicy{MAC: append(net.HardwareAddr(nil), mac...), Verdict: verdict})
			}
		}
	}
	return result
}
