//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
)

// collectV3StaticPrefixes builds the full first-packet DIRECT snapshot:
// bypass_rule_set (+ promotions) ∪ pure-IP route rules → bare DIRECT.
func collectV3StaticPrefixes(parent *ECommon.Backend, routeRouter adapter.Router, outbounds adapter.OutboundManager) []netip.Prefix {
	var prefixes []netip.Prefix
	seen := make(map[netip.Prefix]struct{}, 256)
	add := func(list []netip.Prefix) {
		for _, p := range list {
			p = p.Masked()
			if !p.IsValid() {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			prefixes = append(prefixes, p)
		}
	}
	if parent != nil {
		add(parent.ListBypassCIDR())
	}
	if routeRouter != nil {
		bare := func(tag string) bool {
			return isBareDirectOutbound(outbounds, tag)
		}
		add(R.CollectStaticDirectPrefixes(routeRouter.Rules(), bare))
	}
	return prefixes
}

func isBareDirectOutbound(outbounds adapter.OutboundManager, tag string) bool {
	if outbounds == nil {
		return false
	}
	var ob adapter.Outbound
	if tag == "" {
		ob = outbounds.Default()
	} else {
		var ok bool
		ob, ok = outbounds.Outbound(tag)
		if !ok || ob == nil {
			return false
		}
	}
	if ob == nil {
		return false
	}
	// Only bare direct/ebpf — never selector/smart/urltest groups.
	switch ob.Type() {
	case C.TypeDirect, C.TypeEBPF:
		return true
	default:
		return false
	}
}
