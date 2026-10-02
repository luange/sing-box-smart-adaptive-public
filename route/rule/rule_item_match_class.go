package rule

import "github.com/sagernet/sing-box/adapter"

// Every RuleItem reports the condition class it evaluates so eBPF
// verdict learn can refuse destination-level DIRECT caching when routing
// depended on domain/process/user/etc. Items that omit MatchClass still
// contribute RouteMatchUnknown via itemMatchClass (fail-closed).

var (
	_ RuleItemClass = (*IPCIDRItem)(nil)
	_ RuleItemClass = (*IPIsPrivateItem)(nil)
	_ RuleItemClass = (*IPVersionItem)(nil)
	_ RuleItemClass = (*IPAcceptAnyItem)(nil)
	_ RuleItemClass = (*PortItem)(nil)
	_ RuleItemClass = (*PortRangeItem)(nil)
	_ RuleItemClass = (*NetworkItem)(nil)
	_ RuleItemClass = (*NetworkTypeItem)(nil)
	_ RuleItemClass = (*NetworkIsExpensiveItem)(nil)
	_ RuleItemClass = (*NetworkIsConstrainedItem)(nil)
	_ RuleItemClass = (*InboundItem)(nil)
	_ RuleItemClass = (*InboundInterfaceItem)(nil)
	_ RuleItemClass = (*DomainItem)(nil)
	_ RuleItemClass = (*DomainKeywordItem)(nil)
	_ RuleItemClass = (*DomainRegexItem)(nil)
	_ RuleItemClass = (*AdGuardDomainItem)(nil)
	_ RuleItemClass = (*SourceHostnameItem)(nil)
	_ RuleItemClass = (*ProtocolItem)(nil)
	_ RuleItemClass = (*ClientItem)(nil)
	_ RuleItemClass = (*ProcessItem)(nil)
	_ RuleItemClass = (*ProcessPathItem)(nil)
	_ RuleItemClass = (*ProcessPathRegexItem)(nil)
	_ RuleItemClass = (*PackageNameItem)(nil)
	_ RuleItemClass = (*PackageNameRegexItem)(nil)
	_ RuleItemClass = (*UserItem)(nil)
	_ RuleItemClass = (*UserIdItem)(nil)
	_ RuleItemClass = (*AuthUserItem)(nil)
	_ RuleItemClass = (*ClashModeItem)(nil)
	_ RuleItemClass = (*PreferredByItem)(nil)
	_ RuleItemClass = (*PreferredByDNSItem)(nil)
	_ RuleItemClass = (*QueryTypeItem)(nil)
	_ RuleItemClass = (*QueryClientSubnetItem)(nil)
	_ RuleItemClass = (*QueryDNSSECItem)(nil)
	_ RuleItemClass = (*DNSResponseRCodeItem)(nil)
	_ RuleItemClass = (*DNSResponseRecordItem)(nil)
	_ RuleItemClass = (*OutboundItem)(nil)
	_ RuleItemClass = (*SourceMACAddressItem)(nil)
	_ RuleItemClass = (*WIFIBSSIDItem)(nil)
	_ RuleItemClass = (*WIFISSIDItem)(nil)
	_ RuleItemClass = (*RuleSetItem)(nil)
)

func (r *IPCIDRItem) MatchClass() adapter.RouteMatchInputs      { return adapter.RouteMatchIP }
func (r *IPIsPrivateItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchIP }
func (r *IPVersionItem) MatchClass() adapter.RouteMatchInputs   { return adapter.RouteMatchIP }
func (r *IPAcceptAnyItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchIP }
func (r *PortItem) MatchClass() adapter.RouteMatchInputs        { return adapter.RouteMatchPort }
func (r *PortRangeItem) MatchClass() adapter.RouteMatchInputs   { return adapter.RouteMatchPort }
func (r *NetworkItem) MatchClass() adapter.RouteMatchInputs     { return adapter.RouteMatchNetwork }
func (r *NetworkTypeItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchNetwork }
func (r *NetworkIsExpensiveItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchNetwork
}
func (r *NetworkIsConstrainedItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchNetwork
}
func (r *InboundItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchNetwork }
func (r *InboundInterfaceItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchNetwork
}
func (r *DomainItem) MatchClass() adapter.RouteMatchInputs         { return adapter.RouteMatchDomain }
func (r *DomainKeywordItem) MatchClass() adapter.RouteMatchInputs  { return adapter.RouteMatchDomain }
func (r *DomainRegexItem) MatchClass() adapter.RouteMatchInputs    { return adapter.RouteMatchDomain }
func (r *AdGuardDomainItem) MatchClass() adapter.RouteMatchInputs  { return adapter.RouteMatchDomain }
func (r *SourceHostnameItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchDomain }
func (r *ProtocolItem) MatchClass() adapter.RouteMatchInputs       { return adapter.RouteMatchProtocol }
func (r *ClientItem) MatchClass() adapter.RouteMatchInputs         { return adapter.RouteMatchProtocol }
func (r *ProcessItem) MatchClass() adapter.RouteMatchInputs        { return adapter.RouteMatchProcess }
func (r *ProcessPathItem) MatchClass() adapter.RouteMatchInputs    { return adapter.RouteMatchProcess }
func (r *ProcessPathRegexItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchProcess
}
func (r *PackageNameItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchProcess }
func (r *PackageNameRegexItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchProcess
}
func (r *UserItem) MatchClass() adapter.RouteMatchInputs      { return adapter.RouteMatchUser }
func (r *UserIdItem) MatchClass() adapter.RouteMatchInputs    { return adapter.RouteMatchUser }
func (r *AuthUserItem) MatchClass() adapter.RouteMatchInputs  { return adapter.RouteMatchUser }
func (r *ClashModeItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchOther }
func (r *PreferredByItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *PreferredByDNSItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *QueryTypeItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchOther }
func (r *QueryClientSubnetItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *QueryDNSSECItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchOther }
func (r *DNSResponseRCodeItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *DNSResponseRecordItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *OutboundItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchOther }
func (r *SourceMACAddressItem) MatchClass() adapter.RouteMatchInputs {
	return adapter.RouteMatchOther
}
func (r *WIFIBSSIDItem) MatchClass() adapter.RouteMatchInputs { return adapter.RouteMatchOther }
func (r *WIFISSIDItem) MatchClass() adapter.RouteMatchInputs  { return adapter.RouteMatchOther }

// MatchClass for rule-set items. Pure-IP → RouteMatchIP; any non-IP metadata
// ORs bits outside RouteMatchIPOnly so learn fails closed. Empty setList → Unknown.
func (r *RuleSetItem) MatchClass() adapter.RouteMatchInputs {
	if len(r.setList) == 0 {
		return adapter.RouteMatchUnknown
	}
	var class adapter.RouteMatchInputs
	for _, ruleSet := range r.setList {
		meta := ruleSet.Metadata()
		if meta.ContainsIPCIDRRule {
			class |= adapter.RouteMatchIP
		}
		if meta.ContainsProcessRule {
			class |= adapter.RouteMatchProcess
		}
		if meta.ContainsWIFIRule {
			class |= adapter.RouteMatchOther
		}
		if meta.ContainsDNSQueryTypeRule {
			class |= adapter.RouteMatchOther
		}
		if meta.ContainsNonIPCIDRRule {
			class |= adapter.RouteMatchDomain | adapter.RouteMatchOther
		}
	}
	if class == 0 {
		return adapter.RouteMatchUnknown
	}
	return class
}
