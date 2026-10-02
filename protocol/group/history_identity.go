package group

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

// historyKeyForOutbound resolves a group to its current leaf before deriving
// the URL-test identity. Display aliases are never part of the history key.
func historyKeyForOutbound(manager adapter.OutboundManager, detour adapter.Outbound, link, network string) urltest.HistoryKey {
	if manager != nil {
		realTag := RealTag(manager, detour)
		if leaf, loaded := manager.Outbound(realTag); loaded {
			detour = leaf
		}
	}
	return urltest.KeyForOutbound(detour, link, network)
}
