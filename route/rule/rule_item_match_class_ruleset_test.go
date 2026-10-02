package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

type matchClassRuleSet struct {
	meta adapter.RuleSetMetadata
}

func (s *matchClassRuleSet) Name() string { return "match-class-fake" }
func (s *matchClassRuleSet) StartContext(context.Context, *adapter.HTTPStartContext) error {
	return nil
}
func (s *matchClassRuleSet) Metadata() adapter.RuleSetMetadata { return s.meta }
func (s *matchClassRuleSet) ExtractIPSet() []*netipx.IPSet     { return nil }
func (s *matchClassRuleSet) IncRef()                           {}
func (s *matchClassRuleSet) DecRef()                           {}
func (s *matchClassRuleSet) Cleanup()                          {}
func (s *matchClassRuleSet) RegisterCallback(adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	return nil
}
func (s *matchClassRuleSet) UnregisterCallback(*list.Element[adapter.RuleSetUpdateCallback]) {}
func (s *matchClassRuleSet) Close() error                                                    { return nil }
func (s *matchClassRuleSet) Match(*adapter.InboundContext) bool                              { return false }
func (s *matchClassRuleSet) String() string                                                  { return "match-class-fake" }

func TestRuleSetItemMatchClassPureIP(t *testing.T) {
	item := &RuleSetItem{setList: []adapter.RuleSet{&matchClassRuleSet{
		meta: adapter.RuleSetMetadata{ContainsIPCIDRRule: true},
	}}}
	got := item.MatchClass()
	if got&adapter.RouteMatchIP == 0 {
		t.Fatalf("pure geoip rule-set must contribute RouteMatchIP, got %#b", got)
	}
	if got&^adapter.RouteMatchIPOnly != 0 {
		t.Fatalf("pure IP rule-set leaked non-IP bits: %#b", got)
	}
}

func TestRuleSetItemMatchClassDomainBlocksLearn(t *testing.T) {
	item := &RuleSetItem{setList: []adapter.RuleSet{&matchClassRuleSet{
		meta: adapter.RuleSetMetadata{ContainsIPCIDRRule: true, ContainsNonIPCIDRRule: true},
	}}}
	got := item.MatchClass()
	if got&adapter.RouteMatchDomain == 0 {
		t.Fatalf("domain-bearing rule-set must set Domain, got %#b", got)
	}
	if got&^adapter.RouteMatchIPOnly == 0 {
		t.Fatal("expected non-IP-only bits so verdict learn fails closed")
	}
}

func TestRuleSetItemMatchClassEmptyUnknown(t *testing.T) {
	item := &RuleSetItem{}
	if item.MatchClass() != adapter.RouteMatchUnknown {
		t.Fatal("empty setList must be Unknown (fail-closed)")
	}
}
