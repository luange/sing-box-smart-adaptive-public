package rule

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func collectMACPolicies(t *testing.T, action option.RuleAction, items []RuleItem) []SourceMACPolicy {
	t.Helper()
	rule := &DefaultRule{abstractDefaultRule{
		action:   mustAction(t, action),
		items:    items,
		allItems: items,
	}}
	return rule.sourceMACPolicies(make(map[string]struct{}))
}

func mustAction(t *testing.T, action option.RuleAction) adapter.RuleAction {
	t.Helper()
	a, err := NewRuleAction(context.Background(), nil, action)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func macItem(macs ...string) *SourceMACAddressItem {
	return NewSourceMACAddressItem(macs)
}

func TestCollectSourceMACPoliciesDirect(t *testing.T) {
	policies := collectMACPolicies(t, option.RuleAction{Action: C.RuleActionTypeDirect},
		[]RuleItem{macItem("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")})
	if len(policies) != 2 {
		t.Fatalf("policies=%d", len(policies))
	}
	for _, policy := range policies {
		if policy.Verdict != SourceMACOffloadDirect {
			t.Fatalf("verdict=%d", policy.Verdict)
		}
		if len(policy.MAC) != 6 {
			t.Fatalf("mac=%v", policy.MAC)
		}
	}
}

func TestCollectSourceMACPoliciesRejectDrop(t *testing.T) {
	policies := collectMACPolicies(t, option.RuleAction{Action: C.RuleActionTypeReject, RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDrop}},
		[]RuleItem{macItem("aa:bb:cc:dd:ee:ff")})
	if len(policies) != 1 || policies[0].Verdict != SourceMACOffloadBlock {
		t.Fatalf("policies=%#v", policies)
	}
}

func TestCollectSourceMACPoliciesRejectDefaultNotSinkable(t *testing.T) {
	policies := collectMACPolicies(t, option.RuleAction{Action: C.RuleActionTypeReject},
		[]RuleItem{macItem("aa:bb:cc:dd:ee:ff")})
	if len(policies) != 0 {
		t.Fatalf("default reject must stay in userspace: %#v", policies)
	}
}

func TestCollectSourceMACPoliciesMixedItemsNotSinkable(t *testing.T) {
	domain := &SourceHostnameItem{hostnames: []string{"example.org"}}
	policies := collectMACPolicies(t, option.RuleAction{Action: C.RuleActionTypeDirect},
		[]RuleItem{macItem("aa:bb:cc:dd:ee:ff"), domain})
	if len(policies) != 0 {
		t.Fatalf("mixed-condition rule over-broadens in kernel: %#v", policies)
	}
}

func TestCollectSourceMACPoliciesRouteTargetNotSinkable(t *testing.T) {
	policies := collectMACPolicies(t, option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "proxy"}},
		[]RuleItem{macItem("aa:bb:cc:dd:ee:ff")})
	if len(policies) != 0 {
		t.Fatalf("route-to-proxy is a userspace decision: %#v", policies)
	}
}
