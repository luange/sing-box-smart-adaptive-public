package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	U "github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestLoadBalanceRandomPrefersAvailableMembers(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(secondOutbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyRandom(loadBalanceGroup, "")
	for range 16 {
		if selected := loadBalanceGroup.Unwrap(new(adapter.InboundContext), true); selected != secondOutbound {
			t.Fatalf("random balance selected unavailable member %v", selected)
		}
	}
}

func TestLoadBalancePersistentHashKeepsHostAffinity(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	now := time.Now()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(firstOutbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 20})
	history.StoreURLTestHistoryKey(U.KeyForOutbound(secondOutbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 30})
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyConsistentHashing(loadBalanceGroup, "")
	metadata := &adapter.InboundContext{Domain: "example.com"}
	selected := loadBalanceGroup.Unwrap(metadata, true)
	for range 16 {
		if got := loadBalanceGroup.Unwrap(metadata, true); got != selected {
			t.Fatalf("persistent balance changed host affinity from %v to %v", selected, got)
		}
	}
}

func TestLoadBalanceStickySessionRemapsAfterProviderRefresh(t *testing.T) {
	first := &preMatchTestOutbound{tag: "first"}
	sticky := &preMatchTestOutbound{tag: "sticky"}
	third := &preMatchTestOutbound{tag: "third"}
	history := U.NewHistoryStorage()
	now := time.Now()
	for _, outbound := range []adapter.Outbound{first, sticky, third} {
		history.StoreURLTestHistoryKey(U.KeyForOutbound(outbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 20})
	}
	group := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{first, sticky, third},
		history:   history,
	}
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, _ int) int {
		// The old implementation stored this as index 1. After refresh that
		// index points at third, while the identity record must still resolve to
		// sticky at its new index 0.
		return 1
	})
	metadata := new(adapter.InboundContext)
	if selected := group.Unwrap(metadata, true); selected != sticky {
		t.Fatalf("initial sticky selection=%v, want sticky", selected)
	}
	group.replaceOutbounds([]adapter.Outbound{sticky, third})
	if selected := group.Unwrap(metadata, true); selected != sticky {
		t.Fatalf("sticky selection after refresh=%v, want sticky", selected)
	}
}

func TestLoadBalanceStickySessionReSelectsAfterCredentialRefresh(t *testing.T) {
	first := &providerDialTestNode{providerTestNode: providerTestNode{tag: "first", identity: "path-a"}, dialIdentity: "dial-a"}
	remaining := &providerDialTestNode{providerTestNode: providerTestNode{tag: "remaining", identity: "path-x"}, dialIdentity: "dial-b"}
	other := &providerDialTestNode{providerTestNode: providerTestNode{tag: "other", identity: "path-x"}, dialIdentity: "dial-c"}
	history := U.NewHistoryStorage()
	now := time.Now()
	for _, outbound := range []adapter.Outbound{first, remaining, other} {
		history.StoreURLTestHistoryKey(U.KeyForOutbound(outbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 20})
	}
	group := &LoadBalanceGroup{outbounds: []adapter.Outbound{first, remaining, other}, history: history}
	selectedIndex := 0
	group.strategyFn = strategyStickySessionsWithIndex(group, func(_ uint64, length int) int {
		if selectedIndex >= length {
			t.Fatalf("selected index %d exceeds member count %d", selectedIndex, length)
		}
		return selectedIndex
	})
	metadata := new(adapter.InboundContext)
	if selected := group.Unwrap(metadata, true); selected != first {
		t.Fatalf("initial sticky selection=%v, want first", selected)
	}
	// Remove the authenticated member. The two remaining nodes intentionally
	// share its path; a sticky lookup must miss and re-run the strategy rather
	// than silently selecting the first path match.
	group.replaceOutbounds([]adapter.Outbound{remaining, other})
	selectedIndex = 1
	if selected := group.Unwrap(metadata, true); selected != other {
		t.Fatalf("sticky refresh migrated by path/order to %v, want strategy result other", selected)
	}
}

func TestLoadBalanceUDPFailureDoesNotPoisonTCPHealth(t *testing.T) {
	outbound := &preMatchTestOutbound{tag: "udp-node"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(outbound, "", N.NetworkTCP), &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	profiles := newNodeProfileRegistry(context.Background())
	defer profiles.close()
	endpointKey, profileKey := groupTCPProfileKey(outbound, "")
	if _, err, _ := profiles.runProbeMode(context.Background(), endpointKey, profileKey, time.Second, time.Minute, false, func(context.Context) (uint16, error) {
		return 20, nil
	}); err != nil {
		t.Fatal(err)
	}
	group := &LoadBalanceGroup{
		history:         history,
		profileRegistry: profiles,
	}
	profiles.recordPassive(groupUDPProfileKey(outbound), false, 0, groupPassiveFailureTTL)
	if !group.memberAvailable(outbound, &adapter.InboundContext{Network: N.NetworkTCP}) {
		t.Fatal("UDP failure suppressed TCP member")
	}
	if group.memberAvailable(outbound, &adapter.InboundContext{Network: N.NetworkUDP}) {
		t.Fatal("UDP failure did not suppress UDP member")
	}
	if history.LoadURLTestHistoryKey(U.KeyForOutbound(outbound, "", N.NetworkTCP)) == nil {
		t.Fatal("UDP failure removed TCP URL-test history")
	}
}

func TestLoadBalanceSelectPreMatchOutboundWithMetadata(t *testing.T) {
	selectedOutbound := new(preMatchTestOutbound)
	metadata := &adapter.InboundContext{Network: N.NetworkUDP}
	var receivedMetadata *adapter.InboundContext
	var receivedTouch bool
	loadBalance := &LoadBalance{
		group: &LoadBalanceGroup{
			strategyFn: func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
				receivedMetadata = metadata
				receivedTouch = touch
				if matcher != nil && !matcher(selectedOutbound) {
					return nil
				}
				return selectedOutbound
			},
		},
	}

	outbound, action := loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, selectedOutbound, outbound)
	require.Equal(t, adapter.PreMatchFlow, action)
	require.Same(t, metadata, receivedMetadata)
	require.True(t, receivedTouch)
}

func TestLoadBalancePreMatchDoesNotConsumeIneligibleRoundRobinSelection(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(firstOutbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	history.StoreURLTestHistoryKey(U.KeyForOutbound(secondOutbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, "")
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction) {
		return nil, adapter.PreMatchContinue
	})
	require.Nil(t, selectedOutbound)
	require.Equal(t, adapter.PreMatchContinue, action)
	require.Same(t, firstOutbound, loadBalanceGroup.Unwrap(metadata, true))
}

func TestLoadBalancePreMatchAdvancesAcceptedRoundRobinSelection(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first"}
	secondOutbound := &preMatchTestOutbound{tag: "second"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(firstOutbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	history.StoreURLTestHistoryKey(U.KeyForOutbound(secondOutbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{firstOutbound, secondOutbound},
		history:   history,
	}
	loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, "")
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, firstOutbound, selectedOutbound)
	require.Equal(t, adapter.PreMatchFlow, action)
	selectedOutbound, action = loadBalance.SelectPreMatchOutbound(metadata, selectPreMatchFlow)
	require.Same(t, secondOutbound, selectedOutbound)
	require.Equal(t, adapter.PreMatchFlow, action)
}

func TestLoadBalanceStickyPreMatchReusesIneligibleSelectionForL4(t *testing.T) {
	nonL3Outbound := &preMatchTestOutbound{tag: "non-l3"}
	l3Outbound := &preMatchTestOutbound{tag: "l3"}
	history := U.NewHistoryStorage()
	history.StoreURLTestHistoryKey(U.KeyForOutbound(nonL3Outbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	history.StoreURLTestHistoryKey(U.KeyForOutbound(l3Outbound, "", N.NetworkTCP), new(adapter.URLTestHistory))
	loadBalanceGroup := &LoadBalanceGroup{
		outbounds: []adapter.Outbound{nonL3Outbound, l3Outbound},
		history:   history,
		ttl:       time.Minute,
	}
	var selectIndexCount int
	loadBalanceGroup.strategyFn = strategyStickySessionsWithIndex(loadBalanceGroup, func(_ uint64, length int) int {
		index := selectIndexCount % length
		selectIndexCount++
		return index
	})
	loadBalance := &LoadBalance{group: loadBalanceGroup}
	metadata := new(adapter.InboundContext)
	var preMatchCandidate adapter.Outbound

	selectedOutbound, action := loadBalance.SelectPreMatchOutbound(metadata, func(outbound adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction) {
		preMatchCandidate = outbound
		if outbound == nonL3Outbound {
			return nil, adapter.PreMatchContinue
		}
		return outbound, adapter.PreMatchFlow
	})
	require.Nil(t, selectedOutbound)
	require.Equal(t, adapter.PreMatchContinue, action)
	require.Same(t, nonL3Outbound, preMatchCandidate)
	require.Same(t, nonL3Outbound, loadBalanceGroup.Unwrap(metadata, true))
	require.Equal(t, 1, selectIndexCount)
}
