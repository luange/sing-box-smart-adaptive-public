package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

func TestURLTestCloseBeforeGroupStart(t *testing.T) {
	// NewURLTestGroup can fail validation before Start stores a group. Closing
	// that partially initialized wrapper must remain safe and idempotent.
	s := &URLTest{providerSource: &groupProviderSource{}}
	if err := s.Close(); err != nil {
		t.Fatalf("close before start: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close before start: %v", err)
	}
}

func TestSelectDashboardOutboundsSamplesRecentAndStale(t *testing.T) {
	history := urltest.NewHistoryStorage()
	outbounds := make([]adapter.Outbound, 0, 20)
	for index := range 20 {
		tag := "dashboard-node-" + itoaSmall(index)
		outbounds = append(outbounds, &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)})
	}
	now := time.Now()
	for index := range 6 {
		history.StoreURLTestHistoryKey(urltest.KeyForOutbound(outbounds[index], "", N.NetworkTCP), &adapter.URLTestHistory{Time: now.Add(-time.Duration(index) * time.Minute), Delay: uint16(index + 1)})
	}
	selected := selectDashboardOutbounds(history, outbounds, dashboardURLTestLimit)
	if len(selected) != dashboardURLTestLimit {
		t.Fatalf("selected %d dashboard candidates, want %d", len(selected), dashboardURLTestLimit)
	}
	seen := make(map[string]struct{}, len(selected))
	for _, candidate := range selected {
		if _, exists := seen[candidate.Tag()]; exists {
			t.Fatalf("duplicate dashboard candidate %q", candidate.Tag())
		}
		seen[candidate.Tag()] = struct{}{}
	}
	for index := 0; index < 6; index++ {
		if _, exists := seen[outbounds[index].Tag()]; !exists {
			t.Fatalf("recent candidate %q was not sampled", outbounds[index].Tag())
		}
	}
	for index := 6; index < dashboardURLTestLimit; index++ {
		if _, exists := seen[outbounds[index].Tag()]; !exists {
			t.Fatalf("stale candidate %q was not sampled", outbounds[index].Tag())
		}
	}
}

func TestSelectDashboardOutboundsKeepsProbeTargetsSeparate(t *testing.T) {
	history := urltest.NewHistoryStorage()
	first := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "target-a", []string{N.NetworkTCP}, nil)}
	second := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "target-b", []string{N.NetworkTCP}, nil)}
	now := time.Now()
	history.StoreURLTestHistoryKey(urltest.KeyForOutbound(first, "https://probe-a.example/204", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 10})
	history.StoreURLTestHistoryKey(urltest.KeyForOutbound(second, "https://probe-b.example/204", N.NetworkTCP), &adapter.URLTestHistory{Time: now, Delay: 20})
	selected := selectDashboardOutbounds(history, []adapter.Outbound{first, second}, 1, "https://probe-b.example/204")
	if len(selected) != 1 || selected[0] != second {
		t.Fatalf("dashboard selected %v for target-specific probe, want target-b", selected)
	}
}
