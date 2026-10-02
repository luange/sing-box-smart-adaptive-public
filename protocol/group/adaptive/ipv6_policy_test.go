package adaptive

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAIIPv6PolicyBlocksOnlyStrictAIIPv6(t *testing.T) {
	pool := &AdaptivePool{aiIPv6Policy: "block"}
	ipv6 := M.ParseSocksaddr("[2001:4860:4860::8888]:443")
	ipv4 := M.ParseSocksaddr("1.1.1.1:443")
	if !pool.applyAIIPv6Policy(ServiceContext{ID: "chatgpt_web"}, ipv6, nil) {
		t.Fatal("ChatGPT IPv6 was not blocked")
	}
	if !pool.applyAIIPv6Policy(ServiceContext{ID: "cloudflare_challenge"}, ipv6, nil) {
		t.Fatal("challenge IPv6 was not blocked")
	}
	if pool.applyAIIPv6Policy(ServiceContext{ID: "youtube"}, ipv6, nil) {
		t.Fatal("non-AI IPv6 was blocked")
	}
	if pool.applyAIIPv6Policy(ServiceContext{ID: "chatgpt_web"}, ipv4, nil) {
		t.Fatal("AI IPv4 was blocked")
	}
	if pool.aiIPv6Blocked.Load() != 2 {
		t.Fatalf("unexpected blocked counter: %d", pool.aiIPv6Blocked.Load())
	}
	pool.aiIPv6Policy = "allow"
	if pool.applyAIIPv6Policy(ServiceContext{ID: "chatgpt_web"}, ipv6, nil) {
		t.Fatal("allow policy blocked IPv6")
	}
}

func TestAIIPv6PolicyFiltersResolvedDualStackWithoutBlockingIPv4(t *testing.T) {
	pool := &AdaptivePool{aiIPv6Policy: "block"}
	metadata := &adapter.InboundContext{DestinationAddresses: []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"),
	}}
	if pool.applyAIIPv6Policy(ServiceContext{ID: "chatgpt_web"}, M.ParseSocksaddr("chatgpt.com:443"), metadata) {
		t.Fatal("dual-stack AI destination was blocked despite IPv4 fallback")
	}
	if len(metadata.DestinationAddresses) != 1 || !metadata.DestinationAddresses[0].Is4() {
		t.Fatalf("IPv6 address was not filtered: %v", metadata.DestinationAddresses)
	}
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	if !pool.applyAIIPv6Policy(ServiceContext{ID: "chatgpt_web"}, M.ParseSocksaddr("chatgpt.com:443"), metadata) {
		t.Fatal("IPv6-only AI destination was not blocked")
	}
}
