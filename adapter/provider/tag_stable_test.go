package provider

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestUniqueProviderTagStableAcrossReloads(t *testing.T) {
	seen1 := map[string]bool{"airport/hk": true}
	id := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "hk", Options: struct{ Server string }{Server: "1.2.3.4"}})
	tag1 := uniqueProviderTag("airport/hk", id, seen1)
	seen1[tag1] = true

	seen2 := map[string]bool{"airport/hk": true}
	tag2 := uniqueProviderTag("airport/hk", id, seen2)
	if tag1 != tag2 {
		t.Fatalf("stable rename drifted: %q vs %q", tag1, tag2)
	}
	if tag1 == "airport/hk" {
		t.Fatal("expected a distinct rename when base is taken")
	}
}

func TestProviderOutboundIdentityDiffersByOptions(t *testing.T) {
	a := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "n", Options: struct{ Server string }{Server: "a"}})
	b := providerOutboundIdentity(option.Outbound{Type: "trojan", Tag: "n", Options: struct{ Server string }{Server: "b"}})
	if a == b {
		t.Fatal("different servers must fingerprint differently")
	}
}

func TestProviderDialIdentityKeepsCredentialsDistinct(t *testing.T) {
	base := func(password string) option.Outbound {
		return option.Outbound{Type: "trojan", Tag: "hk", Options: map[string]any{
			"server": "edge.example", "server_port": 443, "password": password,
		}}
	}
	if providerOutboundIdentity(base("one")) != providerOutboundIdentity(base("two")) {
		t.Fatal("path identity should ignore credential rotation")
	}
	if providerOutboundDialIdentity(base("one")) == providerOutboundDialIdentity(base("two")) {
		t.Fatal("dial identity must separate credentials")
	}
}

func TestProviderDuplicateTagsStableWhenSubscriptionReorders(t *testing.T) {
	a := NewAdapter(context.Background(), nil, nil, nil, log.NewNOPFactory(), log.NewNOPFactory().Logger(), "airport", "inline", option.ProviderHealthCheckOptions{})
	first := []option.Outbound{
		{Type: "trojan", Tag: "HK", Options: map[string]any{"server": "b.example"}},
		{Type: "trojan", Tag: "HK", Options: map[string]any{"server": "a.example"}},
	}
	second := []option.Outbound{first[1], first[0]}
	firstTags := a.resolveOutboundTags(first)
	secondTags := a.resolveOutboundTags(second)
	byServer := func(opts []option.Outbound, tags []string) map[string]string {
		result := make(map[string]string, len(opts))
		for i, opt := range opts {
			result[opt.Options.(map[string]any)["server"].(string)] = tags[i]
		}
		return result
	}
	if got, want := byServer(second, secondTags), byServer(first, firstTags); !equalStringMap(got, want) {
		t.Fatalf("duplicate tags changed after reorder: first=%v second=%v", want, got)
	}
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
