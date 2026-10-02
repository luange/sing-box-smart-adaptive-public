package trafficfamily

import (
	"net/netip"
	"testing"
	"time"
)

func TestSemanticAnchors(t *testing.T) {
	tests := map[string]string{
		"chatgpt.com": "chatgpt_web", "auth.openai.com": "chatgpt_web",
		"api.openai.com": "openai_api", "claude.ai": "claude",
		"r1.googlevideo.com": "youtube", "gemini.google.com": "gemini",
		"mmg.whatsapp.net": "whatsapp", "sglong.wechat.com": "wechat",
		"gateway.discord.gg": "discord", "accounts.google.com": "google_account",
	}
	for host, expected := range tests {
		if got := Classify(host); got.ID != expected || !got.StrictAffinity {
			t.Fatalf("host=%s got=%+v want=%s", host, got, expected)
		}
	}
}

func TestTelegramPublishedAddressesShareBusiness(t *testing.T) {
	tests := []string{
		"149.154.167.43",
		"91.108.56.195",
		"2001:b28:f23d::1",
	}
	for _, address := range tests {
		if got := ClassifyAddress(netip.MustParseAddr(address)); got.ID != "telegram" || got.Business != "telegram" || !got.StrictAffinity {
			t.Fatalf("address=%s got=%+v", address, got)
		}
	}
	if got := ClassifyAddress(netip.MustParseAddr("1.1.1.1")); got.ID != "" {
		t.Fatalf("unrelated address was classified: %+v", got)
	}
}

func TestResolveEvidencePriorityAndFallback(t *testing.T) {
	resolver := NewResolver()
	now := time.Unix(1, 0)
	match := resolver.ResolveEvidence(Evidence{
		Host:    "api.openai.com",
		Feature: "k3:telegram",
		Address: netip.MustParseAddr("149.154.167.43"),
	}, "client", now)
	if match.Business != "openai" {
		t.Fatalf("known SNI lost priority: %+v", match)
	}

	match = resolver.ResolveEvidence(Evidence{Feature: "k3:telegram", Address: netip.MustParseAddr("1.1.1.1")}, "client", now)
	if match.Business != "telegram" {
		t.Fatalf("application feature was not resolved: %+v", match)
	}
	match = resolver.ResolveEvidence(Evidence{Feature: "quic", Address: netip.MustParseAddr("1.1.1.1")}, "client", now)
	if match.ID != "unknown" {
		t.Fatalf("transport feature became a business: %+v", match)
	}
}

func TestOpenAISubservicesShareBusinessWithoutSharingSiteIdentity(t *testing.T) {
	web := Classify("chatgpt.com")
	api := Classify("api.openai.com")
	if web.ID == api.ID {
		t.Fatal("OpenAI subservices unexpectedly share the exact site identity")
	}
	if web.Business != "openai" || api.Business != web.Business {
		t.Fatalf("OpenAI business mismatch: web=%+v api=%+v", web, api)
	}
}

func TestUnknownSiteClassifiesAutomatically(t *testing.T) {
	resolver := NewResolver()
	if got := resolver.Resolve("img.assets.example.co.uk", "client", time.Now()); got.ID != "site:example.co.uk" || got.StrictAffinity {
		t.Fatalf("unexpected automatic site family: %+v", got)
	}
}

func TestChallengeInheritsRecentParent(t *testing.T) {
	resolver := NewResolver()
	now := time.Now()
	resolver.Resolve("chatgpt.com", "client-a", now)
	if got := resolver.Resolve("challenges.cloudflare.com", "client-a", now.Add(time.Second)); got.ID != "chatgpt_web" {
		t.Fatalf("challenge did not inherit product family: %+v", got)
	}
	if got := resolver.Resolve("challenges.cloudflare.com", "client-b", now.Add(time.Second)); got.ID != "cloudflare_challenge" {
		t.Fatalf("unrelated client inherited another client lineage: %+v", got)
	}
	if got := resolver.Resolve("challenges.cloudflare.com", "client-a", now.Add(time.Minute)); got.ID != "cloudflare_challenge" {
		t.Fatalf("expired lineage remained active: %+v", got)
	}
}
