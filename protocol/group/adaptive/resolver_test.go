package adaptive

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestServiceResolverBindsYouTubeCrossDomainSession(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	metadata := &adapter.InboundContext{
		Inbound: "mixed-in",
		Source:  M.ParseSocksaddr("192.168.0.10:12345"),
	}
	control := resolver.Resolve(metadata, M.ParseSocksaddr("www.youtube.com:443"), N.NetworkTCP)
	media := resolver.Resolve(metadata, M.ParseSocksaddr("r1---sn.example.googlevideo.com:443"), N.NetworkUDP)
	image := resolver.Resolve(metadata, M.ParseSocksaddr("i.ytimg.com:443"), N.NetworkTCP)
	avatar := resolver.Resolve(metadata, M.ParseSocksaddr("yt3.ggpht.com:443"), N.NetworkTCP)
	if control.ID != "youtube" || media.ID != "youtube" || image.ID != "youtube" || avatar.ID != "youtube" {
		t.Fatalf("YouTube domains split across services: %q %q %q %q", control.ID, media.ID, image.ID, avatar.ID)
	}
	if control.Session != media.Session || control.Session != image.Session || control.Session != avatar.Session {
		t.Fatal("YouTube TCP/UDP domains did not share one session lease")
	}
	if control.Mode != ModeStrictAffinity {
		t.Fatalf("YouTube did not use strict affinity: %s", control.Mode)
	}
}

func TestServiceResolverSecurityAndMessagingFamilies(t *testing.T) {
	tests := map[string]string{
		"accounts.google.com": "google_account", "payments.google.com": "google_account",
		"appleid.apple.com": "apple_account", "smp-device-content.g.aaplimg.com": "apple_account",
		"login.microsoftonline.com": "microsoft_account", "aadcdn.msauth.net": "microsoft_account",
		"challenges.cloudflare.com": "cloudflare_challenge", "web.whatsapp.com": "whatsapp", "mmg.whatsapp.net": "whatsapp",
	}
	for host, expected := range tests {
		resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
		client := &adapter.InboundContext{Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
		if got := resolver.Resolve(client, M.ParseSocksaddr(host+":443"), N.NetworkTCP); got.ID != expected || got.Mode != ModeStrictAffinity {
			t.Fatalf("service family mismatch host=%s got=%+v", host, got)
		}
	}
}

func TestServiceResolverIsolatesProductAffinitySpines(t *testing.T) {
	// Cross-product browser_identity coupling was a thrash path: one service
	// breaker bounced another's egress. Each product now owns its lease/sticky key.
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	client := &adapter.InboundContext{Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.2:1000")}
	cases := []struct {
		host string
		id   string
	}{
		{"chatgpt.com", "chatgpt_web"},
		{"claude.ai", "claude"},
		{"gemini.google.com", "gemini"},
		{"accounts.google.com", "google_account"},
		{"appleid.apple.com", "apple_account"},
		{"login.microsoftonline.com", "microsoft_account"},
		{"api.openai.com", "openai_api"},
	}
	sessions := make(map[string]SessionKey)
	for _, tc := range cases {
		resolved := resolver.Resolve(client, M.ParseSocksaddr(tc.host+":443"), N.NetworkTCP)
		if resolved.Mode != ModeStrictAffinity || resolved.ID != tc.id || resolved.AffinityID != tc.id {
			t.Fatalf("affinity isolation mismatch host=%s got=%+v want id/affinity=%s", tc.host, resolved, tc.id)
		}
		sessions[tc.id] = resolved.Session
	}
	if sessions["chatgpt_web"] == sessions["claude"] {
		t.Fatal("chatgpt and claude must not share session/lease spine")
	}
	if sessions["chatgpt_web"] == sessions["gemini"] {
		t.Fatal("chatgpt and gemini must not share session/lease spine")
	}
	if sessions["chatgpt_web"] == sessions["google_account"] {
		t.Fatal("chatgpt and google_account must not share session/lease spine")
	}
	// Same product, related hosts still share spine (health service id + affinity).
	cdn := resolver.Resolve(client, M.ParseSocksaddr("auth.openai.com.cdn.cloudflare.net:443"), N.NetworkTCP)
	if cdn.ID != "chatgpt_web" || cdn.Session != sessions["chatgpt_web"] {
		t.Fatalf("chatgpt CDN host lost product spine: %+v", cdn)
	}
}

func TestServiceResolverChallengeInheritsProductSpine(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	client := &adapter.InboundContext{Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.2:1000")}
	product := resolver.Resolve(client, M.ParseSocksaddr("chatgpt.com:443"), N.NetworkTCP)
	challenge := resolver.Resolve(client, M.ParseSocksaddr("challenges.cloudflare.com:443"), N.NetworkTCP)
	if challenge.ID != product.ID || challenge.Session != product.Session {
		t.Fatalf("challenge did not inherit product spine: product=%+v challenge=%+v", product, challenge)
	}
}

func TestServiceResolverFakeIPAndQUICMetadataPriority(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	metadata := &adapter.InboundContext{
		Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.10:1000"), FakeIP: true,
		Domain: "r1.googlevideo.com", SniffHost: "unrelated.example", Destination: M.ParseSocksaddr("198.18.0.1:443"),
	}
	if got := resolver.Resolve(metadata, metadata.Destination, N.NetworkUDP); got.ID != "youtube" {
		t.Fatalf("FakeIP reverse domain did not win: %+v", got)
	}
	metadata.Domain = ""
	metadata.SniffHost = "api.openai.com"
	metadata.Protocol = "quic"
	if got := resolver.Resolve(metadata, metadata.Destination, N.NetworkUDP); got.ID != "openai_api" || got.Transport != N.NetworkUDP {
		t.Fatalf("QUIC sniff host did not determine service: %+v", got)
	}
}

func TestServiceResolverNativeQUICSNIOverridesStaleResolverDomain(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	metadata := &adapter.InboundContext{
		Inbound: "US-in", Source: M.ParseSocksaddr("192.168.0.10:1000"),
		Domain: "unrelated.example", SniffHost: "chatgpt.com", Protocol: "quic",
		Destination: M.ParseSocksaddr("192.0.2.10:443"),
	}
	resolved := resolver.Resolve(metadata, metadata.Destination, N.NetworkUDP)
	if resolved.ID != "chatgpt_web" || resolved.Host != "chatgpt.com" {
		t.Fatalf("native QUIC SNI did not override stale domain: %+v", resolved)
	}
}

func TestServiceResolverSeparatesTransportPurposeAndIPFamily(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	tests := []struct {
		name        string
		metadata    *adapter.InboundContext
		destination string
		transport   string
		expected    string
	}{
		{name: "tcp4", destination: "192.0.2.1:443", transport: N.NetworkTCP, expected: "tcp/ipv4"},
		{name: "tcp6", destination: "[2001:db8::1]:443", transport: N.NetworkTCP, expected: "tcp/ipv6"},
		{name: "dns udp4 by port", destination: "8.8.8.8:53", transport: N.NetworkUDP, expected: "udp_dns/ipv4"},
		{name: "dns udp6 by protocol", metadata: &adapter.InboundContext{Protocol: "dns"}, destination: "[2001:4860:4860::8888]:5353", transport: N.NetworkUDP, expected: "udp_dns/ipv6"},
		{name: "data udp4", destination: "192.0.2.1:443", transport: N.NetworkUDP, expected: "udp_data/ipv4"},
		{name: "data udp6", destination: "[2001:db8::1]:443", transport: N.NetworkUDP, expected: "udp_data/ipv6"},
		{name: "unresolved family", destination: "example.com:443", transport: N.NetworkTCP, expected: "tcp/any"},
		{name: "resolved ipv4 family", metadata: &adapter.InboundContext{DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, destination: "example.com:443", transport: N.NetworkTCP, expected: "tcp/ipv4"},
		{name: "resolved mixed family", metadata: &adapter.InboundContext{DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}}, destination: "example.com:443", transport: N.NetworkTCP, expected: "tcp/any"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolver.Resolve(test.metadata, M.ParseSocksaddr(test.destination), test.transport)
			if resolved.HealthTransport != test.expected {
				t.Fatalf("health transport mismatch: got=%q want=%q resolved=%+v", resolved.HealthTransport, test.expected, resolved)
			}
			if resolved.Transport != test.transport {
				t.Fatalf("business transport changed: got=%q want=%q", resolved.Transport, test.transport)
			}
		})
	}
}

func TestRefineHealthTransportFamilyPinsConcreteStack(t *testing.T) {
	if got := refineHealthTransportFamily("tcp/any", healthFamilyIPv4); got != "tcp/ipv4" {
		t.Fatalf("tcp/any + ipv4 => %q", got)
	}
	if got := refineHealthTransportFamily("tcp/any", healthFamilyIPv6); got != "tcp/ipv6" {
		t.Fatalf("tcp/any + ipv6 => %q", got)
	}
	if got := refineHealthTransportFamily("tcp/ipv4", healthFamilyIPv6); got != "tcp/ipv4" {
		t.Fatalf("concrete path must not flip family: %q", got)
	}
	if got := refineHealthTransportFamily(normalizeHealthTransportPath(N.NetworkTCP), healthFamilyIPv4); got != "tcp/ipv4" {
		t.Fatalf("bare tcp + ipv4 => %q", got)
	}
	if got := normalizeHealthTransportPath(N.NetworkTCP); got != "tcp/any" {
		t.Fatalf("bare tcp normalizes to tcp/any: %q", got)
	}
	if got := refineHealthTransportFamily("udp_dns/any", healthFamilyIPv6); got != "udp_dns/ipv6" {
		t.Fatalf("udp_dns/any + ipv6 => %q", got)
	}
	service := ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/any"}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	if got := observedHealthTransport(service, M.ParseSocksaddr("example.com:443"), remote); got != "tcp/ipv4" {
		t.Fatalf("observed from remote addr: %q", got)
	}
	if got := observedHealthTransport(service, M.ParseSocksaddr("2001:db8::1:443"), nil); got != "tcp/ipv6" {
		// ParseSocksaddr with bare v6 may need brackets
		if got2 := observedHealthTransport(service, M.ParseSocksaddr("[2001:db8::1]:443"), nil); got2 != "tcp/ipv6" {
			t.Fatalf("observed from destination IP: %q / %q", got, got2)
		}
	}
}

func TestServiceResolverTemporaryOverrideExpires(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	now := time.Unix(1_700_000_000, 0)
	if err := resolver.SetOverride("youtube", ModeBulk, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if override, loaded := resolver.override("youtube", now.Add(30*time.Second)); !loaded || override.Mode != ModeBulk {
		t.Fatalf("temporary override was not active: %+v loaded=%v", override, loaded)
	}
	if _, loaded := resolver.override("youtube", now.Add(2*time.Minute)); loaded {
		t.Fatal("expired temporary override remained active")
	}
	if err := resolver.SetOverride("youtube", PolicyMode("invalid"), time.Minute, now); err == nil {
		t.Fatal("invalid override mode was accepted")
	}
}

func TestServiceResolverSeparatesGoogleServiceFamiliesAndClients(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	firstClient := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	secondClient := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.11:1000")}
	youtube := resolver.Resolve(firstClient, M.ParseSocksaddr("youtube.com:443"), N.NetworkTCP)
	gemini := resolver.Resolve(firstClient, M.ParseSocksaddr("gemini.google.com:443"), N.NetworkTCP)
	otherClient := resolver.Resolve(secondClient, M.ParseSocksaddr("youtube.com:443"), N.NetworkTCP)
	if youtube.Session == gemini.Session {
		t.Fatal("YouTube and Gemini incorrectly shared a lease")
	}
	if youtube.Session == otherClient.Session {
		t.Fatal("different clients incorrectly shared a strict-affinity lease")
	}
}

func TestServiceResolverSeparatesOpenAIAPIFromChatGPTWeb(t *testing.T) {
	resolver := NewServiceResolver(testIdentityHasher(t), ModeAdaptive)
	client := &adapter.InboundContext{Inbound: "mixed-in", Source: M.ParseSocksaddr("192.168.0.10:1000")}
	api := resolver.Resolve(client, M.ParseSocksaddr("api.openai.com:443"), N.NetworkTCP)
	web := resolver.Resolve(client, M.ParseSocksaddr("chatgpt.com:443"), N.NetworkTCP)
	static := resolver.Resolve(client, M.ParseSocksaddr("cdn.oaistatic.com:443"), N.NetworkTCP)
	if api.ID != "openai_api" || web.ID != "chatgpt_web" || static.ID != "chatgpt_web" {
		t.Fatalf("OpenAI service families were not separated: api=%q web=%q static=%q", api.ID, web.ID, static.ID)
	}
	if api.Session == web.Session || web.Session != static.Session {
		t.Fatal("OpenAI API and ChatGPT web lease boundaries are incorrect")
	}
}

func TestFamilyFromIPIgnoresProxyTunnelAddresses(t *testing.T) {
	if got := familyFromIP(net.ParseIP("10.30.0.115")); got != "" {
		t.Fatalf("private remote must not pin dial family: %s", got)
	}
	if got := familyFromIP(net.ParseIP("127.0.0.1")); got != "" {
		t.Fatalf("loopback must not pin dial family: %s", got)
	}
	if got := familyFromIP(net.ParseIP("198.18.0.1")); got != healthFamilyIPv4 {
		t.Fatalf("FakeIP range must still pin: %s", got)
	}
	if got := familyFromIP(net.ParseIP("1.2.3.4")); got != healthFamilyIPv4 {
		t.Fatalf("public v4: %s", got)
	}
}

func TestObservedHealthTransportPrefersDestinationOverPrivateRemote(t *testing.T) {
	service := ServiceContext{Transport: N.NetworkTCP, HealthTransport: "tcp/any"}
	dest := M.ParseSocksaddr("198.18.1.2:443")
	remote := &net.TCPAddr{IP: net.ParseIP("10.20.20.4"), Port: 12345}
	if got := observedHealthTransport(service, dest, remote); got != "tcp/ipv4" {
		t.Fatalf("destination FakeIP should win over private remote: %s", got)
	}
}

func TestTransactionalUDPResponseExpectation(t *testing.T) {
	hasher, err := NewIdentityHasher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewServiceResolver(hasher, ModeAdaptive)
	for _, test := range []struct {
		name        string
		metadata    *adapter.InboundContext
		destination string
		expected    bool
	}{
		{name: "quic port", destination: "192.0.2.1:443", expected: true},
		{name: "dns port", destination: "192.0.2.1:53", expected: true},
		{name: "stun sniff", metadata: &adapter.InboundContext{Protocol: "stun"}, destination: "192.0.2.1:9000", expected: true},
		{name: "one way data", destination: "192.0.2.1:9000", expected: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := resolver.Resolve(test.metadata, M.ParseSocksaddr(test.destination), N.NetworkUDP)
			if service.ExpectUDPResponse != test.expected {
				t.Fatalf("expect response=%v, want %v", service.ExpectUDPResponse, test.expected)
			}
		})
	}
}
