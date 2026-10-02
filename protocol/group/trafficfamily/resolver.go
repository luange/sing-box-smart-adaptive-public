package trafficfamily

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const defaultInheritanceTTL = 45 * time.Second

// Telegram publishes these service-owned prefixes at
// https://core.telegram.org/resources/cidr.txt.
var telegramPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("91.108.56.0/22"),
	netip.MustParsePrefix("91.108.4.0/22"),
	netip.MustParsePrefix("91.108.8.0/22"),
	netip.MustParsePrefix("91.108.16.0/22"),
	netip.MustParsePrefix("91.108.12.0/22"),
	netip.MustParsePrefix("149.154.160.0/20"),
	netip.MustParsePrefix("91.105.192.0/23"),
	netip.MustParsePrefix("91.108.20.0/22"),
	netip.MustParsePrefix("185.76.151.0/24"),
	netip.MustParsePrefix("2001:b28:f23d::/48"),
	netip.MustParsePrefix("2001:b28:f23f::/48"),
	netip.MustParsePrefix("2001:67c:4e8::/48"),
	netip.MustParsePrefix("2001:b28:f23c::/48"),
	netip.MustParsePrefix("2a0a:f280::/32"),
}

type Match struct {
	ID              string
	Business        string
	StrictAffinity  bool
	ParentCandidate bool
	InheritParent   bool
}

// Evidence is the normalized boundary between protocol classifiers and Smart.
// Host normally comes from SNI/HTTP Host, Feature may be supplied by a DPI
// classifier, and Address is the actual destination. A transport label such
// as TLS or QUIC is deliberately not an application identity.
type Evidence struct {
	Host        string
	Application string
	// Protocol selects the appropriate SNI or HTTP Host table. It is context
	// only and is never promoted into an application identity.
	Protocol string
	// Feature is retained for adapters which already emit app:<name> or
	// k3:<name>. Generic transport protocols are never accepted as apps.
	Feature string
	Address netip.Addr
}

type recentParent struct {
	family    string
	business  string
	expiresAt time.Time
}

// Resolver combines a deliberately small semantic catalog with process-local
// flow lineage. Unknown sites are classified automatically by registrable
// domain; encrypted payloads are never inspected.
type Resolver struct {
	access  sync.RWMutex
	recent  map[string]recentParent
	lineage time.Duration
	catalog *Catalog
}

func NewResolver() *Resolver {
	return &Resolver{recent: make(map[string]recentParent), lineage: defaultInheritanceTTL}
}

func NewResolverWithCatalog(catalog *Catalog) *Resolver {
	resolver := NewResolver()
	resolver.catalog = catalog
	return resolver
}

// ResolveEvidence combines independent evidence without allowing a weak IP or
// feature match to override a known SNI business. Recognized semantic SNI is
// authoritative; application features and service-owned address ranges fill
// the IP-only gap; an unknown host finally falls back to its registrable site.
func (r *Resolver) ResolveEvidence(evidence Evidence, client string, now time.Time) Match {
	host := normalizeHost(evidence.Host)
	if host != "" {
		if match := Classify(host); match.ID != "" {
			return r.Resolve(host, client, now)
		}
		if r != nil {
			if match := r.catalog.ClassifyHost(host, evidence.Protocol); match.ID != "" {
				return match
			}
		}
	}
	if r != nil {
		if match := r.catalog.ClassifyApplication(evidence.Application); match.ID != "" {
			return match
		}
		feature := strings.ToLower(strings.TrimSpace(evidence.Feature))
		if strings.HasPrefix(feature, "app:") || strings.HasPrefix(feature, "k3:") {
			if match := r.catalog.ClassifyApplication(feature); match.ID != "" {
				return match
			}
		}
	}
	if match := ClassifyFeature(evidence.Feature); match.ID != "" {
		return match
	}
	if match := ClassifyAddress(evidence.Address); match.ID != "" {
		return match
	}
	return r.Resolve(host, client, now)
}

func (r *Resolver) Resolve(host, client string, now time.Time) Match {
	match := Classify(host)
	if r == nil || client == "" {
		return withGenericSite(match, host)
	}
	// Most domains are independent sites and do not participate in client
	// lineage. Avoid taking the global lineage lock on this hot path.
	if !match.InheritParent && !match.ParentCandidate {
		return withGenericSite(match, host)
	}
	if match.InheritParent {
		r.access.RLock()
		if parent, loaded := r.recent[client]; loaded && parent.expiresAt.After(now) {
			r.access.RUnlock()
			match.ID = parent.family
			match.Business = parent.business
			match.StrictAffinity = true
			return match
		}
		r.access.RUnlock()
	}
	if match.ParentCandidate {
		r.access.Lock()
		r.recent[client] = recentParent{family: match.ID, business: match.Business, expiresAt: now.Add(r.lineage)}
		if len(r.recent) > 4096 {
			for key, parent := range r.recent {
				if !parent.expiresAt.After(now) {
					delete(r.recent, key)
				}
			}
		}
		r.access.Unlock()
	}
	return withGenericSite(match, host)
}

func withGenericSite(match Match, host string) Match {
	if match.ID != "" {
		if match.Business == "" {
			match.Business = match.ID
		}
		return match
	}
	host = normalizeHost(host)
	if host == "" {
		match.ID = "unknown"
		return match
	}
	identity, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		identity = host
	}
	match.ID = "site:" + identity
	match.Business = match.ID
	return match
}

// Classify contains only semantic anchors whose cross-domain identity cannot
// be inferred safely from encrypted connection behavior alone.
func Classify(host string) Match {
	host = normalizeHost(host)
	switch {
	case domainMatches(host, "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com", "youtube-nocookie.com"):
		return strictParent("youtube")
	case domainMatches(host, "gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com"):
		return strictParent("gemini")
	case host == "api.openai.com" || domainMatches(host, "platform.openai.com"):
		return businessParent("openai_api", "openai")
	case domainMatches(host, "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "openai.com.cdn.cloudflare.net", "oaistatic.com.cdn.cloudflare.net", "chatgpt.com.cdn.cloudflare.net"):
		return businessParent("chatgpt_web", "openai")
	case domainMatches(host, "claude.ai", "anthropic.com"):
		return strictParent("claude")
	case domainMatches(host, "telegram.org", "t.me", "telegram.me", "telegram.dog"):
		return strictParent("telegram")
	case domainMatches(host, "accounts.google.com", "oauth2.googleapis.com", "securetoken.googleapis.com", "pay.google.com", "payments.google.com", "payments.googleusercontent.com"):
		// Keep the account family visible for diagnostics, but share the
		// business identity with Google's static/API/CDN hosts.  OAuth is a
		// multi-origin flow: isolating accounts.google.com from gstatic,
		// googleapis and googleusercontent lets one origin look healthy while
		// another origin stalls, leaving the browser spinning indefinitely.
		return businessParent("google_account", "google")
	case domainMatches(host, "appleid.apple.com", "idmsa.apple.com", "appleid.cdn-apple.com", "aaplimg.com"):
		return strictParent("apple_account")
	case domainMatches(host, "login.microsoftonline.com", "login.live.com", "account.live.com", "msauth.net", "msftauth.net"):
		return strictParent("microsoft_account")
	case domainMatches(host, "challenges.cloudflare.com", "turnstile.cloudflare.com"):
		return Match{ID: "cloudflare_challenge", StrictAffinity: true, InheritParent: true}
	case domainMatches(host, "whatsapp.com", "whatsapp.net", "wa.me"):
		return strictParent("whatsapp")
	case domainMatches(host, "wechat.com", "wechatapp.com", "weixin.qq.com", "weixin.qq.com.cn"):
		return strictParent("wechat")
	case domainMatches(host, "discord.com", "discord.gg", "discordapp.com", "discordapp.net"):
		return strictParent("discord")
	case domainMatches(host, "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com", "googlemail.com", "1e100.net"):
		return strictParent("google")
	default:
		return Match{}
	}
}

// ClassifyAddress contains only address ownership published by the service
// itself. It intentionally does not infer a business from the client's most
// recent domain: unrelated IP-only traffic commonly follows a web request and
// must not inherit that request's routing identity.
func ClassifyAddress(address netip.Addr) Match {
	address = address.Unmap()
	if !address.IsValid() {
		return Match{}
	}
	for _, prefix := range telegramPrefixes {
		if prefix.Contains(address) {
			return strictParent("telegram")
		}
	}
	return Match{}
}

// ClassifyFeature accepts application identities, not transport protocols.
// K3 adapters should normalize signature IDs to these stable labels.
func ClassifyFeature(feature string) Match {
	feature = strings.ToLower(strings.TrimSpace(feature))
	switch feature {
	case "telegram", "app:telegram", "k3:telegram":
		return strictParent("telegram")
	default:
		return Match{}
	}
}

func strictParent(id string) Match {
	return Match{ID: id, Business: id, StrictAffinity: true, ParentCandidate: true}
}

func businessParent(id, business string) Match {
	return Match{ID: id, Business: business, StrictAffinity: true, ParentCandidate: true}
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func domainMatches(host string, domains ...string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
