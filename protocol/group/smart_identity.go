package group

// Smart probe identities are deliberately derived from the structured
// provider options when available.  Subscription providers commonly append a
// numeric suffix to otherwise identical nodes; using the runtime tag as the
// probe key makes every copy run its own health check and defeats the shared
// probe registry.  Credentials remain excluded so a password/UUID rotation
// does not create a second endpoint profile.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodeidentity"
	"github.com/sagernet/sing-box/option"
)

func (s *Smart) probeIdentityLocked(candidate adapter.Outbound) string {
	return probeIdentityFromProviders(candidate, s.providers)
}

// dialIdentityLocked is intentionally stronger than probeIdentityLocked. The
// latter is a path identity (credentials stripped) and is shared for RTT/DNS
// probing. Dial outcomes, breakers and retry diversity must keep different
// credentials separate because a server may map them to different backends or
// quotas. The returned value is always an opaque hash and never exposes the
// option payload.
func (s *Smart) dialIdentityLocked(candidate adapter.Outbound) string {
	if candidate == nil {
		return ""
	}
	if identified, ok := candidate.(adapter.OutboundWithDialIdentity); ok {
		if identity := identified.DialIdentity(); identity != "" {
			return identity
		}
	}
	for _, provider := range s.providers {
		if provider == nil {
			continue
		}
		var outboundOptions option.Outbound
		var loaded bool
		if lookup, ok := provider.(adapter.ProviderOutboundOptionLookup); ok {
			outboundOptions, loaded = lookup.OutboundOption(candidate.Tag())
		} else if source, ok := provider.(adapter.ProviderOutboundOptions); ok {
			outboundOptions, loaded = source.OutboundOptions()[candidate.Tag()]
		}
		if !loaded || outboundOptions.Type == "" || outboundOptions.Options == nil {
			continue
		}
		payload, err := json.Marshal(struct {
			Type    string `json:"type"`
			Options any    `json:"options"`
		}{Type: outboundOptions.Type, Options: outboundOptions.Options})
		if err != nil {
			payload = []byte(fmt.Sprintf("%s\x00%T\x00%s", outboundOptions.Type, outboundOptions.Options, candidate.Tag()))
		}
		h := sha256.New()
		_, _ = h.Write([]byte("sing-box/smart-dial/v1\x00"))
		_, _ = h.Write(payload)
		return "dial:" + hex.EncodeToString(h.Sum(nil))
	}
	return probeIdentityFromProviders(candidate, s.providers)
}

func probeIdentityFromProviders(candidate adapter.Outbound, providers map[string]adapter.Provider) string {
	if candidate == nil {
		return ""
	}
	// Provider adapters attach a credential-free identity to each runtime
	// member. Prefer it over a display-tag lookup so duplicate suffixes and
	// provider reload order cannot move a health portrait to another endpoint.
	if identified, ok := candidate.(adapter.OutboundWithEndpointIdentity); ok {
		if identity := identified.EndpointIdentity(); identity != "" {
			return identity
		}
	}
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		var outboundOptions option.Outbound
		var loaded bool
		if lookup, ok := provider.(adapter.ProviderOutboundOptionLookup); ok {
			outboundOptions, loaded = lookup.OutboundOption(candidate.Tag())
		} else if source, ok := provider.(adapter.ProviderOutboundOptions); ok {
			outboundOptions, loaded = source.OutboundOptions()[candidate.Tag()]
		}
		if !loaded || outboundOptions.Type == "" || outboundOptions.Options == nil {
			continue
		}
		// Normalize typed options once; the shared helper also applies the
		// credential filter to nested fields.
		normalizedOptions, err := nodeidentity.CanonicalEndpointOptionsForType(outboundOptions.Type, outboundOptions.Options)
		if err != nil {
			continue
		}
		payload := map[string]any{
			"type":    outboundOptions.Type,
			"options": normalizedOptions,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			break
		}
		h := sha256.New()
		_, _ = h.Write([]byte("sing-box/smart-endpoint/v1\x00"))
		_, _ = h.Write(raw)
		return "endpoint:" + hex.EncodeToString(h.Sum(nil))
	}
	// Static outbounds and legacy providers without structured options still
	// get a stable identity; retaining the tag avoids accidental cross-node
	// coalescing when there is no trustworthy endpoint description.
	return candidate.Type() + "\x00" + candidate.Tag()
}
