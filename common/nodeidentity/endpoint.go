// Package nodeidentity contains the canonical identity rules shared by
// Smart and AdaptivePool. Keeping this in one package prevents the two group
// implementations from silently creating different endpoint profiles.
package nodeidentity

import (
	"encoding/json"
	"strings"
)

// CanonicalEndpointOptions converts typed outbound options to a JSON-shaped
// value and removes credentials and other per-subscription secrets. The
// returned value is safe to hash for endpoint-level probe deduplication.
func CanonicalEndpointOptions(input any) (any, error) {
	return CanonicalEndpointOptionsForType("", input)
}

// CanonicalEndpointOptionsForType returns the path identity projection for a
// known outbound protocol. Protocol-specific projections are intentionally
// conservative: only fields that are authentication material are removed;
// transport, TLS, routing and protocol-mode fields remain part of the path.
// Unknown protocols use the legacy generic projection for compatibility.
func CanonicalEndpointOptionsForType(protocol string, input any) (any, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var value any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if keys, known := protocolCredentialKeys(protocol); known {
		return stripProtocolCredentials(value, keys, false), nil
	}
	return StripEndpointCredentials(value), nil
}

// protocolCredentialKeys is the single source of truth for path-vs-dial
// identity projection. Keep this list explicit: a field named "token" or
// "secret" in an arbitrary transport/header object is not necessarily an
// endpoint credential and must not silently collapse two paths.
func protocolCredentialKeys(protocol string) (map[string]struct{}, bool) {
	var keys []string
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "vless", "vmess":
		keys = []string{"uuid"}
	case "trojan", "shadowsocks", "shadowsocksr", "anytls", "shadowtls":
		keys = []string{"password"}
	case "hysteria", "hysteria2":
		keys = []string{"password", "auth", "auth_str", "token"}
	case "tuic":
		keys = []string{"uuid", "password"}
	case "wireguard":
		keys = []string{"private_key", "pre_shared_key"}
	case "ssh":
		keys = []string{"user", "password", "private_key", "private_key_path", "private_key_passphrase"}
	case "socks", "http", "naive":
		keys = []string{"username", "password"}
	case "snell":
		keys = []string{"psk", "userkey"}
	case "openvpn":
		keys = []string{"username", "password", "static_key", "static_key_path", "client_key", "client_key_path", "client_certificate", "client_certificate_path"}
	case "openconnect":
		keys = []string{"username", "password", "cookie", "token", "secret", "pin", "client_key", "client_key_path", "client_certificate", "client_certificate_path"}
	case "tailscale":
		keys = []string{"auth_key"}
	default:
		return nil, false
	}
	result := make(map[string]struct{}, len(keys)+1)
	for _, key := range keys {
		result[key] = struct{}{}
	}
	// Authorization is only treated as a credential inside HTTP header maps.
	// It is not a global field rule because custom protocol options may use
	// similarly named fields as routing metadata.
	result["authorization"] = struct{}{}
	return result, true
}

func stripProtocolCredentials(value any, keys map[string]struct{}, inHeaders bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			if _, sensitive := keys[normalized]; sensitive && (normalized != "authorization" || inHeaders) {
				continue
			}
			childHeaders := inHeaders || normalized == "headers" || normalized == "extra_headers"
			result[key] = stripProtocolCredentials(item, keys, childHeaders)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = stripProtocolCredentials(item, keys, inHeaders)
		}
		return result
	default:
		return value
	}
}

// StripEndpointCredentials recursively removes fields that identify a
// credential rather than the network endpoint.
func StripEndpointCredentials(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			switch normalized {
			case "password", "uuid", "psk", "token", "secret", "private_key", "privatekey", "auth", "authorization":
				continue
			}
			result[key] = StripEndpointCredentials(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = StripEndpointCredentials(item)
		}
		return result
	default:
		return value
	}
}
