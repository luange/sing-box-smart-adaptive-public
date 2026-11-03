package nodeidentity

import (
	"encoding/json"
	"testing"
)

func TestCanonicalEndpointOptionsStripsNestedCredentials(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server":   "example.com",
		"password": "hidden",
		"tls":      map[string]any{"headers": map[string]any{"authorization": "hidden"}, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if _, ok := result["password"]; ok {
		t.Fatal("top-level credential was retained")
	}
	tls := result["tls"].(map[string]any)
	if headers, ok := tls["headers"].(map[string]any); !ok || len(headers) != 0 {
		t.Fatalf("nested credential headers were retained: %#v", tls["headers"])
	}
	if tls["server_name"] != "example.com" {
		t.Fatalf("endpoint field changed: %#v", tls["server_name"])
	}
}

func TestCanonicalEndpointOptionsKeepsNonCredentialHeaders(t *testing.T) {
	value, err := CanonicalEndpointOptions(map[string]any{
		"server": "example.com",
		"headers": map[string]any{
			"Host":          "origin.example.com",
			"User-Agent":    "sing-box",
			"Authorization": "Bearer secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := value.(map[string]any)["headers"].(map[string]any)
	if headers["Host"] != "origin.example.com" || headers["User-Agent"] != "sing-box" {
		t.Fatalf("non-credential headers were lost: %#v", headers)
	}
	if _, ok := headers["Authorization"]; ok {
		t.Fatal("authorization header was retained")
	}
}

func TestProtocolProjectionCoversCredentialVariants(t *testing.T) {
	first, err := CanonicalEndpointOptionsForType("ssh", map[string]any{
		"server": "edge.example", "server_port": 22, "user": "alice",
		"password": "one", "private_key_path": "/keys/a", "host_key": []any{"ssh-ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalEndpointOptionsForType("ssh", map[string]any{
		"server": "edge.example", "server_port": 22, "user": "bob",
		"password": "two", "private_key_path": "/keys/b", "host_key": []any{"ssh-ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("SSH credential variants must share path projection: %s != %s", firstJSON, secondJSON)
	}
}

func TestProtocolProjectionPreservesNonCredentialTokenFields(t *testing.T) {
	value, err := CanonicalEndpointOptionsForType("http", map[string]any{
		"server":        "edge.example",
		"authorization": "routing-metadata",
		"headers":       map[string]any{"Token": "routing-hint", "Authorization": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := value.(map[string]any)["headers"].(map[string]any)
	if headers["Token"] != "routing-hint" {
		t.Fatalf("custom Token header was removed: %#v", headers)
	}
	if _, ok := headers["Authorization"]; ok {
		t.Fatalf("authorization header was retained: %#v", headers)
	}
	if value.(map[string]any)["authorization"] != "routing-metadata" {
		t.Fatal("non-header authorization metadata was removed")
	}
}

func TestProtocolProjectionKeepsOpenVPNAuthAlgorithm(t *testing.T) {
	first, err := CanonicalEndpointOptionsForType("openvpn", map[string]any{
		"server": "edge.example", "remote_port": 1194, "auth": "SHA256", "password": "one",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalEndpointOptionsForType("openvpn", map[string]any{
		"server": "edge.example", "remote_port": 1194, "auth": "SHA512", "password": "two",
	})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) == string(secondJSON) {
		t.Fatalf("OpenVPN auth algorithm must remain part of path projection: %s", firstJSON)
	}
}
