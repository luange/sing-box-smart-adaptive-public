package urltest

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestProbeTLSServerName(t *testing.T) {
	for _, test := range []struct {
		host string
		want string
	}{
		{host: "1.1.1.1", want: "cloudflare-dns.com"},
		{host: "1.0.0.1", want: "cloudflare-dns.com"},
		{host: "www.gstatic.com", want: "www.gstatic.com"},
	} {
		t.Run(test.host, func(t *testing.T) {
			if got := probeTLSServerName(test.host); got != test.want {
				t.Fatalf("probeTLSServerName(%q) = %q, want %q", test.host, got, test.want)
			}
		})
	}
}

func TestIdentityHistoryDoesNotReuseProviderAlias(t *testing.T) {
	storage := NewHistoryStorage()
	keyA := HistoryKey{PathIdentity: "path-a", ProbeTarget: "target-a", Network: "tcp"}
	keyB := HistoryKey{PathIdentity: "path-b", ProbeTarget: "target-a", Network: "tcp"}
	history := &adapter.URLTestHistory{Time: time.Now(), Delay: 30}
	storage.StoreURLTestHistoryKey(keyA, history)
	if got := storage.LoadURLTestHistoryKey(keyA); got != history {
		t.Fatalf("identity history did not round-trip")
	}
	if got := storage.LoadURLTestHistoryKey(keyB); got != nil {
		t.Fatalf("provider alias fallback reused another endpoint's history: %#v", got)
	}
}

func TestIdentityHistorySeparatesProbeContext(t *testing.T) {
	storage := NewHistoryStorage()
	keyTCP := HistoryKey{PathIdentity: "path", ProbeTarget: "target-a", Network: "tcp"}
	keyTCPOtherTarget := HistoryKey{PathIdentity: "path", ProbeTarget: "target-b", Network: "tcp"}
	keyUDP := HistoryKey{PathIdentity: "path", ProbeTarget: "target-a", Network: "udp"}
	storage.StoreURLTestHistoryKey(keyTCP, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	if storage.LoadURLTestHistoryKey(keyTCPOtherTarget) != nil {
		t.Fatal("different probe target reused URL-test history")
	}
	if storage.LoadURLTestHistoryKey(keyUDP) != nil {
		t.Fatal("different network family reused URL-test history")
	}
}

func TestIdentityHistorySeparatesAuthenticatedCredentials(t *testing.T) {
	storage := NewHistoryStorage()
	keyA := HistoryKey{PathIdentity: "path", DialIdentity: "credential-a", ProbeTarget: "target", Network: "tcp"}
	keyB := HistoryKey{PathIdentity: "path", DialIdentity: "credential-b", ProbeTarget: "target", Network: "tcp"}
	storage.StoreURLTestHistoryKey(keyA, &adapter.URLTestHistory{Time: time.Now(), Delay: 25})
	if storage.LoadURLTestHistoryKey(keyB) != nil {
		t.Fatal("different authenticated dial identities reused URL-test history")
	}
}
