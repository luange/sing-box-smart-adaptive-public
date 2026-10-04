package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type failedProbeDialer struct {
	N.Dialer
	err error
}

func (d failedProbeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

func TestURLTestReportsTargetHTTPStatusWithoutChangingGenericSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	var observation ProbeObservation
	ctx := WithProbeObserver(context.Background(), func(value ProbeObservation) { observation = value })
	if _, err := URLTest(ctx, server.URL+"/generate_204", N.SystemDialer); err != nil {
		t.Fatalf("generic URLTest must retain its connectivity-only contract: %v", err)
	}
	if observation.Stage != "target_response" || observation.HTTPStatus != http.StatusForbidden {
		t.Fatalf("target response stage/status = %+v", observation)
	}
}

func TestURLTestReportsUpstreamFailureStage(t *testing.T) {
	var observation ProbeObservation
	ctx := WithProbeObserver(context.Background(), func(value ProbeObservation) { observation = value })
	_, err := URLTest(ctx, "https://probe.example/generate_204", failedProbeDialer{err: &net.DNSError{Err: "temporary failure", Name: "probe.example"}})
	if err == nil || observation.Stage != "dns" || observation.HTTPStatus != 0 {
		t.Fatalf("DNS failure was not staged: observation=%+v err=%v", observation, err)
	}
}

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
