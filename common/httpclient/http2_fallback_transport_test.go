package httpclient

import (
	"fmt"
	"testing"
	"time"
)

func TestHTTP2FallbackAuthorityCacheIsBoundedAndExpires(t *testing.T) {
	transport := &http2FallbackTransport{fallbackAuthority: make(map[string]time.Time)}
	for i := 0; i < h2FallbackAuthorityLimit+1; i++ {
		transport.markH2Fallback(fmt.Sprintf("host-%d.example", i))
	}
	if got := len(transport.fallbackAuthority); got != h2FallbackAuthorityLimit {
		t.Fatalf("fallback authority entries = %d, want %d", got, h2FallbackAuthorityLimit)
	}
	transport.fallbackAccess.Lock()
	transport.fallbackAuthority["expired.example"] = time.Now().Add(-time.Second)
	transport.fallbackAccess.Unlock()
	if transport.isH2Fallback("expired.example") {
		t.Fatal("expired fallback authority remained active")
	}
	transport.fallbackAccess.RLock()
	_, found := transport.fallbackAuthority["expired.example"]
	transport.fallbackAccess.RUnlock()
	if found {
		t.Fatal("expired fallback authority was not removed")
	}
}
