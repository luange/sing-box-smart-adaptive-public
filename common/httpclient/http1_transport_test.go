package httpclient

import "testing"

func TestHTTP1TransportBoundsIdleConnections(t *testing.T) {
	transport := newHTTP1Transport(nil, nil).transport
	if transport.MaxIdleConns != defaultMaxIdleConns {
		t.Fatalf("MaxIdleConns = %d, want %d", transport.MaxIdleConns, defaultMaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != defaultIdleConnTimeout {
		t.Fatalf("IdleConnTimeout = %s, want %s", transport.IdleConnTimeout, defaultIdleConnTimeout)
	}
}
