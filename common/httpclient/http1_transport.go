package httpclient

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	// A custom Transport does not inherit http.DefaultTransport's limits.  The
	// zero values mean unlimited idle connections across authorities and no
	// idle expiry, which is a leak-shaped failure mode for subscriptions and
	// APIs that encounter many hosts over a long-running core.
	defaultMaxIdleConns        = 64
	defaultMaxIdleConnsPerHost = 8
	defaultIdleConnTimeout     = 90 * time.Second
)

type http1Transport struct {
	transport *http.Transport
}

func newHTTP1Transport(rawDialer N.Dialer, baseTLSConfig tls.Config) *http1Transport {
	transport := &http.Transport{
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		IdleConnTimeout:     defaultIdleConnTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rawDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	if baseTLSConfig != nil {
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(ctx, rawDialer, baseTLSConfig, M.ParseSocksaddr(addr), []string{"http/1.1"}, "")
		}
	}
	return &http1Transport{transport: transport}
}

func (t *http1Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(request)
}

func (t *http1Transport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func (t *http1Transport) Close() error {
	t.CloseIdleConnections()
	return nil
}
