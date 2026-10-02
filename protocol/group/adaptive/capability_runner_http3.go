//go:build with_quic

package adaptive

import (
	"context"
	stdTLS "crypto/tls"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	sBufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

func newHTTP3ProbeClient(ctx context.Context, dialer N.Dialer, target ProbeTarget) (probeHTTPClient, error) {
	transport := &http3.Transport{
		TLSClientConfig: &stdTLS.Config{MinVersion: stdTLS.VersionTLS13, Time: ntp.TimeFuncFromContext(ctx), RootCAs: adapter.RootPoolFromContext(ctx), NextProtos: []string{http3.NextProtoH3}},
		Dial: func(dialContext context.Context, address string, tlsConfig *stdTLS.Config, config *quic.Config) (*quic.Conn, error) {
			udpConnection, err := dialer.DialContext(dialContext, N.NetworkUDP, M.ParseSocksaddr(address))
			if err != nil {
				return nil, err
			}
			packetConnection := sBufio.NewUnbindPacketConn(udpConnection)
			connection, err := quic.DialEarly(dialContext, packetConnection, udpConnection.RemoteAddr(), tlsConfig, config)
			if err != nil {
				_ = udpConnection.Close()
				return nil, err
			}
			return connection, nil
		},
	}
	return &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		allowed := map[string]struct{}{target.executionHost(): {}}
		for _, host := range target.executionRedirectHosts() {
			allowed[host] = struct{}{}
		}
		if len(via) >= maxProbeRedirects || !probeRedirectAllowed(request.URL, allowed) {
			return errProbeRedirectPolicy
		}
		return nil
	}}, nil
}
