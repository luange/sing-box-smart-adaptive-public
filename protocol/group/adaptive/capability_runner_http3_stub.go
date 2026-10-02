//go:build !with_quic

package adaptive

import (
	"context"
	"errors"

	N "github.com/sagernet/sing/common/network"
)

func newHTTP3ProbeClient(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
	return nil, errors.New("adaptive HTTP/3 probe requires a with_quic build")
}
