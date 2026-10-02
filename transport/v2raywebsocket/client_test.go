package v2raywebsocket

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type failingUpgradeDialer struct{}

func (failingUpgradeDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
	}()
	return client, nil
}

func (failingUpgradeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestDialContextDoesNotReturnTypedNilOnUpgradeFailure(t *testing.T) {
	client := &Client{
		dialer:     failingUpgradeDialer{},
		requestURL: url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		headers:    make(http.Header),
	}
	conn, err := client.DialContext(context.Background())
	if err == nil {
		t.Fatal("expected websocket upgrade failure")
	}
	if conn != nil {
		t.Fatal("upgrade failure returned a non-nil connection")
	}
}

var _ N.Dialer = failingUpgradeDialer{}
