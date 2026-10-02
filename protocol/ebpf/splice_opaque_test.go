//go:build with_ebpf && (linux || android)

package ebpf

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestIsOpaqueRelayLayerTLS(t *testing.T) {
	if !isOpaqueRelayLayer(&tls.Conn{}) {
		t.Fatal("expected *tls.Conn opaque")
	}
}

func TestIsOpaqueRelayLayerTCP(t *testing.T) {
	// nil-safe
	if isOpaqueRelayLayer(nil) {
		t.Fatal("nil must not be opaque")
	}
	// bare TCP type name is not opaque
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("want *net.TCPConn got %T", c)
	}
	if isOpaqueRelayLayer(tcp) {
		t.Fatal("TCPConn must not be opaque")
	}
	if got := spliceTCPFromConn(tcp); got == nil {
		t.Fatal("expected bare TCP spliceable")
	}
}

func TestSpliceTCPFromConnStopsUnderTLS(t *testing.T) {
	// tls.Conn without handshake still has type barrier
	tc := &tls.Conn{}
	if got := spliceTCPFromConn(tc); got != nil {
		t.Fatal("must not peel TCP under TLS")
	}
}
