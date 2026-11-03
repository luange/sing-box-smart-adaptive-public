//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"
)

type nestConn struct {
	net.Conn
	up net.Conn
}

func (n *nestConn) Upstream() any { return n.up }

func TestWalkConnChainDepthExceeded(t *testing.T) {
	// 20 wrappers, innermost is nil TCP.
	var cur net.Conn
	for i := 0; i < 20; i++ {
		cur = &nestConn{up: cur}
	}
	if walkConnChain(cur, func(net.Conn) bool { return false }) {
		t.Fatal("depth 20 must return false (truncated)")
	}
	if spliceTCPFromConn(cur) != nil {
		t.Fatal("deep chain must refuse splice even if no TCP found")
	}
}

func TestWalkConnChainFindsTCP(t *testing.T) {
	// Use a real TCP pair so *net.TCPConn is authentic.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Wrap client 3 times.
	var wrapped net.Conn = client
	for i := 0; i < 3; i++ {
		wrapped = &nestConn{up: wrapped}
	}
	if !walkConnChain(wrapped, func(c net.Conn) bool {
		_, ok := c.(*net.TCPConn)
		return ok
	}) {
		t.Fatal("shallow chain must complete")
	}
	if spliceTCPFromConn(wrapped) == nil {
		t.Fatal("expected *net.TCPConn")
	}
}

func TestWalkConnChainSelfRefNoLoop(t *testing.T) {
	n := &nestConn{}
	n.up = n
	// Should break on next==conn, return true (complete walk of 1 node).
	if !walkConnChain(n, func(net.Conn) bool { return false }) {
		t.Fatal("self-ref must not hang / truncate")
	}
}

func TestRefuseIfBufferedDepth(t *testing.T) {
	var cur net.Conn
	for i := 0; i < 20; i++ {
		cur = &nestConn{up: cur}
	}
	if err := refuseIfBuffered(cur); err == nil {
		t.Fatal("deep chain must refuse")
	}
}
