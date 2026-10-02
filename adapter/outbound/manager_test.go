package outbound

import (
	"context"
	"net"
	"testing"

	A "github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type managerTestOutbound struct{ Adapter }

func (m *managerTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (m *managerTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestManagerRemoveRejectsInconsistentIndexWithoutPanic(t *testing.T) {
	leaf := &managerTestOutbound{Adapter: NewAdapter(C.TypeDirect, "provider-leaf", []string{N.NetworkTCP}, nil)}
	manager := &Manager{
		outboundByTag: map[string]A.Outbound{"provider-leaf": leaf},
		dependByTag:   make(map[string][]string),
	}
	if err := manager.Remove("provider-leaf"); err == nil {
		t.Fatal("expected inconsistent index error")
	}
	if manager.outboundByTag["provider-leaf"] != leaf {
		t.Fatal("failed removal must not partially delete the outbound map entry")
	}
}
