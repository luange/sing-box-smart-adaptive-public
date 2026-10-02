package adapter

import (
	"context"
	"io"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type ConnectionManager interface {
	Lifecycle
	Count() int
	CloseAll()
	TrackConn(conn net.Conn) net.Conn
	TrackPacketConn(conn net.PacketConn) net.PacketConn
	// TrackCloser registers an arbitrary closer (e.g. eBPF splice pair) for CloseAll.
	TrackCloser(closer io.Closer) io.Closer
	NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
