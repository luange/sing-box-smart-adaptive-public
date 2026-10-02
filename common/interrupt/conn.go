package interrupt

import (
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

/*type GroupedConn interface {
	MarkAsInternal()
}

func MarkAsInternal(conn any) {
	if groupedConn, isGroupConn := common.Cast[GroupedConn](conn); isGroupConn {
		groupedConn.MarkAsInternal()
	}
}*/

type Conn struct {
	net.Conn
	shard   *groupShard
	element *list.Element[*groupConnItem]
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

/*func (c *Conn) MarkAsInternal() {
	c.element.Value.internal = true
}*/

func (c *Conn) Close() error {
	if c.element.Value.removed.CompareAndSwap(false, true) {
		c.shard.access.Lock()
		c.shard.connections.Remove(c.element)
		c.shard.access.Unlock()
	}
	return c.Conn.Close()
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

func (c *Conn) Upstream() any {
	return c.Conn
}

type PacketConn struct {
	net.PacketConn
	shard   *groupShard
	element *list.Element[*groupConnItem]
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	return n, address, err
}

func (c *PacketConn) WriteTo(p []byte, address net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, address)
	if n > 0 {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

/*func (c *PacketConn) MarkAsInternal() {
	c.element.Value.internal = true
}*/

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if packetReader, ok := c.PacketConn.(N.PacketReader); ok {
		destination, err := packetReader.ReadPacket(buffer)
		if buffer.Len() > 0 {
			c.element.Value.lastActive.Store(time.Now().UnixNano())
		}
		return destination, err
	}
	_, addr, err := buffer.ReadPacketFrom(c.PacketConn)
	if buffer.Len() > 0 {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), err
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if packetWriter, ok := c.PacketConn.(N.PacketWriter); ok {
		err := packetWriter.WritePacket(buffer, destination)
		if err == nil {
			c.element.Value.lastActive.Store(time.Now().UnixNano())
		}
		return err
	}
	defer buffer.Release()
	_, err := c.PacketConn.WriteTo(buffer.Bytes(), destination.UDPAddr())
	if err == nil {
		c.element.Value.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

func (c *PacketConn) Close() error {
	if c.element.Value.removed.CompareAndSwap(false, true) {
		c.shard.access.Lock()
		c.shard.connections.Remove(c.element)
		c.shard.access.Unlock()
	}
	return c.PacketConn.Close()
}

func (c *PacketConn) ReaderReplaceable() bool {
	return true
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return bufio.NewPacketConn(c.PacketConn)
}
