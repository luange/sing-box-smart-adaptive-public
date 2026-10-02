package route

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

type ConnectionManager struct {
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Count() int {
	return m.connections.Len()
}

func (m *ConnectionManager) CloseAll() {
	m.access.Lock()
	var closers []io.Closer
	for element := m.connections.Front(); element != nil; {
		nextElement := element.Next()
		closers = append(closers, element.Value)
		m.connections.Remove(element)
		element = nextElement
	}
	m.access.Unlock()
	for _, closer := range closers {
		common.Close(closer)
	}
}

func (m *ConnectionManager) Close() error {
	m.CloseAll()
	return nil
}

func (m *ConnectionManager) TrackConn(conn net.Conn) net.Conn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedConn{
		Conn:    conn,
		manager: m,
		element: element,
	}
}

func (m *ConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	return &trackedPacketConn{
		PacketConn: conn,
		manager:    m,
		element:    element,
	}
}

// TrackCloser registers an arbitrary closer (e.g. eBPF splice pair) so CloseAll
// releases it. Returns a wrapper that unregisters on Close.
func (m *ConnectionManager) TrackCloser(closer io.Closer) io.Closer {
	if closer == nil {
		return nil
	}
	m.access.Lock()
	element := m.connections.PushBack(closer)
	m.access.Unlock()
	return &trackedCloser{
		Closer:  closer,
		manager: m,
		element: element,
	}
}

type trackedCloser struct {
	io.Closer
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedCloser) Close() error {
	c.manager.access.Lock()
	if c.element != nil {
		c.manager.connections.Remove(c.element)
		c.element = nil
	}
	c.manager.access.Unlock()
	return c.Closer.Close()
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	// Share Extended with traffic trackers so group leaf tags recorded during
	// DialContext are visible to connection_history on close.
	metadata.InitExtended()
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		noteCloseReason(ctx, adapter.ClassifyDialError(err))
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			if chain := metadata.GetRealOutboundChain(); len(chain) > 0 {
				dialerString += "[" + strings.Join(chain, " -> ") + "]"
			}
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		noteCloseReason(ctx, adapter.ClassifyHandshakeError(err))
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	// Module A: learn path after dial success (first connection still userspace). Fail-open.
	// Shared-network transparent flows may surface as mixed; hub learners gate eligibility.
	if metadata.InboundType == C.TypeEBPF || metadata.InboundType == C.TypeMixed {
		if learner := service.FromContext[adapter.VerdictLearner](ctx); learner != nil {
			remoteAP := M.AddrPortFromNet(remoteConn.RemoteAddr())
			learner.MaybeLearnTCP(ctx, this, metadata, remoteAP)
		}
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	if metadata.TLSSpoof != "" {
		spoofConn, spoofErr := tlsspoof.NewConn(remoteConn, metadata.TLSSpoofMethod, metadata.TLSSpoof)
		if spoofErr != nil {
			noteCloseReason(ctx, adapter.ClassifyHandshakeError(spoofErr))
			spoofErr = E.Cause(spoofErr, "tls_spoof setup")
			remoteConn.Close()
			N.CloseOnHandshakeFailure(conn, onClose, spoofErr)
			m.logger.ErrorContext(ctx, spoofErr)
			return
		}
		remoteConn = spoofConn
	}
	serverFirst := sniff.Skip(&metadata)
	var done atomic.Bool
	if m.kickWriteHandshake(ctx, conn, remoteConn, serverFirst, false, &done, onClose) {
		return
	}
	if m.kickWriteHandshake(ctx, remoteConn, conn, serverFirst, true, &done, onClose) {
		return
	}
	// Module B: eBPF sockmap splice (opt-in, fail-open). Master §6.1.
	if splicer := service.FromContext[adapter.ConnectionSplicer](ctx); splicer != nil {
		if splicer.TrySpliceTCP(ctx, metadata.InboundType, this, conn, remoteConn, metadata, onClose) {
			m.logger.DebugContext(ctx, "connection handed to eBPF splice")
			return
		}
	}
	go m.connectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	go m.connectionCopy(ctx, remoteConn, conn, true, &done, onClose)
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.InitExtended()
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			noteCloseReason(ctx, adapter.ClassifyDialError(err))
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if chain := metadata.GetRealOutboundChain(); len(chain) > 0 {
					dialerString += "[" + strings.Join(chain, " -> ") + "]"
				}
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else if packetDialer, withDestination := this.(dialer.PacketDialerWithDestination); withDestination {
			remotePacketConn, destinationAddress, err = packetDialer.ListenPacketWithDestination(ctx, metadata.Destination)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			noteCloseReason(ctx, adapter.ClassifyDialError(err))
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if chain := metadata.GetRealOutboundChain(); len(chain) > 0 {
					dialerString += "[" + strings.Join(chain, " -> ") + "]"
				}
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		noteCloseReason(ctx, adapter.ClassifyHandshakeError(err))
		conn.Close()
		remotePacketConn.Close()
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	// UDP DIRECT learn after proven bind/connect (fail-open).
	if metadata.InboundType == C.TypeEBPF || metadata.InboundType == C.TypeMixed {
		if learner := service.FromContext[adapter.VerdictLearner](ctx); learner != nil {
			remoteAP := metadata.Destination.AddrPort()
			if destinationAddress.IsValid() {
				remoteAP = netip.AddrPortFrom(destinationAddress, metadata.Destination.Port)
			} else if remoteConn != nil {
				if ap := M.AddrPortFromNet(remoteConn.RemoteAddr()); ap.IsValid() {
					remoteAP = ap
				}
			}
			if remoteAP.IsValid() {
				learner.MaybeLearnUDP(ctx, this, metadata, remoteAP)
			}
		}
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else {
			destination := M.SocksaddrFrom(destinationAddress, metadata.Destination.Port)
			if metadata.Destination != destination {
				if metadata.UDPDisableDomainUnmapping {
					remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				} else {
					remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), destination, originDestination)
				}
			} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
				remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	var udpTimeout time.Duration
	if metadata.UDPTimeout > 0 {
		udpTimeout = metadata.UDPTimeout
	} else {
		protocol := metadata.Protocol
		if protocol == "" {
			protocol = C.PortProtocols[metadata.Destination.Port]
		}
		if protocol != "" {
			udpTimeout = C.ProtocolTimeouts[protocol]
		}
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	var done atomic.Bool
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	noteCloseReason(ctx, adapter.ClassifyStreamError(err, !direction))
	if err != nil {
		common.Close(source, destination)
	} else if duplexDst, isDuplex := destination.(N.WriteCloser); isDuplex {
		err = duplexDst.CloseWrite()
		if err != nil {
			noteCloseReason(ctx, adapter.ClassifyStreamError(err, !direction))
			common.Close(source, destination)
		}
	} else {
		destination.Close()
	}
	if done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
		common.Close(source, destination)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

func (m *ConnectionManager) kickWriteHandshake(ctx context.Context, source net.Conn, destination net.Conn, serverFirst bool, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) bool {
	if !N.NeedHandshakeForWrite(destination) {
		return false
	}
	var (
		err          error
		wrotePayload bool
	)
	if serverFirst {
		_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
		_, err = destination.Write(nil)
		_ = destination.SetWriteDeadline(time.Time{})
	} else {
		var cachedBuffer *buf.Buffer
		sourceReader, readCounters := N.UnwrapCountReader(source, nil)
		destinationWriter, writeCounters := N.UnwrapCountWriter(destination, nil)
		if cachedReader, ok := sourceReader.(N.CachedReader); ok {
			cachedBuffer = cachedReader.ReadCached()
		}
		if cachedBuffer != nil {
			wrotePayload = true
			dataLen := cachedBuffer.Len()
			_, err = destinationWriter.Write(cachedBuffer.Bytes())
			cachedBuffer.Release()
			if err == nil {
				for _, counter := range readCounters {
					counter(int64(dataLen))
				}
				for _, counter := range writeCounters {
					counter(int64(dataLen))
				}
			}
		} else {
			_ = destination.SetWriteDeadline(time.Now().Add(C.ReadPayloadTimeout))
			_, err = destinationWriter.Write(nil)
			_ = destination.SetWriteDeadline(time.Time{})
		}
	}
	if err == nil {
		return false
	}
	if !wrotePayload && (E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) || E.IsTimeout(err)) {
		// A probe-style write can time out before any payload is available. The
		// caller deliberately continues with the normal copy path, so this is
		// not a closed connection and must not be recorded as a handshake
		// failure in history.
		return false
	}
	noteCloseReason(ctx, adapter.ClassifyHandshakeError(err))
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
	if !direction {
		m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
	} else {
		m.logger.ErrorContext(ctx, "connection download handshake: ", err)
	}
	return true
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	_, err := bufio.CopyPacket(destination, source)
	noteCloseReason(ctx, classifyPacketCloseError(err, !direction))
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		if onClose != nil {
			onClose(err)
		}
	}
	common.Close(source, destination)
}

func noteCloseReason(ctx context.Context, reason adapter.ConnectionCloseReason) {
	if reason == "" {
		return
	}
	if metadata := adapter.ContextFrom(ctx); metadata != nil && metadata.Extended != nil {
		metadata.Extended.SetCloseReason(reason)
	}
}

func classifyPacketCloseError(err error, clientDirection bool) adapter.ConnectionCloseReason {
	if err == nil {
		if clientDirection {
			return adapter.CloseReasonClientEOF
		}
		return adapter.CloseReasonRemoteEOF
	}
	return adapter.ClassifyStreamError(err, clientDirection)
}

type trackedConn struct {
	net.Conn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any {
	return c.Conn
}

func (c *trackedConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedConn) WriterReplaceable() bool {
	return true
}

type trackedPacketConn struct {
	net.PacketConn
	manager *ConnectionManager
	element *list.Element[io.Closer]
}

func (c *trackedPacketConn) Close() error {
	c.manager.access.Lock()
	c.manager.connections.Remove(c.element)
	c.manager.access.Unlock()
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) Upstream() any {
	return bufio.NewPacketConn(c.PacketConn)
}

func (c *trackedPacketConn) ReaderReplaceable() bool {
	return true
}

func (c *trackedPacketConn) WriterReplaceable() bool {
	return true
}
