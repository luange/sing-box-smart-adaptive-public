//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"reflect"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

// TrySpliceTCP attempts module B sockmap splice. Returns true if the connection
// was taken over (caller must not start userspace copy). Always fail-open.
func TrySpliceTCP(
	ctx context.Context,
	coord *outboundCoordinator,
	inboundType string,
	dialer N.Dialer,
	local net.Conn,
	remote net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
	track func(io.Closer),
) bool {
	if coord == nil || !coord.enabled() {
		return false
	}
	// W4 defense-in-depth: startSplice already refuses to attach when
	// half_close=passthrough; keep this gate if a backend is ever wired another way.
	if coord.HalfClose() == "passthrough" {
		return false
	}
	backend := coord.Splice()
	if backend == nil || backend.IsClosed() {
		return false
	}
	// E3: inbound type whitelist — default eBPF only (master §6.1).
	if !spliceInboundOK(inboundType) {
		coord.info("eBPF splice skip: inbound type ", inboundType)
		return false
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment || metadata.TLSSpoof != "" {
		coord.info("eBPF splice skip: tls fragment/spoof requires userspace")
		return false
	}

	localTCP := spliceTCPFromConn(local)
	remoteTCP := spliceTCPFromConn(remote)
	if localTCP == nil || remoteTCP == nil {
		// Proxy AEAD/TLS leaves almost always hit this; Debug avoids log storms.
		// Unexpected bare-inbound misses still visible when type whitelist passes later.
		if coord.logger != nil {
			coord.noteSpliceSkipBareTCP()
			coord.logger.Debug("eBPF splice skip: not bare TCP (local=", localTCP != nil, " remote=", remoteTCP != nil, ")")
		}
		return false
	}
	// E4: outbound type whitelist (default direct/ebpf/socks/http).
	// Extension: adapter.SpliceCapableConn.SpliceReady() on either side bypasses
	// the type list so encrypted leaves can opt in later without expanding the
	// blanket whitelist (still requires a real bare TCP from SpliceReady).
	typeOK := coord.spliceOutboundOK(dialer)
	if !typeOK && (connHasSpliceReady(local) || connHasSpliceReady(remote)) {
		typeOK = true
	}
	if !typeOK {
		if outbound, ok := dialer.(adapter.Outbound); ok {
			coord.noteSpliceSkipType()
			coord.info("eBPF splice skip: outbound type ", outbound.Type())
		} else {
			coord.noteSpliceSkipType()
			coord.info("eBPF splice skip: outbound type unknown")
		}
		return false
	}

	// Q6: map-independent gates BEFORE BeginPair (no bpf write on reject path).
	// flush/drain are pure userspace TCP — peer map not required.
	if err := refuseIfBuffered(local); err != nil {
		coord.info("eBPF splice skip: ", err)
		return false
	}
	if err := refuseIfBuffered(remote); err != nil {
		coord.info("eBPF splice skip: remote ", err)
		return false
	}
	if err := flushCachedToRemote(local, remoteTCP); err != nil {
		coord.info("eBPF splice skip: flush cached: ", err)
		return false
	}
	// Drain kernel recvq while still userspace-only (client-first HTTP, etc.).
	if err := drainTCPRecvTo(localTCP, remoteTCP); err != nil {
		coord.info("eBPF splice skip: drain local recvq: ", err)
		return false
	}
	if err := drainTCPRecvTo(remoteTCP, localTCP); err != nil {
		coord.info("eBPF splice skip: drain remote recvq: ", err)
		return false
	}
	// E2 pre-Activate: any remaining queued bytes would be dual-moved.
	if n, err := tcpRecvQueueLen(localTCP); err != nil || n > 0 {
		coord.noteSpliceSkipRecvq()
		coord.info("eBPF splice skip: local recvq not empty (n=", n, " err=", err, ")")
		return false
	}
	if n, err := tcpRecvQueueLen(remoteTCP); err != nil || n > 0 {
		coord.noteSpliceSkipRecvq()
		coord.info("eBPF splice skip: remote recvq not empty (n=", n, " err=", err, ")")
		return false
	}

	// Two-phase pair (A-2): BeginPair → Activate only after gates pass.
	pair, err := backend.BeginPair(localTCP, remoteTCP)
	if err != nil {
		coord.info("eBPF splice skip: begin pair: ", err)
		return false
	}
	if err := pair.Activate(); err != nil {
		_ = pair.Release()
		coord.info("eBPF splice skip: activate: ", err)
		return false
	}
	// §4.3 residual window: bytes arriving between last FIONREAD and Activate.
	// If either recvq is non-empty now, dual-move risk — Release (activated→FIN)
	// and fail-open to userspace (client may retry; better than silent corruption).
	if n, err := tcpRecvQueueLen(localTCP); err != nil || n > 0 {
		_ = pair.Release()
		coord.noteSpliceSkipRecvq()
		coord.info("eBPF splice skip: post-activate local recvq (n=", n, " err=", err, ")")
		return false
	}
	if n, err := tcpRecvQueueLen(remoteTCP); err != nil || n > 0 {
		_ = pair.Release()
		coord.noteSpliceSkipRecvq()
		coord.info("eBPF splice skip: post-activate remote recvq (n=", n, " err=", err, ")")
		return false
	}

	done := make(chan struct{})
	watcher := coord.SpliceWatcher()
	pair.SetOnRelease(func() {
		if watcher != nil {
			watcher.Remove(pair)
		}
		select {
		case <-done:
		default:
			close(done)
		}
		if onClose != nil {
			onClose(nil)
		}
	})
	if track != nil {
		track(pairCloser{pair: pair})
	}

	// Q5: prefer backend-level single epoll watcher; fall back to per-pair.
	idle := coord.IdleTimeout()
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	if watcher != nil && watcher.Add(pair) {
		// shared watcher owns close/idle; no per-pair goroutine
	} else {
		if watcher != nil && coord.logger != nil {
			coord.logger.Warn("eBPF splice pair watch: backend register failed, per-pair fallback")
		}
		go watchSplicePair(ctx, pair, backend.Accounting(), idle, done)
	}
	if coord.logger != nil {
		coord.noteSpliceActive()
		coord.logger.Info("eBPF splice pair active")
	}
	return true
}

func (c *outboundCoordinator) info(args ...any) {
	if c == nil || c.logger == nil {
		return
	}
	c.logger.Info(args...)
}

type pairCloser struct {
	pair *ECommon.SplicePair
}

func (p pairCloser) Close() error {
	if p.pair == nil {
		return nil
	}
	return p.pair.Release()
}

func watchSplicePair(
	ctx context.Context,
	pair *ECommon.SplicePair,
	accounting bool,
	idle time.Duration,
	done <-chan struct{},
) {
	// Prefer EPOLLRDHUP on both sockets; fall back to idle/liveness if epoll setup fails.
	// stopEpoll unblocks EpollWait on pair release so Close() cannot strand waiters.
	stopEpoll := make(chan struct{})
	epollDone := make(chan struct{})
	if startSpliceEpollWatch(pair, epollDone, stopEpoll) {
		go func() {
			select {
			case <-epollDone:
				_ = pair.Release()
			case <-done:
			case <-ctx.Done():
			}
			close(stopEpoll)
		}()
	}

	tickerInterval := idle / 2
	if tickerInterval < 5*time.Second {
		tickerInterval = 5 * time.Second
	}
	if tickerInterval > idle {
		tickerInterval = idle
	}
	// Q5 step1: drop 2s liveTick/TCP_INFO poll — EPOLLRDHUP|HUP|ERR covers peer death.
	// Byte-idle sweep (accounting) remains as §4.3 residual-window safety net.
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()
	var lastUp, lastDown uint64
	stale := 0
	for {
		select {
		case <-ctx.Done():
			_ = pair.Release()
			return
		case <-done:
			return
		case <-ticker.C:
			// Optional light liveness only when accounting is off (no byte signal).
			if !accounting {
				if !splicePairAlive(pair) {
					_ = pair.Release()
					return
				}
				continue
			}
			up, down, err := pair.Bytes()
			if err != nil {
				_ = pair.Release()
				return
			}
			if up == lastUp && down == lastDown {
				stale++
				if stale >= 2 {
					_ = pair.Release()
					return
				}
			} else {
				stale = 0
				lastUp, lastDown = up, down
			}
		}
	}
}

func startSpliceEpollWatch(pair *ECommon.SplicePair, fired chan struct{}, stop <-chan struct{}) bool {
	if pair == nil {
		return false
	}
	left, _ := pair.LeftConn().(*net.TCPConn)
	right, _ := pair.RightConn().(*net.TCPConn)
	if left == nil || right == nil {
		return false
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		// Q5: epoll failure must not be silent — caller still uses idle sweep.
		// (Warn once at call site if needed; per-pair flood avoided by rare path.)
		return false
	}
	add := func(conn *net.TCPConn) error {
		raw, err := conn.SyscallConn()
		if err != nil {
			return err
		}
		var ctrlErr error
		err = raw.Control(func(fd uintptr) {
			ctrlErr = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, int(fd), &unix.EpollEvent{
				Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR,
				Fd:     int32(fd),
			})
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
	if err := add(left); err != nil {
		_ = unix.Close(epfd)
		return false
	}
	if err := add(right); err != nil {
		_ = unix.Close(epfd)
		return false
	}
	go func() {
		defer unix.Close(epfd)
		events := make([]unix.EpollEvent, 2)
		for {
			// Timed wait so stop can be observed without relying on edge events.
			n, err := unix.EpollWait(epfd, events, 500)
			select {
			case <-stop:
				return
			default:
			}
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return
			}
			if n > 0 {
				select {
				case <-fired:
				default:
					close(fired)
				}
				return
			}
		}
	}()
	return true
}

func splicePairAlive(pair *ECommon.SplicePair) bool {
	if pair == nil {
		return false
	}
	return tcpConnAlive(pair.LeftConn()) && tcpConnAlive(pair.RightConn())
}

func tcpConnAlive(conn net.Conn) bool {
	tcp, ok := conn.(*net.TCPConn)
	if !ok || tcp == nil {
		return false
	}
	var alive bool = true
	raw, err := tcp.SyscallConn()
	if err != nil {
		return false
	}
	_ = raw.Control(func(fd uintptr) {
		nerr, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil || nerr != 0 {
			alive = false
			return
		}
		// Linux TCP_INFO: first byte is tcpi_state.
		// ESTABLISHED=1, FIN_WAIT1=4, FIN_WAIT2=5, CLOSE_WAIT=8 still carry data;
		// CLOSE=7, TIME_WAIT=6, LAST_ACK=9, CLOSING=11 are terminal for splice.
		var info [256]byte
		size := uint32(len(info))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(unix.TCP_INFO),
			uintptr(unsafe.Pointer(&info[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			return
		}
		switch info[0] {
		case 1, 4, 5, 8: // ESTABLISHED, FIN_WAIT*, CLOSE_WAIT
			alive = true
		case 6, 7, 9, 11: // TIME_WAIT, CLOSE, LAST_ACK, CLOSING
			alive = false
		default:
			// SYN_* / LISTEN unexpected for spliced pair.
			alive = false
		}
	})
	return alive
}

func spliceInboundOK(inboundType string) bool {
	// E3 decision: contract §6.1 P0 surface is eBPF inbound only.
	// redirect/tproxy require explicit future authorization + lab evidence.
	return inboundType == C.TypeEBPF
}

// tcpRecvQueueLen returns SO_RCVBUF pending bytes via FIONREAD (E2).
func tcpRecvQueueLen(conn *net.TCPConn) (int, error) {
	if conn == nil {
		return 0, E.New("nil conn")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var ctrlErr error
	err = raw.Control(func(fd uintptr) {
		// TIOCINQ == FIONREAD on Linux (queued recv bytes).
		n, ctrlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	})
	if err != nil {
		return 0, err
	}
	return n, ctrlErr
}

// drainTCPRecvTo moves any currently queued kernel recv bytes from src to dst
// in userspace. Call only before Activate (A-2). Caps iterations to avoid
// spinning if the peer keeps flooding during the drain window.
//
// 50ms read deadline: enough for a local-kernel recvq drain without hanging the
// attempt path; always cleared before return so Activate/userspace copy is not
// left with a short deadline (Q14).
func drainTCPRecvTo(src, dst *net.TCPConn) error {
	if src == nil || dst == nil {
		return nil
	}
	const maxRounds = 32
	var buf []byte
	for range maxRounds {
		n, err := tcpRecvQueueLen(src)
		if err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}
		// Q7: allocate only when FIONREAD > 0.
		need := n
		if need > 64*1024 {
			need = 64 * 1024
		}
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		_ = src.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		nr, rerr := src.Read(buf[:need])
		_ = src.SetReadDeadline(time.Time{})
		if nr > 0 {
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				return E.Cause(werr, "drain recvq write")
			}
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() && nr > 0 {
				continue
			}
			if rerr == io.EOF && nr > 0 {
				return nil
			}
			// Q14: real error with nr>0 previously fell through as success.
			if nr > 0 {
				return E.Cause(rerr, "drain recvq read after partial")
			}
			return E.Cause(rerr, "drain recvq read")
		}
	}
	// Still non-empty after cap → caller FIONREAD gate will fail-open.
	return nil
}

// connChainMaxDepth bounds wrapper unwrap; deeper chains refuse splice (fail-open).
// Mirrors common/ebpf.unwrapTCPConn depth (intentionally separate packages — N4).
const connChainMaxDepth = 16

// walkConnChain visits conn and Upstream/NetConn wrappers without heap maps (Q7/N4).
// fn return true = early stop (complete). Return false only if depth exceeded (truncated).
func walkConnChain(conn net.Conn, fn func(net.Conn) bool) bool {
	for depth := 0; conn != nil; depth++ {
		if depth >= connChainMaxDepth {
			return false // truncated: chain not fully inspected
		}
		if fn(conn) {
			return true // early stop: caller got an answer
		}
		type upstreamer interface{ Upstream() any }
		if u, ok := conn.(upstreamer); ok {
			if next, ok := u.Upstream().(net.Conn); ok && next != nil && next != conn {
				conn = next
				continue
			}
		}
		type netConner interface{ NetConn() net.Conn }
		if n, ok := conn.(netConner); ok {
			if next := n.NetConn(); next != nil && next != conn {
				conn = next
				continue
			}
		}
		break
	}
	return true // walked to end
}

func connHasSpliceReady(conn net.Conn) bool {
	ready := false
	_ = walkConnChain(conn, func(c net.Conn) bool {
		if sc, ok := c.(adapter.SpliceCapableConn); ok {
			if sc.SpliceReady() != nil {
				ready = true
				return true
			}
		}
		return false
	})
	return ready
}

// isOpaqueRelayLayer returns true for connection wrappers that transform bytes
// (TLS / proxy crypto / framed protocols). Walking *through* them to an inner
// *net.TCPConn and splicing that TCP would bypass the transform → corruption.
// Transparent wrappers (buffers, counters, deadlines) must return false.
func isOpaqueRelayLayer(c net.Conn) bool {
	if c == nil {
		return false
	}
	if _, ok := c.(*tls.Conn); ok {
		return true
	}
	// Avoid importing every protocol package; name-match is fail-closed enough.
	name := reflect.TypeOf(c).String()
	// strip pointer prefix for matching
	name = strings.TrimPrefix(name, "*")
	opaqueSubstr := []string{
		"tls.Conn", "utls.", "tlsfragment.", "tlsspoof.",
		"vmess.", "vless.", "trojan.", "shadowsocks.", "shadowtls.",
		"anytls.", "hysteria.", "tuic.", "wireguard.", "naive.",
		"reality.", "xtls.", "smux.", "yamux.", "mux.",
	}
	lower := strings.ToLower(name)
	for _, s := range opaqueSubstr {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func spliceTCPFromConn(conn net.Conn) *net.TCPConn {
	var foundCapable *net.TCPConn
	var foundTCP *net.TCPConn
	opaque := false
	complete := walkConnChain(conn, func(c net.Conn) bool {
		// SpliceCapableConn is the extension point for post-handshake / post-crypto
		// plain TCP (design §3.6). Prefer over bare unwrap.
		if sc, ok := c.(adapter.SpliceCapableConn); ok {
			if t := sc.SpliceReady(); t != nil {
				foundCapable = t
				return true
			}
			// Declared incapable at this layer — keep walking only if transparent.
		}
		if isOpaqueRelayLayer(c) {
			opaque = true
			return true // stop: do not peel under crypto
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			foundTCP = tcp
			return true
		}
		return false
	})
	if foundCapable != nil {
		return foundCapable
	}
	if opaque {
		return nil
	}
	if !complete {
		return nil // depth exceeded before finding TCP — refuse splice
	}
	return foundTCP
}

// flushCachedToRemote drains N.CachedReader / ReadCached buffers along the local
// wrapper chain and writes them to remote so SOCKMAP does not lose sniff payload.
// Must run before Activate (A-2: userspace-only move while kernel is not splicing).
func flushCachedToRemote(local net.Conn, remote net.Conn) error {
	if local == nil || remote == nil {
		return nil
	}
	var flushErr error
	complete := walkConnChain(local, func(cur net.Conn) bool {
		var buffer *buf.Buffer
		if cr, ok := cur.(N.CachedReader); ok {
			buffer = cr.ReadCached()
		} else if cr, ok := cur.(interface{ ReadCached() *buf.Buffer }); ok {
			buffer = cr.ReadCached()
		}
		if buffer != nil {
			data := buffer.Bytes()
			if len(data) > 0 {
				_, err := remote.Write(data)
				buffer.Release()
				if err != nil {
					flushErr = E.Cause(err, "flush cached to remote before splice")
					return true
				}
			} else {
				buffer.Release()
			}
		}
		return false
	})
	if flushErr != nil {
		return flushErr
	}
	if !complete {
		return E.New("conn wrapper chain too deep; skip splice")
	}
	return nil
}

// refuseIfBuffered returns error if any wrapper in the chain still holds unread
// application bytes after flush. Splice cannot see those bytes.
func refuseIfBuffered(conn net.Conn) error {
	var refuseErr error
	complete := walkConnChain(conn, func(cur net.Conn) bool {
		type readerState interface{ ReaderReplaceable() bool }
		if rs, ok := cur.(readerState); ok && !rs.ReaderReplaceable() {
			refuseErr = E.New("conn has buffered data; skip splice")
			return true
		}
		return false
	})
	if refuseErr != nil {
		return refuseErr
	}
	if !complete {
		return E.New("conn wrapper chain too deep; skip splice")
	}
	return nil
}
