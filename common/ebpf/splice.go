//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include "singbox_ebpf.h"
#include "singbox_ebpf_out.h"

static int singbox_ebpf_splice_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t max_entries,
	int enable_accounting,
	struct sb_splice_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_splice_prepare(
		object,
		object_size,
		max_entries,
		enable_accounting != 0,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_splice_attach(struct sb_splice_runtime *runtime, int *saved_errno) {
	int result = sb_ebpf_splice_attach(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_splice_close(struct sb_splice_runtime *runtime, int *saved_errno) {
	int result = sb_ebpf_splice_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
)

//go:embed native/splice.bpf.o
var spliceObject []byte

// SpliceStats are global splice counters (module B observability).
type SpliceStats struct {
	PairsCreated     uint64
	PairsReleased    uint64
	Redirects        uint64
	RedirectFailures uint64
	PeerMisses       uint64
	Passthrough      uint64
	ActivePairs      uint64
}

// SplicePair is one kernel-spliced TCP connection pair.
type SplicePair struct {
	backend   *SpliceBackend
	leftKey   spliceKey
	rightKey  spliceKey
	leftConn  net.Conn
	rightConn net.Conn
	created   time.Time
	released  bool
	activated bool // SOCKHASH inserted
	mu        sync.Mutex
	onRelease func()
}

// SetOnRelease registers a callback invoked once after Release completes.
func (p *SplicePair) SetOnRelease(fn func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.onRelease = fn
	p.mu.Unlock()
}

// SpliceBackend owns SOCKHASH + sk_skb programs.
type SpliceBackend struct {
	access     sync.RWMutex
	runtime    *C.struct_sb_splice_runtime
	closed     bool
	attached   bool
	pairs      map[*SplicePair]struct{}
	maxPairs   uint32
	accounting bool
	// Go-side pair counters (kernel ARRAY is only written by BPF programs for
	// redirect/miss/passthrough). Avoids userland RMW races on the shared map.
	pairsCreated  atomic.Uint64
	pairsReleased atomic.Uint64
	possibleCPUs  int
}

// PrepareSplice loads maps/programs from the embedded object. Does not attach.
func PrepareSplice(maxEntries uint32, accounting bool) (*SpliceBackend, error) {
	if len(spliceObject) < 4 {
		return nil, E.New("splice BPF object missing; run make -C common/ebpf generate")
	}
	runtime := (*C.struct_sb_splice_runtime)(C.calloc(1, C.size_t(unsafe.Sizeof(C.struct_sb_splice_runtime{}))))
	if runtime == nil {
		return nil, E.New("allocate splice runtime")
	}
	var savedErrno C.int
	acc := 0
	if accounting {
		acc = 1
	}
	// E1: know possible CPU count before creating PERCPU maps / ever touching bytes map.
	cpus, cpuErr := possibleCPUCount()
	if cpuErr != nil {
		if accounting {
			// Fail open at coordinator: refuse prepare so splice stays off.
			C.free(unsafe.Pointer(runtime))
			return nil, E.Cause(cpuErr, "detect possible CPUs for PERCPU splice maps")
		}
		// accounting=false: never touch bytes map; CPU count unused.
		cpus = 0
	}
	if accounting && cpus < 1 {
		C.free(unsafe.Pointer(runtime))
		return nil, E.New("possible CPU count must be >= 1 when accounting is enabled")
	}
	if C.singbox_ebpf_splice_prepare(
		(*C.uint8_t)(unsafe.Pointer(&spliceObject[0])),
		C.size_t(len(spliceObject)),
		C.uint32_t(maxEntries),
		C.int(acc),
		runtime,
		&savedErrno,
	) != 0 {
		C.free(unsafe.Pointer(runtime))
		return nil, eBPFOperationError("prepare splice", syscall.Errno(savedErrno))
	}
	return &SpliceBackend{
		runtime:      runtime,
		pairs:        make(map[*SplicePair]struct{}),
		maxPairs:     maxEntries,
		accounting:   accounting,
		possibleCPUs: cpus,
	}, nil
}

func (b *SpliceBackend) Attach() error {
	if b == nil {
		return E.New("nil splice backend")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || b.runtime == nil {
		return E.New("splice backend closed")
	}
	if b.attached {
		return nil
	}
	var savedErrno C.int
	if C.singbox_ebpf_splice_attach(b.runtime, &savedErrno) != 0 {
		return eBPFOperationError("attach splice", syscall.Errno(savedErrno))
	}
	// Enable dataplane after programs are attached.
	ctrl := spliceControl{Enabled: 1}
	if b.accounting {
		ctrl.Flags = spliceCtrlAccounting
	}
	if err := b.writeControl(ctrl); err != nil {
		_ = b.detachLocked()
		return err
	}
	b.attached = true
	return nil
}

func (b *SpliceBackend) writeControl(ctrl spliceControl) error {
	if b.runtime == nil || b.runtime.control_map_fd < 0 {
		return E.New("splice control map missing")
	}
	var key uint32
	return updateMap(int(b.runtime.control_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&ctrl))
}

func (b *SpliceBackend) detachLocked() error {
	if b.runtime == nil {
		return nil
	}
	// Disable before detach.
	_ = b.writeControl(spliceControl{Enabled: 0})
	var savedErrno C.int
	if C.singbox_ebpf_splice_close(b.runtime, &savedErrno) != 0 {
		return eBPFOperationError("close splice", syscall.Errno(savedErrno))
	}
	C.free(unsafe.Pointer(b.runtime))
	b.runtime = nil
	b.attached = false
	return nil
}

func (b *SpliceBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	if b.closed {
		b.access.Unlock()
		return nil
	}
	b.closed = true
	pairs := make([]*SplicePair, 0, len(b.pairs))
	for pair := range b.pairs {
		pairs = append(pairs, pair)
	}
	b.pairs = nil
	b.access.Unlock()
	for _, pair := range pairs {
		_ = pair.Release()
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.detachLocked()
}

func (b *SpliceBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.closed
}

// Accounting reports whether per-pair byte counters are enabled.
func (b *SpliceBackend) Accounting() bool {
	if b == nil {
		return false
	}
	return b.accounting
}

// Pair is a test/helper that BeginPair+Activate in one shot.
// Production path: BeginPair → flush → recvq empty check → Activate.
func (b *SpliceBackend) Pair(left, right net.Conn) (*SplicePair, error) {
	pair, err := b.BeginPair(left, right)
	if err != nil {
		return nil, err
	}
	if err := pair.Activate(); err != nil {
		_ = pair.Release()
		return nil, err
	}
	return pair, nil
}

// BeginPair installs peer map + counters only. Data path stays userspace until Activate.
func (b *SpliceBackend) BeginPair(left, right net.Conn) (*SplicePair, error) {
	if b == nil {
		return nil, E.New("nil splice backend")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || !b.attached || b.runtime == nil {
		return nil, E.New("splice backend not ready")
	}
	if uint32(len(b.pairs)) >= b.maxPairs && b.maxPairs > 0 {
		return nil, E.New("splice pair capacity reached")
	}

	leftTCP, ok := unwrapTCPConn(left)
	if !ok {
		return nil, E.New("left conn is not *net.TCPConn")
	}
	rightTCP, ok := unwrapTCPConn(right)
	if !ok {
		return nil, E.New("right conn is not *net.TCPConn")
	}

	leftKey, err := tcpConnKey(leftTCP)
	if err != nil {
		return nil, E.Cause(err, "left splice key")
	}
	rightKey, err := tcpConnKey(rightTCP)
	if err != nil {
		return nil, E.Cause(err, "right splice key")
	}

	// 1) peer map both directions (no dataplane yet without SOCKHASH)
	if err := updateMap(int(b.runtime.peer_map_fd), unsafe.Pointer(&leftKey), unsafe.Pointer(&rightKey)); err != nil {
		return nil, E.Cause(err, "write peer left→right")
	}
	if err := updateMap(int(b.runtime.peer_map_fd), unsafe.Pointer(&rightKey), unsafe.Pointer(&leftKey)); err != nil {
		_ = deleteMap(int(b.runtime.peer_map_fd), unsafe.Pointer(&leftKey))
		return nil, E.Cause(err, "write peer right→left")
	}
	if err := b.zeroPerCPUBytes(leftKey); err != nil {
		b.rollbackPeer(leftKey, rightKey)
		return nil, E.Cause(err, "zero left bytes")
	}
	if err := b.zeroPerCPUBytes(rightKey); err != nil {
		b.rollbackPeer(leftKey, rightKey)
		return nil, E.Cause(err, "zero right bytes")
	}

	pair := &SplicePair{
		backend:   b,
		leftKey:   leftKey,
		rightKey:  rightKey,
		leftConn:  leftTCP,
		rightConn: rightTCP,
		created:   time.Now(),
	}
	b.pairs[pair] = struct{}{}
	b.pairsCreated.Add(1)
	return pair, nil
}

// Activate inserts both sockets into SOCKHASH — kernel dataplane starts.
func (p *SplicePair) Activate() error {
	if p == nil || p.backend == nil {
		return E.New("nil pair")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return E.New("pair released")
	}
	if p.activated {
		return nil
	}
	b := p.backend
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || b.runtime == nil {
		return E.New("backend closed")
	}
	leftTCP, _ := p.leftConn.(*net.TCPConn)
	rightTCP, _ := p.rightConn.(*net.TCPConn)
	if leftTCP == nil || rightTCP == nil {
		return E.New("pair missing tcp conns")
	}
	leftFD, err := tcpConnFD(leftTCP)
	if err != nil {
		return err
	}
	rightFD, err := tcpConnFD(rightTCP)
	if err != nil {
		return err
	}
	if err := updateMap(int(b.runtime.sock_map_fd), unsafe.Pointer(&p.leftKey), unsafe.Pointer(&leftFD)); err != nil {
		return E.Cause(err, "sockhash insert left")
	}
	if err := updateMap(int(b.runtime.sock_map_fd), unsafe.Pointer(&p.rightKey), unsafe.Pointer(&rightFD)); err != nil {
		_ = deleteMap(int(b.runtime.sock_map_fd), unsafe.Pointer(&p.leftKey))
		return E.Cause(err, "sockhash insert right")
	}
	p.activated = true
	return nil
}

func (b *SpliceBackend) rollbackPeer(left, right spliceKey) {
	_ = deleteMap(int(b.runtime.peer_map_fd), unsafe.Pointer(&left))
	_ = deleteMap(int(b.runtime.peer_map_fd), unsafe.Pointer(&right))
	_ = deleteMap(int(b.runtime.bytes_map_fd), unsafe.Pointer(&left))
	_ = deleteMap(int(b.runtime.bytes_map_fd), unsafe.Pointer(&right))
}

func (b *SpliceBackend) perCPUBuffer() []uint64 {
	if b.possibleCPUs < 1 {
		return nil
	}
	return make([]uint64, b.possibleCPUs)
}

func (b *SpliceBackend) zeroPerCPUBytes(key spliceKey) error {
	if !b.accounting {
		return nil // C-3: never touch bytes map when accounting is off
	}
	if b.runtime == nil || b.runtime.bytes_map_fd < 0 {
		return E.New("bytes map missing")
	}
	buf := b.perCPUBuffer()
	if len(buf) == 0 {
		return E.New("percpu buffer empty")
	}
	return updateMap(int(b.runtime.bytes_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&buf[0]))
}

func (b *SpliceBackend) sumPerCPUBytes(key spliceKey) (uint64, error) {
	if !b.accounting {
		return 0, E.New("accounting disabled")
	}
	if b.runtime == nil || b.runtime.bytes_map_fd < 0 {
		return 0, E.New("bytes map missing")
	}
	buf := b.perCPUBuffer()
	if len(buf) == 0 {
		return 0, E.New("percpu buffer empty")
	}
	if err := lookupMap(int(b.runtime.bytes_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&buf[0])); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range buf {
		sum += v
	}
	return sum, nil
}

func (p *SplicePair) Release() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.releaseLocked()
}

func (p *SplicePair) releaseLocked() error {
	if p.released {
		return nil
	}
	p.released = true
	b := p.backend
	callback := p.onRelease
	p.onRelease = nil
	if b != nil {
		b.access.Lock()
		if b.pairs != nil {
			delete(b.pairs, p)
		}
		runtime := b.runtime
		b.access.Unlock()
		if runtime != nil {
			_ = deleteMap(int(runtime.sock_map_fd), unsafe.Pointer(&p.leftKey))
			_ = deleteMap(int(runtime.sock_map_fd), unsafe.Pointer(&p.rightKey))
			_ = deleteMap(int(runtime.peer_map_fd), unsafe.Pointer(&p.leftKey))
			_ = deleteMap(int(runtime.peer_map_fd), unsafe.Pointer(&p.rightKey))
			_ = deleteMap(int(runtime.bytes_map_fd), unsafe.Pointer(&p.leftKey))
			_ = deleteMap(int(runtime.bytes_map_fd), unsafe.Pointer(&p.rightKey))
			b.pairsReleased.Add(1)
		}
	}
	// Q5: run onRelease before Close so watchers can EPOLL_CTL_DEL while fds
	// are still valid (DEL after close races with fd reuse).
	if callback != nil {
		callback()
	}
	// Close TCP only after Activate: SOCKMAP owns the dataplane and callers
	// already handed the pair to the watchdog. Pre-Activate abort (E2 FIONREAD
	// gate / fail-open) must leave sockets open for userspace connectionCopy —
	// closing here caused lab RST on every client-first HTTP request.
	// Graceful Close (FIN) only; never SetLinger(0)/RST (A-4).
	if p.activated {
		if p.leftConn != nil {
			_ = p.leftConn.Close()
		}
		if p.rightConn != nil {
			_ = p.rightConn.Close()
		}
	}
	return nil
}

// LeftConn returns the left TCP connection (for close-watch).
func (p *SplicePair) LeftConn() net.Conn {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.leftConn
}

// RightConn returns the right TCP connection (for close-watch).
func (p *SplicePair) RightConn() net.Conn {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rightConn
}

func (p *SplicePair) Bytes() (up, down uint64, err error) {
	if p == nil {
		return 0, 0, E.New("pair closed")
	}
	p.mu.Lock()
	released := p.released
	b := p.backend
	leftKey := p.leftKey
	rightKey := p.rightKey
	p.mu.Unlock()
	if released || b == nil {
		return 0, 0, E.New("pair closed")
	}
	// Hold backend lock so detachLocked cannot free runtime under us.
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed || b.runtime == nil {
		return 0, 0, E.New("pair closed")
	}
	up, err = b.sumPerCPUBytes(leftKey)
	if err != nil {
		return 0, 0, err
	}
	down, err = b.sumPerCPUBytes(rightKey)
	return up, down, err
}

func (b *SpliceBackend) RuntimeStats() (SpliceStats, error) {
	var stats SpliceStats
	if b == nil {
		return stats, E.New("closed")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return stats, E.New("closed")
	}
	stats.ActivePairs = uint64(len(b.pairs))
	stats.PairsCreated = b.pairsCreated.Load()
	stats.PairsReleased = b.pairsReleased.Load()
	// Kernel-only counters (Q10 named indices). On lookup error return zero+err, never half-filled.
	var out SpliceStats
	out.ActivePairs = stats.ActivePairs
	out.PairsCreated = stats.PairsCreated
	out.PairsReleased = stats.PairsReleased
	for _, idx := range []struct {
		i   uint32
		set func(uint64)
	}{
		{spliceStatRedirects, func(v uint64) { out.Redirects = v }},
		{spliceStatRedirectFailures, func(v uint64) { out.RedirectFailures = v }},
		{spliceStatPeerMisses, func(v uint64) { out.PeerMisses = v }},
		{spliceStatPassthrough, func(v uint64) { out.Passthrough = v }},
	} {
		var v uint64
		i := idx.i
		if err := lookupMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&i), unsafe.Pointer(&v)); err != nil {
			return SpliceStats{}, err
		}
		idx.set(v)
	}
	return out, nil
}

// unwrapTCPConn walks Upstream/NetConn with a depth cap (Q7: no heap map).
func unwrapTCPConn(conn net.Conn) (*net.TCPConn, bool) {
	const maxDepth = 16
	for depth := 0; depth < maxDepth && conn != nil; depth++ {
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp, true
		}
		type unwrapper interface{ NetConn() net.Conn }
		if u, ok := conn.(unwrapper); ok {
			if next := u.NetConn(); next != nil && next != conn {
				conn = next
				continue
			}
		}
		type upstreamer interface{ Upstream() any }
		if u, ok := conn.(upstreamer); ok {
			if next, ok := u.Upstream().(net.Conn); ok && next != nil && next != conn {
				conn = next
				continue
			}
		}
		break
	}
	return nil, false
}

func tcpConnFD(conn *net.TCPConn) (uint64, error) {
	var fd int
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = raw.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return 0, err
	}
	return uint64(fd), nil
}

func tcpConnKey(conn *net.TCPConn) (spliceKey, error) {
	var key spliceKey
	key.Protocol = 6
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || la == nil || la.IP == nil {
		return key, E.New("invalid local addr")
	}
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ra == nil || ra.IP == nil {
		return key, E.New("invalid remote addr")
	}
	key.LocalPort = uint16(la.Port)
	key.RemotePort = uint16(ra.Port)
	ip4 := la.IP.To4()
	ip4r := ra.IP.To4()
	if ip4 != nil && ip4r != nil {
		key.Family = addressFamilyIPv4 // AF_INET
		copy(key.LocalAddr[:4], ip4)
		copy(key.RemoteAddr[:4], ip4r)
		return key, nil
	}
	// W2: pure IPv6 both ends (BPF fill_splice_key AF_INET6 branch).
	// Mixed v4/v6 is not a valid TCP pair; refuse and fail-open to userspace.
	if ip4 != nil || ip4r != nil {
		return key, E.New("splice refuses mixed IPv4/IPv6 endpoints")
	}
	lip := la.IP.To16()
	rip := ra.IP.To16()
	if lip == nil || rip == nil {
		return key, E.New("invalid IPv6 splice endpoint")
	}
	key.Family = addressFamilyIPv6 // AF_INET6
	copy(key.LocalAddr[:], lip)
	copy(key.RemoteAddr[:], rip)
	return key, nil
}

// possibleCPUCount parses /sys/devices/system/cpu/possible (e.g. "0-7", "0,2-3").
// Kernel PERCPU map value layout is value_size * num_possible_cpus().
// Framework E1: never guess 1 on failure — that under-sizes the userspace buffer
// and lets the kernel write past the Go heap.
func possibleCPUCount() (int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/possible")
	if err != nil {
		return 0, err
	}
	maxID := -1
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(lo)
			end, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil {
				return 0, E.New("parse cpu possible range: ", part)
			}
			if end > maxID {
				maxID = end
			}
			if start > maxID {
				maxID = start
			}
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			return 0, E.Cause(err, "parse cpu possible id")
		}
		if id > maxID {
			maxID = id
		}
	}
	if maxID < 0 {
		return 0, E.New("empty /sys/devices/system/cpu/possible")
	}
	return maxID + 1, nil
}
