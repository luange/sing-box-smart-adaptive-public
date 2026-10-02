//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"sync"
	"syscall"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"golang.org/x/sys/unix"
)

// spliceWatcher is a backend-level close/idle monitor (Q5 step2–3):
// one epoll fd + one goroutine instead of per-pair epoll/goroutines.
// Fail-open: if create fails, callers fall back to per-pair watchSplicePair.
type spliceWatcher struct {
	logger interface {
		Info(args ...any)
		Warn(args ...any)
	}
	accounting bool
	idle       time.Duration

	access sync.Mutex
	epfd   int
	// fd → pair (both ends registered). EPOLL_CTL_DEL before socket close.
	byFD   map[int32]*ECommon.SplicePair
	pairs  map[*ECommon.SplicePair]*watchPairState
	stop   chan struct{}
	done   chan struct{}
	closed bool
}

type watchPairState struct {
	leftFD, rightFD  int32
	lastUp, lastDown uint64
	stale            int
}

func newSpliceWatcher(
	logger interface {
		Info(args ...any)
		Warn(args ...any)
	},
	accounting bool,
	idle time.Duration,
) (*spliceWatcher, error) {
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	w := &spliceWatcher{
		logger:     logger,
		accounting: accounting,
		idle:       idle,
		epfd:       epfd,
		byFD:       make(map[int32]*ECommon.SplicePair),
		pairs:      make(map[*ECommon.SplicePair]*watchPairState),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

// Add registers both ends after Activate. Safe if pair already released.
func (w *spliceWatcher) Add(pair *ECommon.SplicePair) bool {
	if w == nil || pair == nil {
		return false
	}
	left, _ := pair.LeftConn().(*net.TCPConn)
	right, _ := pair.RightConn().(*net.TCPConn)
	if left == nil || right == nil {
		return false
	}
	lfd, err := tcpFD(left)
	if err != nil {
		return false
	}
	rfd, err := tcpFD(right)
	if err != nil {
		return false
	}

	w.access.Lock()
	defer w.access.Unlock()
	if w.closed {
		return false
	}
	ev := &unix.EpollEvent{Events: unix.EPOLLRDHUP | unix.EPOLLHUP | unix.EPOLLERR}
	ev.Fd = lfd
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, int(lfd), ev); err != nil {
		return false
	}
	ev.Fd = rfd
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, int(rfd), ev); err != nil {
		_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, int(lfd), nil)
		return false
	}
	w.byFD[lfd] = pair
	w.byFD[rfd] = pair
	w.pairs[pair] = &watchPairState{leftFD: lfd, rightFD: rfd}
	return true
}

// Remove drops epoll interest. Must run before sockets are closed (Release).
func (w *spliceWatcher) Remove(pair *ECommon.SplicePair) {
	if w == nil || pair == nil {
		return
	}
	w.access.Lock()
	defer w.access.Unlock()
	w.removeLocked(pair)
}

func (w *spliceWatcher) removeLocked(pair *ECommon.SplicePair) {
	st, ok := w.pairs[pair]
	if !ok {
		return
	}
	delete(w.pairs, pair)
	if st.leftFD != 0 {
		_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, int(st.leftFD), nil)
		delete(w.byFD, st.leftFD)
	}
	if st.rightFD != 0 {
		_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, int(st.rightFD), nil)
		delete(w.byFD, st.rightFD)
	}
}

func (w *spliceWatcher) Close() {
	if w == nil {
		return
	}
	w.access.Lock()
	if w.closed {
		w.access.Unlock()
		return
	}
	w.closed = true
	close(w.stop)
	epfd := w.epfd
	w.access.Unlock()
	// Wake EpollWait by closing epfd after stop is signaled.
	if epfd >= 0 {
		_ = unix.Close(epfd)
	}
	<-w.done
}

func (w *spliceWatcher) loop() {
	defer close(w.done)
	interval := w.idle / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > w.idle {
		interval = w.idle
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	events := make([]unix.EpollEvent, 64)
	for {
		// Timed wait (E-3): never EpollWait(-1).
		n, err := unix.EpollWait(w.epfd, events, 500)
		select {
		case <-w.stop:
			return
		default:
		}
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// epfd closed on shutdown
			select {
			case <-w.stop:
				return
			default:
				if w.logger != nil {
					w.logger.Warn("eBPF splice watcher epoll: ", err)
				}
				// keep idle path until stop
				n = 0
			}
		}
		var toRelease []*ECommon.SplicePair
		if n > 0 {
			w.access.Lock()
			seen := make(map[*ECommon.SplicePair]struct{}, n)
			for i := 0; i < n; i++ {
				pair := w.byFD[events[i].Fd]
				if pair == nil {
					continue
				}
				if _, ok := seen[pair]; ok {
					continue
				}
				seen[pair] = struct{}{}
				w.removeLocked(pair)
				toRelease = append(toRelease, pair)
			}
			w.access.Unlock()
		}
		for _, pair := range toRelease {
			_ = pair.Release()
		}

		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.sweepIdle()
		default:
		}
	}
}

func (w *spliceWatcher) sweepIdle() {
	// Snapshot under lock, process without holding lock (no long hold on BeginPair path).
	type snap struct {
		pair *ECommon.SplicePair
		st   *watchPairState
	}
	w.access.Lock()
	list := make([]snap, 0, len(w.pairs))
	for p, st := range w.pairs {
		list = append(list, snap{pair: p, st: st})
	}
	w.access.Unlock()

	var dead []*ECommon.SplicePair
	for _, s := range list {
		if !w.accounting {
			if !splicePairAlive(s.pair) {
				dead = append(dead, s.pair)
			}
			continue
		}
		// Bytes() is a syscall snapshot; only the st bookkeeping needs the
		// lock — removeLocked reads the same fields concurrently.
		up, down, err := s.pair.Bytes()
		if err != nil {
			dead = append(dead, s.pair)
			continue
		}
		w.access.Lock()
		if _, ok := w.pairs[s.pair]; !ok {
			// Removed (and likely released) while we were sampling.
			w.access.Unlock()
			continue
		}
		if up == s.st.lastUp && down == s.st.lastDown {
			s.st.stale++
			if s.st.stale >= 2 {
				dead = append(dead, s.pair)
			}
		} else {
			s.st.stale = 0
			s.st.lastUp, s.st.lastDown = up, down
		}
		w.access.Unlock()
	}
	if len(dead) == 0 {
		return
	}
	w.access.Lock()
	for _, p := range dead {
		w.removeLocked(p)
	}
	w.access.Unlock()
	for _, p := range dead {
		_ = p.Release()
	}
}

func tcpFD(conn *net.TCPConn) (int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	var ctrlErr error
	err = raw.Control(func(sysfd uintptr) {
		fd = int(sysfd)
	})
	if err != nil {
		return 0, err
	}
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	return int32(fd), nil
}
