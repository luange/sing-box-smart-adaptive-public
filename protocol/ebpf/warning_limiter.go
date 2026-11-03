//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"
)

const packetWarningInterval = 10 * time.Second

type warningLimiter struct {
	access     sync.Mutex
	next       time.Time
	suppressed uint64
}

func (l *warningLimiter) allow(now time.Time) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.next = now.Add(packetWarningInterval)
	return true, suppressed
}

type warningLogger interface {
	Warn(args ...any)
}

func (l *warningLimiter) warnError(logger warningLogger, prefix string, err error) {
	allowed, suppressed := l.allow(time.Now())
	if !allowed {
		return
	}
	if suppressed > 0 {
		logger.Warn(prefix, err, " (", suppressed, " similar warnings suppressed)")
		return
	}
	logger.Warn(prefix, err)
}

func (l *warningLimiter) warnValueError(logger warningLogger, prefix string, value any, suffix string, err error) {
	allowed, suppressed := l.allow(time.Now())
	if !allowed {
		return
	}
	if suppressed > 0 {
		logger.Warn(prefix, value, suffix, err, " (", suppressed, " similar warnings suppressed)")
		return
	}
	logger.Warn(prefix, value, suffix, err)
}

func (l *warningLimiter) warnMessage(logger warningLogger, message string) {
	allowed, suppressed := l.allow(time.Now())
	if !allowed {
		return
	}
	if suppressed > 0 {
		logger.Warn(message, " (", suppressed, " similar warnings suppressed)")
		return
	}
	logger.Warn(message)
}

type udpWarningLimiters struct {
	packetInfo          warningLimiter
	originalDestination warningLimiter
	cleanup             warningLimiter
	admission           warningLimiter
}
