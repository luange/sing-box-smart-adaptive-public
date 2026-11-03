//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

type benchmarkWarningLogger struct {
	calls uint64
}

func (l *benchmarkWarningLogger) Warn(...any) {
	l.calls++
}

func TestWarningLimiter(t *testing.T) {
	var limiter warningLimiter
	now := time.Unix(100, 0)
	allowed, suppressed := limiter.allow(now)
	if !allowed || suppressed != 0 {
		t.Fatalf("unexpected first result: allowed=%v suppressed=%d", allowed, suppressed)
	}
	for range 3 {
		allowed, suppressed = limiter.allow(now.Add(time.Second))
		if allowed || suppressed != 0 {
			t.Fatalf("unexpected limited result: allowed=%v suppressed=%d", allowed, suppressed)
		}
	}
	allowed, suppressed = limiter.allow(now.Add(packetWarningInterval))
	if !allowed || suppressed != 3 {
		t.Fatalf("unexpected resumed result: allowed=%v suppressed=%d", allowed, suppressed)
	}
}

func BenchmarkWarningLimiterSuppressed(b *testing.B) {
	var limiter warningLimiter
	logger := new(benchmarkWarningLogger)
	limiter.next = time.Now().Add(time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		limiter.warnError(logger, "repeated packet warning: ", errBenchmarkWarning)
	}
}

var errBenchmarkWarning = benchmarkWarningError{}

type benchmarkWarningError struct{}

func (benchmarkWarningError) Error() string { return "warning" }

func BenchmarkWarningLoggerUnbounded(b *testing.B) {
	logger := new(benchmarkWarningLogger)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		logger.Warn("repeated packet warning")
	}
}
