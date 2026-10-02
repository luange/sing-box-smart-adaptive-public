package clashapi

import (
	"context"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

const (
	defaultReclaimCheckInterval = time.Minute
	defaultReclaimCooldown      = 5 * time.Minute
	defaultReclaimMinimumAge    = 5 * time.Minute
	defaultReclaimMinimumIdle   = 32 << 20
)

type memoryReclaimState struct {
	startedAt        time.Time
	lastReclaim      time.Time
	eligibleSamples  int
	reclaimCount     atomic.Uint64
	lastReclaimUnix  atomic.Int64
	lastReleasedByte atomic.Uint64
}

type memoryReclaimConfig struct {
	interval            time.Duration
	cooldown            time.Duration
	minimumAge          time.Duration
	minimumIdle         uint64
	maximumHeapAlloc    uint64
	consecutiveEligible int
}

func newMemoryReclaimConfig(options *option.MemoryReclaimOptions) (memoryReclaimConfig, bool) {
	if options == nil || !options.Enabled {
		return memoryReclaimConfig{}, false
	}
	config := memoryReclaimConfig{
		interval:            time.Duration(options.CheckInterval),
		cooldown:            time.Duration(options.Cooldown),
		minimumAge:          time.Duration(options.MinimumProcessAge),
		consecutiveEligible: options.ConsecutiveEligible,
	}
	if options.MinimumIdle != nil {
		config.minimumIdle = options.MinimumIdle.Value()
	}
	if options.MaximumHeapAlloc != nil {
		config.maximumHeapAlloc = options.MaximumHeapAlloc.Value()
	}
	if config.interval <= 0 {
		config.interval = defaultReclaimCheckInterval
	}
	if config.cooldown <= 0 {
		config.cooldown = defaultReclaimCooldown
	}
	if config.minimumAge <= 0 {
		config.minimumAge = defaultReclaimMinimumAge
	}
	if config.minimumIdle == 0 {
		config.minimumIdle = defaultReclaimMinimumIdle
	}
	if config.consecutiveEligible <= 0 {
		config.consecutiveEligible = 2
	}
	return config, true
}

func (s *memoryReclaimState) eligible(now time.Time, stats runtime.MemStats, config memoryReclaimConfig) bool {
	if now.Sub(s.startedAt) < config.minimumAge || (!s.lastReclaim.IsZero() && now.Sub(s.lastReclaim) < config.cooldown) {
		s.eligibleSamples = 0
		return false
	}
	idleUnreleased := stats.HeapIdle - stats.HeapReleased
	if idleUnreleased < config.minimumIdle || (config.maximumHeapAlloc > 0 && stats.HeapAlloc > config.maximumHeapAlloc) {
		s.eligibleSamples = 0
		return false
	}
	s.eligibleSamples++
	return s.eligibleSamples >= config.consecutiveEligible
}

func (s *memoryReclaimState) run(ctx context.Context, config memoryReclaimConfig) {
	ticker := time.NewTicker(config.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			if !s.eligible(now, before, config) {
				continue
			}
			debug.FreeOSMemory()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			released := uint64(0)
			if after.HeapReleased > before.HeapReleased {
				released = after.HeapReleased - before.HeapReleased
			}
			s.lastReclaim = now
			s.eligibleSamples = 0
			s.reclaimCount.Add(1)
			s.lastReclaimUnix.Store(now.Unix())
			s.lastReleasedByte.Store(released)
		}
	}
}
