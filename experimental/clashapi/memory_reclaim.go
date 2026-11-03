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
	startedAt       time.Time
	lastReclaim     time.Time
	eligibleSamples int
	reclaimCount    atomic.Uint64
}

type memoryReclaimConfig struct {
	interval, cooldown, minimumAge time.Duration
	minimumIdle, maximumHeapAlloc  uint64
	consecutiveEligible            int
}

func newMemoryReclaimConfig(options *option.MemoryReclaimOptions) (memoryReclaimConfig, bool) {
	if options == nil || !options.Enabled {
		return memoryReclaimConfig{}, false
	}
	config := memoryReclaimConfig{interval: time.Duration(options.CheckInterval), cooldown: time.Duration(options.Cooldown), minimumAge: time.Duration(options.MinimumProcessAge), consecutiveEligible: options.ConsecutiveEligible}
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
	// Reclaim when either condition says that retaining pages is no longer
	// worthwhile. maximumHeapAlloc is a pressure threshold, not an upper
	// bound for allowing a reclaim: the old comparison made a process above
	// the configured maximum permanently ineligible, exactly when it most
	// needed a GC/scavenge pass.
	idlePressure := stats.HeapIdle-stats.HeapReleased >= config.minimumIdle
	heapPressure := config.maximumHeapAlloc > 0 && stats.HeapAlloc >= config.maximumHeapAlloc
	if !idlePressure && !heapPressure {
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
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			if !s.eligible(now, stats, config) {
				continue
			}
			debug.FreeOSMemory()
			s.lastReclaim, s.eligibleSamples = now, 0
			s.reclaimCount.Add(1)
		}
	}
}
