package clashapi

import (
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestMemoryReclaimDefaultsAndDisabled(t *testing.T) {
	_, enabled := newMemoryReclaimConfig(nil)
	require.False(t, enabled)
	config, enabled := newMemoryReclaimConfig(&option.MemoryReclaimOptions{Enabled: true})
	require.True(t, enabled)
	require.Equal(t, defaultReclaimCheckInterval, config.interval)
	require.Equal(t, defaultReclaimCooldown, config.cooldown)
	require.Equal(t, uint64(defaultReclaimMinimumIdle), config.minimumIdle)
	require.Equal(t, 2, config.consecutiveEligible)
}

func TestMemoryReclaimEligibility(t *testing.T) {
	now := time.Now()
	config := memoryReclaimConfig{
		minimumAge:          time.Minute,
		cooldown:            5 * time.Minute,
		minimumIdle:         32 << 20,
		maximumHeapAlloc:    128 << 20,
		consecutiveEligible: 2,
	}
	state := &memoryReclaimState{startedAt: now.Add(-2 * time.Minute)}
	stats := runtime.MemStats{HeapAlloc: 64 << 20, HeapIdle: 64 << 20, HeapReleased: 16 << 20}
	require.False(t, state.eligible(now, stats, config))
	require.True(t, state.eligible(now.Add(time.Second), stats, config))

	state.lastReclaim = now
	require.False(t, state.eligible(now.Add(time.Minute), stats, config))
	stats.HeapAlloc = 256 << 20
	require.False(t, state.eligible(now.Add(6*time.Minute), stats, config))
	stats.HeapAlloc = 64 << 20
	stats.HeapReleased = 48 << 20
	require.False(t, state.eligible(now.Add(6*time.Minute), stats, config))
}
