package clashapi

import (
	"runtime"
	"testing"
	"time"
)

func TestMemoryReclaimEligibility(t *testing.T) {
	now := time.Now()
	config := memoryReclaimConfig{
		minimumAge:          time.Minute,
		cooldown:            time.Minute,
		minimumIdle:         32 << 20,
		maximumHeapAlloc:    96 << 20,
		consecutiveEligible: 1,
	}

	t.Run("idle pages trigger reclaim", func(t *testing.T) {
		state := memoryReclaimState{startedAt: now.Add(-2 * time.Minute)}
		if !state.eligible(now, runtime.MemStats{HeapIdle: 64 << 20}, config) {
			t.Fatal("idle pages should make reclaim eligible")
		}
	})

	t.Run("heap pressure triggers reclaim even without idle threshold", func(t *testing.T) {
		state := memoryReclaimState{startedAt: now.Add(-2 * time.Minute)}
		if !state.eligible(now, runtime.MemStats{HeapAlloc: 96 << 20}, config) {
			t.Fatal("maximum heap allocation should make reclaim eligible")
		}
	})

	t.Run("below both thresholds does not trigger reclaim", func(t *testing.T) {
		state := memoryReclaimState{startedAt: now.Add(-2 * time.Minute)}
		if state.eligible(now, runtime.MemStats{HeapAlloc: 95 << 20, HeapIdle: 31 << 20}, config) {
			t.Fatal("below both thresholds must remain ineligible")
		}
	})
}
