package adaptive

import (
	"encoding/binary"
	"hash/fnv"
	"time"
)

// policyKernel is the host-neutral decision boundary. HealthStore, provider
// refresh, dialing, and leases remain host-owned; the kernel receives a
// bounded snapshot and returns only the preferred node identity/reason.
type policyKernel interface {
	Configure(margin float64, cooldown time.Duration, manualFailure string)
	Choose(key string, candidates []policyKernelCandidate, mode PolicyMode, now time.Time) policyKernelDecision
	SetBulkSequence(key string, sequence uint64)
	Remember(key string, id NodeID, now time.Time, cooldown time.Duration)
	Forget(key string)
	Reset()
	Close()
}

type policyKernelCandidate struct {
	ID                uint64
	SortKeyHi         uint64
	SortKeyLo         uint64
	HealthPriority    int
	WeightedDelayMS   float64
	ThroughputBPS     float64
	ThroughputSamples float64
	Supported         bool
	Eligible          bool
	Pinned            bool
	Leased            bool
}

func kernelCandidateSortKey(id NodeID) (uint64, uint64) {
	return binary.BigEndian.Uint64(id[:8]), binary.BigEndian.Uint64(id[8:])
}

type policyKernelDecision struct {
	SelectedID uint64
	Switched   bool
	Reason     uint8
}

func kernelCandidateID(id NodeID) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("sing-box/adaptive-policy/v1\x00"))
	_, _ = h.Write(id[:])
	value := h.Sum64()
	if value == 0 {
		return 1
	}
	return value
}

func policyKernelMode(mode PolicyMode) uint8 {
	switch mode {
	case ModeStrictAffinity:
		return 0
	case ModeLatency:
		return 2
	case ModeBulk:
		return 3
	case ModeManual:
		return 4
	default:
		return 1
	}
}

func kernelDecisionReason(reason uint8) DecisionReason {
	switch reason {
	case 1:
		return ReasonStickyMargin
	case 8:
		return ReasonSwitchCooldown
	case 2:
		return ReasonLease
	case 3:
		return ReasonManualPin
	case 4:
		return ReasonWarmingFallback
	case 6:
		return ReasonBulkSpread
	case 7:
		return ReasonBulkThroughput
	default:
		return ReasonRanked
	}
}
