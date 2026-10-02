package group

import (
	"hash/fnv"
	"time"
)

// smartPolicyBackend is the small portability boundary between the Smart
// host (provider discovery, EndpointProfile and dialing) and the policy
// kernel.  A backend must own its selection state; the host must not run a
// second confirmation/cooldown state machine for the same decision.
type smartPolicyBackend interface {
	Choose(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) smartPolicyDecision
	Observe(key string, id uint64, success bool, elapsed time.Duration, now time.Time)
	Reset()
	Close()
}

// smartPolicyIncumbent is optional so non-Zig/reference backends and small
// test doubles do not need an extra state-synchronization primitive.
type smartPolicyIncumbent interface {
	SetSelected(key string, id uint64, now time.Time)
}

// smartPolicyAdopter restores a host-confirmed incumbent after a bounded
// policy context is recreated. It must be a no-op when the backend already has
// a selected candidate; otherwise a pending policy challenge could be reset by
// every host ranking call.
type smartPolicyAdopter interface {
	AdoptSelected(key string, id uint64, now time.Time)
}

// smartPolicyPruner lets a provider refresh remove policy state for endpoints
// that no longer exist. The catalog is shared by all contexts, so one bounded
// ID set is enough; the Zig backend applies it to every retained context.
type smartPolicyPruner interface {
	Prune(ids []uint64)
}

type smartPolicyCandidate struct {
	ID             uint64
	Reliability    float64
	ConnectMS      float64
	FirstByteMS    float64
	JitterMS       float64
	Throughput     float64
	Samples        float64
	Weight         float64
	CandidateOrder float64
	State          uint8
	Eligible       bool
}

type smartPolicyDecision struct {
	SelectedID uint64
	Score      float64
	Switched   bool
	Reason     uint8
}

// smartPolicyID is derived from the canonical Endpoint identity, not the
// provider display tag.  Numeric suffixes added to duplicate subscription
// lines therefore share one policy profile and cannot cause oscillation.
func smartPolicyID(identity string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("sing-box/smart-policy/v1\x00"))
	_, _ = h.Write([]byte(identity))
	id := h.Sum64()
	if id == 0 {
		return 1
	}
	return id
}

func smartPolicyState(state string) uint8 {
	switch state {
	case "healthy":
		return 1
	case "warming":
		return 2
	case "suspect":
		return 3
	case "open":
		return 4
	case "half_open":
		// Keep the historical values stable: state 4 has always meant open.
		// Half-open is additive so older C/FFI consumers continue to decode
		// state 3 as suspect instead of silently changing its meaning.
		return 5
	default:
		return 0
	}
}
