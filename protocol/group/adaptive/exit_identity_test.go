package adaptive

import (
	"strconv"
	"sync/atomic"
	"testing"
)

var exitIdentityTestSequence atomic.Uint64

func uniqueExitIdentityTestGroup(t *testing.T) string {
	t.Helper()
	return t.Name() + "-" + strconv.FormatUint(exitIdentityTestSequence.Add(1), 10)
}

func TestExitIdentityStoreIsProcessLocalKeyedAndCountsOnlyChanges(t *testing.T) {
	groupID := uniqueExitIdentityTestGroup(t)
	store, err := NewExitIdentityStore(groupID)
	if err != nil {
		t.Fatal(err)
	}
	first, valid := tokenizeExitIdentity([]byte("203.0.113.10\n"))
	if !valid {
		t.Fatal("valid public address was rejected")
	}
	second, valid := tokenizeExitIdentity([]byte("2001:4860:4860::8888"))
	if !valid || first == second || first.family != 4 || second.family != 6 {
		t.Fatal("independent public identities did not produce independent keyed tokens")
	}
	handle := NodeHandle{NodeID: NodeID{1}, Slot: 2, Version: 3}
	if changed, accepted := store.Compare(handle, first); changed || !accepted {
		t.Fatalf("first identity did not establish a baseline: changed=%v accepted=%v", changed, accepted)
	}
	if baselines, changes, saturated := store.Stats(); baselines != 0 || changes != 0 || saturated != 0 {
		t.Fatalf("comparison committed identity state: baselines=%d changes=%d saturated=%d", baselines, changes, saturated)
	}
	if !store.Commit(handle, first) {
		t.Fatal("first identity commit failed")
	}
	if changed, accepted := store.Compare(handle, first); changed || !accepted {
		t.Fatalf("stable identity changed: changed=%v accepted=%v", changed, accepted)
	}
	if changed, accepted := store.Compare(handle, second); changed || !accepted {
		t.Fatalf("new address family did not establish an independent baseline: changed=%v accepted=%v", changed, accepted)
	}
	if !store.Commit(handle, second) {
		t.Fatal("changed identity commit failed")
	}
	if changed, accepted := store.Compare(handle, first); changed || !accepted {
		t.Fatal("previously observed rotating identity was counted again")
	}
	if baselines, changes, saturated := store.Stats(); baselines != 1 || changes != 0 || saturated != 0 {
		t.Fatalf("unexpected identity stats: baselines=%d changes=%d saturated=%d", baselines, changes, saturated)
	}
	if ipv4, ipv6, dual := store.FamilyStats(); ipv4 != 1 || ipv6 != 1 || dual != 1 {
		t.Fatalf("unexpected family stats: ipv4=%d ipv6=%d dual=%d", ipv4, ipv6, dual)
	}

	// A reload creates a new wrapper but retains the process-local baseline.
	reloaded, err := NewExitIdentityStore(groupID)
	if err != nil {
		t.Fatal(err)
	}
	if baselines, changes, saturated := reloaded.Stats(); baselines != 1 || changes != 0 || saturated != 0 {
		t.Fatalf("process-local baseline did not survive wrapper reload: baselines=%d changes=%d saturated=%d", baselines, changes, saturated)
	}
}

func TestExitIdentityStoreBoundsRotatingVariants(t *testing.T) {
	store, err := NewExitIdentityStore(uniqueExitIdentityTestGroup(t))
	if err != nil {
		t.Fatal(err)
	}
	handle := NodeHandle{NodeID: NodeID{9}, Slot: 1, Version: 1}
	for index := 0; index < maxExitIdentityVariantsPerNode+2; index++ {
		token := exitIdentityToken{digest: [16]byte{byte(index + 1)}, family: 4}
		changed, accepted := store.Compare(handle, token)
		if !accepted || index > 0 && index < maxExitIdentityVariantsPerNode && !changed {
			t.Fatalf("variant %d comparison failed: changed=%v accepted=%v", index, changed, accepted)
		}
		if !store.Commit(handle, token) {
			t.Fatalf("variant %d commit failed", index)
		}
	}
	baselines, changes, saturated := store.Stats()
	if baselines != 1 || changes != maxExitIdentityVariantsPerNode-1 || saturated != 1 {
		t.Fatalf("variant bound failed: baselines=%d changes=%d saturated=%d", baselines, changes, saturated)
	}
}

func TestExitIdentityClassificationDoesNotExposeIdentity(t *testing.T) {
	target := ProbeTarget{Capability: ProbeCapabilityExitIdentity, Generation: 1}
	raw := ProbeRawResult{TLSHandshakeOK: true, StatusCode: 200, hasIdentityToken: true}
	classification := ClassifyProbeResult(target, raw, target.IssuedAt)
	if classification.Class != ProbeSampleTargetFault { // target lifetime is deliberately invalid here
		t.Fatalf("invalid target was accepted: %+v", classification)
	}
}
