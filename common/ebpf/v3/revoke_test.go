package v3

import (
	"net/netip"
	"testing"
)

// The shared-IP generalisation guard: a learn-promoted /32 DIRECT must be
// revocable when later DNS evidence marks the same address proxy-routed,
// while snapshot-published bypass rules stay protected from accidental
// removal.
func TestMemoryBackendRevokeMergedStaticDirect(t *testing.T) {
	b := NewMemoryBackend()

	// Snapshot: one permanent bypass prefix, committed as bank 1.
	snapshot := []CompiledPolicy{{
		Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 5}), 32),
		Value: PolicyValue{
			Verdict:    uint8(VerdictDirect),
			Source:     uint8(SourceStatic),
			Confidence: ConfidenceStrong,
			ReasonCode: uint16(ReasonStaticDirect),
		},
	}}
	if err := b.PublishStatic(snapshot); err != nil {
		t.Fatal(err)
	}

	// Learn-promote of a different address (dns_prefill path).
	promoted := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32)
	if err := b.MergeStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if got := b.LookupDynamicDirect(promoted.Addr(), ProtocolTCP, 443); got == nil {
		t.Fatal("promoted /32 missing from dynamic map")
	}

	// Shared-IP conflict: revoke the promoted prefix only.
	if err := b.DeleteMergedStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if got := b.LookupDynamicDirect(promoted.Addr(), ProtocolTCP, 443); got != nil {
		t.Fatal("revoked /32 still in active bank")
	}

	// Snapshot-published rule must survive an accidental revoke request.
	if err := b.DeleteMergedStaticDirect(snapshot[0].Prefix); err != nil {
		t.Fatal(err)
	}
	if got := b.LookupStatic(snapshot[0].Prefix.Addr(), ProtocolTCP, 443); got == nil {
		t.Fatal("snapshot-published bypass rule was removed by revoke")
	}

	// A full publish rebuild clears the revocable set for the new bank.
	if err := b.MergeStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if err := b.PublishStatic(nil); err != nil {
		t.Fatal(err)
	}
	if len(b.dynamicDirects4) != 0 || len(b.dynamicDirects6) != 0 {
		t.Fatal("merged set not cleared after snapshot publish")
	}
}
