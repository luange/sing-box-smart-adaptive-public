package adaptive

import "testing"

func TestSourceDeltaRoundTripPreservesOrderAndBindings(t *testing.T) {
	firstID, secondID, thirdID := NodeID{1}, NodeID{2}, NodeID{3}
	firstPort := newTestOutbound("first")
	secondPort := newTestOutbound("second")
	thirdPort := newTestOutbound("third")
	previous := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 4, InputLeafCount: 2, Nodes: []CanonicalNode{
		{NodeID: firstID, SourceKey: "first", Aliases: []string{"first"}, IdentityStable: true},
		{NodeID: secondID, SourceKey: "second", Aliases: []string{"second"}, IdentityStable: true},
	}}, Bindings: map[NodeID]ExecutionPort{firstID: firstPort, secondID: secondPort}}
	current := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 5, InputLeafCount: 2, Nodes: []CanonicalNode{
		{NodeID: secondID, SourceKey: "second-new", Aliases: []string{"second-new"}, IdentityStable: true},
		{NodeID: thirdID, SourceKey: "third", Aliases: []string{"third"}, IdentityStable: true},
	}}, Bindings: map[NodeID]ExecutionPort{secondID: secondPort, thirdID: thirdPort}}
	delta, err := DiffSourcePublication(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Upserts) != 2 || len(delta.Removes) != 1 || delta.Removes[0] != firstID {
		t.Fatalf("unexpected delta: upserts=%d removes=%v", len(delta.Upserts), delta.Removes)
	}
	applied, err := ApplySourceDelta(previous, delta)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Generation != current.Generation || len(applied.Nodes) != 2 || applied.Nodes[0].NodeID != secondID || applied.Nodes[1].NodeID != thirdID || applied.Bindings[thirdID] != thirdPort {
		t.Fatalf("delta application mismatch: %#v", applied.SourceSnapshot)
	}
}

func TestSourceDeltaRejectsRollbackAndMissingBinding(t *testing.T) {
	previous := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 2, Nodes: []CanonicalNode{{NodeID: NodeID{1}, SourceKey: "one"}}}, Bindings: map[NodeID]ExecutionPort{NodeID{1}: newTestOutbound("one")}}
	if _, err := ApplySourceDelta(previous, SourceDeltaPublication{SourceDelta: SourceDelta{Generation: 2}}); err == nil {
		t.Fatal("accepted rollback generation")
	}
	if _, err := ApplySourceDelta(previous, SourceDeltaPublication{SourceDelta: SourceDelta{Generation: 3, Upserts: []CanonicalNode{{NodeID: NodeID{2}, SourceKey: "two"}}}}); err == nil {
		t.Fatal("accepted upsert without execution binding")
	}
}
