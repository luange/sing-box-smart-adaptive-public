package adaptive

import "testing"

func TestCatalogBindingStatsTrackCommitAndRetirement(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	first, err := publisher.publish(port, portSource(1, portNode(NodeID{7}, "first")))
	if err != nil {
		t.Fatal(err)
	}
	stats := port.BindingStats()
	if stats.Active != 1 || stats.Retired != 0 {
		t.Fatalf("unexpected initial binding stats: %+v", stats)
	}
	if _, err = publisher.publish(port, portSource(2, portNode(NodeID{8}, "second"))); err != nil {
		t.Fatal(err)
	}
	stats = port.BindingStats()
	if stats.Active != 1 || stats.Retired != 1 {
		t.Fatalf("replacement did not retire old binding: %+v", stats)
	}
	port.RollbackEpoch(first.RuntimeEpochID + 1)
	stats = port.BindingStats()
	if stats.Active != 1 || stats.Retired != 1 {
		t.Fatalf("unrelated rollback changed binding stats: %+v", stats)
	}
	port.RollbackEpoch(port.Snapshot().RuntimeEpochID)
	stats = port.BindingStats()
	if stats.Active != 0 || stats.Retired != 2 {
		t.Fatalf("matching rollback did not retire active binding: %+v", stats)
	}
}
