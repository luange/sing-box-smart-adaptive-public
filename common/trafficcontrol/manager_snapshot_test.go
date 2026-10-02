package trafficcontrol

import (
	"sync/atomic"
	"testing"

	"github.com/gofrs/uuid/v5"
)

type snapshotTestTracker struct {
	metadata *TrackerMetadata
}

func (t *snapshotTestTracker) Metadata() *TrackerMetadata { return t.metadata }
func (t *snapshotTestTracker) Close() error               { return nil }

func TestConnectionsReturnsOwnedRouteSnapshot(t *testing.T) {
	id, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	metadata := &TrackerMetadata{
		ID:       id,
		Chain:    []string{"airport/node", "JP"},
		Upload:   new(atomic.Int64),
		Download: new(atomic.Int64),
	}
	manager := NewManager(nil)
	manager.connections.Store(id, &snapshotTestTracker{metadata: metadata})

	snapshots := manager.Connections()
	if len(snapshots) != 1 {
		t.Fatalf("snapshot count=%d, want 1", len(snapshots))
	}
	if got, want := snapshots[0].Chain[0], "airport/node"; got != want {
		t.Fatalf("snapshot chain=%v, want %q first", snapshots[0].Chain, want)
	}

	metadata.Chain[0] = "changed-live-metadata"
	if got, want := snapshots[0].Chain[0], "airport/node"; got != want {
		t.Fatalf("snapshot shares live chain backing array: got %q, want %q", got, want)
	}
	snapshots[0].Chain[1] = "changed-snapshot"
	if got, want := metadata.Chain[1], "JP"; got != want {
		t.Fatalf("snapshot mutation changed live chain: got %q, want %q", got, want)
	}
	if snapshots[0].Upload != metadata.Upload || snapshots[0].Download != metadata.Download {
		t.Fatal("counter pointers must remain shared for live totals")
	}
}
