package cachefile

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
)

func TestFakeIPResetIsIdempotentWithoutBuckets(t *testing.T) {
	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cache := &CacheFile{DB: database}
	if err = cache.FakeIPReset(); err != nil {
		t.Fatalf("first empty reset failed: %v", err)
	}
	if err = cache.FakeIPReset(); err != nil {
		t.Fatalf("second empty reset failed: %v", err)
	}
}
