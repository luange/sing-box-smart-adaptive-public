package cachefile

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

func newSelectedTestCache(t *testing.T) *CacheFile {
	t.Helper()
	database, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return &CacheFile{DB: database}
}

func TestSelectedRecordRoundTripAndLegacyShadow(t *testing.T) {
	cache := newSelectedTestCache(t)
	record := adapter.SelectedRecord{Version: 1, DisplayTag: "HK #2", DialIdentity: "dial:b", EndpointIdentity: "endpoint:path"}
	if err := cache.StoreSelectedRecord("smart", record); err != nil {
		t.Fatal(err)
	}
	loaded, ok := cache.LoadSelectedRecord("smart")
	if !ok || loaded != record {
		t.Fatalf("selected record mismatch: loaded=%+v ok=%v want=%+v", loaded, ok, record)
	}
	if got := cache.LoadSelected("smart"); got != record.DisplayTag {
		t.Fatalf("legacy selected shadow=%q want=%q", got, record.DisplayTag)
	}
}

func TestLegacySelectedDoesNotPretendToHaveIdentity(t *testing.T) {
	cache := newSelectedTestCache(t)
	if err := cache.StoreSelected("smart", "HK #2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.LoadSelectedRecord("smart"); ok {
		t.Fatal("legacy selection unexpectedly returned an identity record")
	}
	if got := cache.LoadSelected("smart"); got != "HK #2" {
		t.Fatalf("legacy selection=%q", got)
	}
}

func TestLegacyStoreInvalidatesIdentityRecord(t *testing.T) {
	cache := newSelectedTestCache(t)
	if err := cache.StoreSelectedRecord("smart", adapter.SelectedRecord{Version: 1, DisplayTag: "HK", DialIdentity: "dial:a"}); err != nil {
		t.Fatal(err)
	}
	if err := cache.StoreSelected("smart", "HK #2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.LoadSelectedRecord("smart"); ok {
		t.Fatal("legacy overwrite left a stale identity record")
	}
}
