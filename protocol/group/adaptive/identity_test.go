package adaptive

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testOutbound struct {
	outbound.Adapter
}

func TestSessionKeyStringIsOpaqueAndBounded(t *testing.T) {
	key := SessionKey{1, 2, 3, 4, 5, 6, 7, 8, 9}
	if got := key.String(); got != "0102030405060708" || len(got) != 16 {
		t.Fatalf("unexpected opaque session ID: %q", got)
	}
}

func TestCatalogScalesAndDeduplicatesFiveHundredNodes(t *testing.T) {
	hasher := testIdentityHasher(t)
	roots := make([]A48SourceRoot, 0, 1000)
	manager := make(map[string]*testOutbound, 1000)
	for index := 0; index < 500; index++ {
		outboundOptions := option.Outbound{Type: "test", Options: struct {
			Server string `json:"server"`
		}{Server: "node-" + strconv.Itoa(index) + ".example"}}
		for duplicate := 0; duplicate < 2; duplicate++ {
			tag := "node-" + strconv.Itoa(index) + "-" + strconv.Itoa(duplicate)
			candidate := newTestOutbound(tag)
			manager[tag] = candidate
			optionsCopy := outboundOptions
			roots = append(roots, A48SourceRoot{Outbound: candidate, Options: &optionsCopy, Source: "provider"})
		}
	}
	sourceAdapter := NewA48SourceAdapterV1(1, hasher, roots, func(tag string) (candidate adapter.Outbound, loaded bool) {
		candidate, loaded = manager[tag]
		return
	})
	source, err := sourceAdapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newCatalogTestPublisher().publish(NewCatalogPort(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Candidates) != 500 || snapshot.DuplicatesSuppressed != 500 {
		t.Fatalf("unexpected 500-node catalog: candidates=%d suppressed=%d", len(snapshot.Candidates), snapshot.DuplicatesSuppressed)
	}
}

func TestIdentityKeyIsNotWrittenUntilPublished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive.key")
	prepared, isNew, err := loadOrPrepareIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("missing key was not prepared as new")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("identity key was written during prepare: %v", err)
	}
	if err = persistIdentityKey(path, prepared[:]); err != nil {
		t.Fatal(err)
	}
	restored, isNew, err := loadOrPrepareIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if isNew || restored != prepared {
		t.Fatal("published identity key did not survive restart")
	}
}

func newTestOutbound(tag string) *testOutbound {
	return &testOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
}

func (*testOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (*testOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func testIdentityHasher(t *testing.T) *IdentityHasher {
	t.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	hasher, err := NewIdentityHasher(key)
	if err != nil {
		t.Fatal(err)
	}
	return hasher
}

func TestNodeIDIgnoresDisplayTag(t *testing.T) {
	hasher := testIdentityHasher(t)
	first := option.Outbound{Type: "test", Tag: "node", Options: struct {
		Server   string `json:"server"`
		Password string `json:"password"`
	}{Server: "example.com", Password: "secret"}}
	second := first
	second.Tag = "node (2)"
	firstID, err := hasher.FromCanonicalOptions(first.Type, first.Options)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := hasher.FromCanonicalOptions(second.Type, second.Options)
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID {
		t.Fatal("display tag changed physical NodeID")
	}
}

func TestEndpointIDIsStableAcrossCredentialChanges(t *testing.T) {
	hasher := testIdentityHasher(t)
	first := struct {
		Server   string `json:"server"`
		Port     int    `json:"server_port"`
		Password string `json:"password"`
	}{"edge.example.com", 443, "credential-a"}
	second := first
	second.Password = "credential-b"
	third := first
	third.Server = "other.example.com"
	nodeA, err := hasher.FromCanonicalOptions("trojan", first)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := hasher.FromCanonicalOptions("trojan", second)
	if err != nil {
		t.Fatal(err)
	}
	endpointA, err := hasher.FromEndpointOptions("trojan", first)
	if err != nil {
		t.Fatal(err)
	}
	endpointB, err := hasher.FromEndpointOptions("trojan", second)
	if err != nil {
		t.Fatal(err)
	}
	endpointC, err := hasher.FromEndpointOptions("trojan", third)
	if err != nil {
		t.Fatal(err)
	}
	if nodeA == nodeB {
		t.Fatal("credential changes must retain independent NodeIDs")
	}
	if endpointA != endpointB {
		t.Fatal("credential changes must share an EndpointID")
	}
	if endpointA == endpointC {
		t.Fatal("different servers must not share an EndpointID")
	}
}

func TestEndpointFingerprintStripsNestedCredentialFields(t *testing.T) {
	hasher := testIdentityHasher(t)
	base := map[string]any{
		"server": "edge.example.com",
		"tls":    map[string]any{"server_name": "edge.example.com", "headers": map[string]any{"authorization": "a"}},
	}
	changed := map[string]any{
		"server": "edge.example.com",
		"tls":    map[string]any{"server_name": "edge.example.com", "headers": map[string]any{"authorization": "b"}},
	}
	first, err := hasher.FromEndpointOptions("trojan", base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hasher.FromEndpointOptions("trojan", changed)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("nested credential fields changed endpoint fingerprint")
	}
}

func TestCatalogSuppressesPhysicalDuplicates(t *testing.T) {
	hasher := testIdentityHasher(t)
	first := newTestOutbound("provider/node")
	second := newTestOutbound("provider/node (2)")
	options := option.Outbound{Type: "test", Options: struct {
		Server string `json:"server"`
	}{Server: "example.com"}}
	manager := map[string]*testOutbound{first.Tag(): first, second.Tag(): second}
	sourceAdapter := NewA48SourceAdapterV1(1, hasher, []A48SourceRoot{{Outbound: first, Options: &options, Source: "provider"}, {Outbound: second, Options: &options, Source: "provider"}}, func(tag string) (candidate adapter.Outbound, loaded bool) {
		candidate, loaded = manager[tag]
		return
	})
	source, err := sourceAdapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newCatalogTestPublisher().publish(NewCatalogPort(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Candidates) != 1 || snapshot.DuplicatesSuppressed != 1 {
		t.Fatalf("duplicate was not suppressed: candidates=%d suppressed=%d", len(snapshot.Candidates), snapshot.DuplicatesSuppressed)
	}
	if len(snapshot.Candidates[0].Aliases) != 2 {
		t.Fatalf("duplicate aliases were not retained: %v", snapshot.Candidates[0].Aliases)
	}
}

func TestSourceAdapterMarksCredentialConflictsWithoutMerging(t *testing.T) {
	hasher := testIdentityHasher(t)
	first := newTestOutbound("provider/edge-a")
	second := newTestOutbound("provider/edge-b")
	firstOptions := option.Outbound{Type: "trojan", Options: struct {
		Server   string `json:"server"`
		Password string `json:"password"`
	}{"edge.example.com", "credential-a"}}
	secondOptions := option.Outbound{Type: "trojan", Options: struct {
		Server   string `json:"server"`
		Password string `json:"password"`
	}{"edge.example.com", "credential-b"}}
	manager := map[string]*testOutbound{first.Tag(): first, second.Tag(): second}
	source, err := NewA48SourceAdapterV1(1, hasher, []A48SourceRoot{
		{Outbound: first, Options: &firstOptions, Source: "provider"},
		{Outbound: second, Options: &secondOptions, Source: "provider"},
	}, func(tag string) (adapter.Outbound, bool) { candidate, loaded := manager[tag]; return candidate, loaded }).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(source.Nodes) != 2 || source.DuplicatesSuppressed != 0 {
		t.Fatalf("credential variants were merged: nodes=%d suppressed=%d", len(source.Nodes), source.DuplicatesSuppressed)
	}
	if source.Nodes[0].EndpointID != source.Nodes[1].EndpointID || source.Nodes[0].EndpointConflictCount != 2 || source.Nodes[1].EndpointConflictCount != 2 {
		t.Fatalf("endpoint conflict was not isolated: %+v", source.Nodes)
	}
	if source.Nodes[0].Metadata["endpoint_conflict"] != "true" || source.Nodes[1].Metadata["endpoint_conflict"] != "true" {
		t.Fatal("endpoint conflict metadata missing")
	}
}
