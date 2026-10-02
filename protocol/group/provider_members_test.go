package group

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	blist "github.com/sagernet/sing/common/x/list"
)

type fakeProvider struct {
	tag              string
	typeName         string
	nodes            []adapter.Outbound
	notifyOnRegister bool
	callbacks        blist.List[adapter.ProviderUpdateCallback]
	outboundsCalls   int
}

func (p *fakeProvider) Type() string {
	if p.typeName != "" {
		return p.typeName
	}
	return "provider"
}
func (p *fakeProvider) Tag() string { return p.tag }
func (p *fakeProvider) Outbounds() []adapter.Outbound {
	p.outboundsCalls++
	return p.nodes
}
func (p *fakeProvider) Outbound(tag string) (adapter.Outbound, bool) {
	for _, node := range p.nodes {
		if node.Tag() == tag {
			return node, true
		}
	}
	return nil, false
}
func (p *fakeProvider) UpdatedAt() time.Time { return time.Now() }
func (p *fakeProvider) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	return nil, nil
}
func (p *fakeProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *blist.Element[adapter.ProviderUpdateCallback] {
	element := p.callbacks.PushBack(callback)
	if p.notifyOnRegister {
		_ = callback(p.tag)
	}
	return element
}
func (p *fakeProvider) UnregisterCallback(element *blist.Element[adapter.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}

type fakeProviderManager struct {
	providers []adapter.Provider
	callbacks blist.List[adapter.ProviderManagerUpdateCallback]
}

func (m *fakeProviderManager) Providers() []adapter.Provider        { return m.providers }
func (m *fakeProviderManager) Remove(tag string) error              { return nil }
func (m *fakeProviderManager) Start(stage adapter.StartStage) error { return nil }
func (m *fakeProviderManager) PostStart() error                     { return nil }
func (m *fakeProviderManager) PreClose() error                      { return nil }
func (m *fakeProviderManager) Close() error                         { return nil }
func (m *fakeProviderManager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	return nil
}
func (m *fakeProviderManager) Get(tag string) (adapter.Provider, bool) {
	for _, provider := range m.providers {
		if provider.Tag() == tag {
			return provider, true
		}
	}
	return nil, false
}

func (m *fakeProviderManager) RegisterProviderCallback(callback adapter.ProviderManagerUpdateCallback) *blist.Element[adapter.ProviderManagerUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *fakeProviderManager) UnregisterProviderCallback(element *blist.Element[adapter.ProviderManagerUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *fakeProviderManager) notifyProviderUpdate() {
	callbacks := make([]adapter.ProviderManagerUpdateCallback, 0, m.callbacks.Len())
	for element := m.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	for _, callback := range callbacks {
		callback()
	}
}

type providerTestNode struct {
	adapter.Outbound
	tag      string
	identity string
}

func (n *providerTestNode) Tag() string              { return n.tag }
func (n *providerTestNode) EndpointIdentity() string { return n.identity }

func newTestProviderSource(t *testing.T, options option.GroupCommonOption) (*groupProviderSource, *fakeProviderManager) {
	t.Helper()
	source := newGroupProviderSource(context.Background(), options)
	manager := &fakeProviderManager{providers: []adapter.Provider{
		&fakeProvider{tag: "prov-a", nodes: []adapter.Outbound{
			&providerTestNode{tag: "HK-香港 01"},
			&providerTestNode{tag: "US-美国 01"},
		}},
		&fakeProvider{tag: "prov-b", nodes: []adapter.Outbound{
			&providerTestNode{tag: "HK-香港 02"},
			&providerTestNode{tag: "JP-日本 01"},
		}},
	}}
	source.manager = manager
	return source, manager
}

type providerDialTestNode struct {
	providerTestNode
	dialIdentity string
}

func (n *providerDialTestNode) DialIdentity() string { return n.dialIdentity }

func TestSameOutboundIdentityPrefersDialIdentity(t *testing.T) {
	old := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK #2", identity: "path"}, dialIdentity: "dial-a"}
	newAlias := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK", identity: "path"}, dialIdentity: "dial-a"}
	otherCredential := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK", identity: "path"}, dialIdentity: "dial-b"}
	if !sameOutboundIdentity(old, newAlias) {
		t.Fatal("same dial identity must survive a display-tag rename")
	}
	if sameOutboundIdentity(old, otherCredential) {
		t.Fatal("different dial identities must not share a selected endpoint")
	}
}

func mustRegex(t *testing.T, expr string) *badoption.Regexp {
	t.Helper()
	return (*badoption.Regexp)(regexp.MustCompile(expr))
}

func TestProviderMemberAllowedSharedContract(t *testing.T) {
	include := regexp.MustCompile(`HK|香港`)
	exclude := regexp.MustCompile(`Gcore|排除`)
	cases := []struct {
		tag  string
		want bool
	}{
		{tag: "HK-香港 01", want: true},
		{tag: "HK-Gcore 02", want: false},
		{tag: "US-美国 01", want: false},
	}
	for _, test := range cases {
		if got := providerMemberAllowed(test.tag, include, exclude); got != test.want {
			t.Fatalf("providerMemberAllowed(%q)=%v, want %v", test.tag, got, test.want)
		}
	}
	if !providerMemberAllowed("anything", nil, nil) {
		t.Fatal("nil filters must allow every provider member")
	}
}

func TestGroupProviderSourceIncludeRegex(t *testing.T) {
	source, manager := newTestProviderSource(t, option.GroupCommonOption{
		Providers: []string{"prov-a", "prov-b"},
		Include:   mustRegex(t, `HK|hk|香港|港`),
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tags, members := source.memberOutbounds("")
	if len(members) != 2 || len(tags) != 2 {
		t.Fatalf("tags=%v members=%d", tags, len(members))
	}
	for _, tag := range tags {
		if tag != "HK-香港 01" && tag != "HK-香港 02" {
			t.Fatalf("include filter leaked %q", tag)
		}
	}
	if len(manager.Providers()) != 2 {
		t.Fatalf("providers registered=%d", len(manager.Providers()))
	}
}

func TestGroupProviderSourceExcludeRegex(t *testing.T) {
	source, _ := newTestProviderSource(t, option.GroupCommonOption{
		UseAllProviders: true,
		Exclude:         mustRegex(t, `US|美国`),
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, members := source.memberOutbounds("")
	if len(members) != 3 {
		t.Fatalf("members=%d, want 3 (US excluded)", len(members))
	}
	for _, member := range members {
		if member.Tag() == "US-美国 01" {
			t.Fatalf("exclude filter leaked %q", member.Tag())
		}
	}
}

func TestGroupProviderSourceIncrementalUpdate(t *testing.T) {
	source, manager := newTestProviderSource(t, option.GroupCommonOption{
		Providers: []string{"prov-a", "prov-b"},
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, first := source.memberOutbounds("")
	_, second := source.memberOutbounds("prov-b")
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("first=%d second=%d, want 4/4", len(first), len(second))
	}
	providers := manager.Providers()
	if got := providers[0].(*fakeProvider).outboundsCalls; got != 1 {
		t.Fatalf("prov-a Outbounds calls=%d, want 1 (incremental update must use cache)", got)
	}
	if got := providers[1].(*fakeProvider).outboundsCalls; got != 2 {
		t.Fatalf("prov-b Outbounds calls=%d, want 2 (initial + updated refresh)", got)
	}
}

func TestGroupProviderSourceCloseUnregistersCallbacks(t *testing.T) {
	source, manager := newTestProviderSource(t, option.GroupCommonOption{Providers: []string{"prov-a", "prov-b"}})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, provider := range manager.Providers() {
		if got := provider.(*fakeProvider).callbacks.Len(); got != 1 {
			t.Fatalf("callbacks before close=%d, want 1", got)
		}
	}
	source.close()
	source.close()
	for _, provider := range manager.Providers() {
		if got := provider.(*fakeProvider).callbacks.Len(); got != 0 {
			t.Fatalf("callbacks after close=%d, want 0", got)
		}
	}
}

func TestGroupProviderSourceRegisterAllowsSynchronousProviderNotification(t *testing.T) {
	source := newGroupProviderSource(context.Background(), option.GroupCommonOption{Providers: []string{"prov-a"}})
	provider := &fakeProvider{tag: "prov-a", notifyOnRegister: true}
	manager := &fakeProviderManager{providers: []adapter.Provider{provider}}
	source.manager = manager
	done := make(chan error, 1)
	go func() {
		done <- source.register(func(string) error {
			_, _ = source.memberOutbounds("")
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider callback registration deadlocked on synchronous notification")
	}
	source.close()
}

func TestGroupProviderSourceTracksUseAllProviderChanges(t *testing.T) {
	source, manager := newTestProviderSource(t, option.GroupCommonOption{UseAllProviders: true})
	var updates int
	if err := source.register(func(string) error {
		updates++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, members := source.memberOutbounds(""); len(members) != 4 {
		t.Fatalf("initial members=%d, want 4", len(members))
	}
	manager.providers = append(manager.providers, &fakeProvider{tag: "prov-c", nodes: []adapter.Outbound{
		&providerTestNode{tag: "SG-新加坡 01"},
	}})
	manager.notifyProviderUpdate()
	if _, members := source.memberOutbounds(""); len(members) != 5 {
		t.Fatalf("members after provider add=%d, want 5", len(members))
	}
	if updates != 1 {
		t.Fatalf("group updates=%d, want 1", updates)
	}
	manager.providers = manager.providers[:2]
	manager.notifyProviderUpdate()
	if _, members := source.memberOutbounds(""); len(members) != 4 {
		t.Fatalf("members after provider removal=%d, want 4", len(members))
	}
	source.close()
	if manager.callbacks.Len() != 0 {
		t.Fatalf("manager callbacks after close=%d, want 0", manager.callbacks.Len())
	}
}

func TestGroupProviderSourceUseAllSkipsAggregateViews(t *testing.T) {
	source := newGroupProviderSource(context.Background(), option.GroupCommonOption{UseAllProviders: true})
	leaf := &fakeProvider{tag: "leaf"}
	view := &fakeProvider{tag: "all-airports", typeName: C.ProviderTypeAggregate}
	manager := &fakeProviderManager{providers: []adapter.Provider{leaf, view}}
	source.manager = manager
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	source.access.Lock()
	if _, ok := source.providers[view.tag]; ok {
		source.access.Unlock()
		t.Fatal("use_all_providers included a synthetic aggregate view")
	}
	if _, ok := source.providers[leaf.tag]; !ok {
		source.access.Unlock()
		t.Fatal("use_all_providers dropped a leaf provider")
	}
	source.access.Unlock()
	source.close()
}

func TestRenameProviderMembersUsesStableEndpointIdentity(t *testing.T) {
	newMembers := func(reverse bool) []adapter.Outbound {
		a := &providerTestNode{tag: "HK", identity: "endpoint-a"}
		b := &providerTestNode{tag: "HK", identity: "endpoint-b"}
		if reverse {
			return []adapter.Outbound{b, a}
		}
		return []adapter.Outbound{a, b}
	}
	firstTags, first := renameProviderMembers(newMembers(false), map[string]struct{}{})
	secondTags, second := renameProviderMembers(newMembers(true), map[string]struct{}{})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("unexpected member count: %d/%d", len(first), len(second))
	}
	identityTags := func(members []adapter.Outbound) map[string]string {
		result := make(map[string]string, len(members))
		for _, member := range members {
			identified, ok := member.(adapter.OutboundWithEndpointIdentity)
			if !ok {
				t.Fatalf("member %q lost endpoint identity", member.Tag())
			}
			result[identified.EndpointIdentity()] = member.Tag()
		}
		return result
	}
	firstByIdentity := identityTags(first)
	secondByIdentity := identityTags(second)
	if firstByIdentity["endpoint-a"] != secondByIdentity["endpoint-a"] ||
		firstByIdentity["endpoint-b"] != secondByIdentity["endpoint-b"] {
		t.Fatalf("display suffixes changed after provider reorder: first=%v second=%v", firstTags, secondTags)
	}
	if firstByIdentity["endpoint-a"] != "HK" || firstByIdentity["endpoint-b"] != "HK #2" {
		t.Fatalf("unexpected stable suffix assignment: %v", firstByIdentity)
	}
}
