package adaptive

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type sourceRuntimeOutboundManager struct {
	A.OutboundManager
	byTag map[string]A.Outbound
}

func (m *sourceRuntimeOutboundManager) Outbound(tag string) (A.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

type sourceRuntimeProvider struct {
	A.Provider
	tag       string
	outbounds []A.Outbound
	options   map[string]option.Outbound
	revision  uint64
	delta     A.ProviderDelta
	callbacks list.List[A.ProviderUpdateCallback]
}

func (p *sourceRuntimeProvider) Tag() string { return p.tag }
func (p *sourceRuntimeProvider) Outbounds() []A.Outbound {
	return append([]A.Outbound(nil), p.outbounds...)
}
func (p *sourceRuntimeProvider) Outbound(tag string) (A.Outbound, bool) {
	for _, outbound := range p.outbounds {
		if outbound.Tag() == tag {
			return outbound, true
		}
	}
	return nil, false
}
func (p *sourceRuntimeProvider) OutboundOptions() map[string]option.Outbound {
	result := make(map[string]option.Outbound, len(p.options))
	for tag, outboundOptions := range p.options {
		result[tag] = outboundOptions
	}
	return result
}
func (p *sourceRuntimeProvider) OutboundOption(tag string) (option.Outbound, bool) {
	outboundOptions, loaded := p.options[tag]
	return outboundOptions, loaded
}
func (p *sourceRuntimeProvider) OutboundDeltaRevision() uint64 { return p.revision }
func (p *sourceRuntimeProvider) OutboundDelta(after uint64) (A.ProviderDelta, bool) {
	if after == p.revision {
		return A.ProviderDelta{BaseRevision: after, Revision: after}, true
	}
	if p.delta.BaseRevision != after || p.delta.Revision != p.revision {
		return A.ProviderDelta{}, false
	}
	return p.delta, true
}
func (p *sourceRuntimeProvider) RegisterCallback(callback A.ProviderUpdateCallback) *list.Element[A.ProviderUpdateCallback] {
	return p.callbacks.PushBack(callback)
}
func (p *sourceRuntimeProvider) UnregisterCallback(element *list.Element[A.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}
func (p *sourceRuntimeProvider) notify() error {
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		if err := element.Value(p.tag); err != nil {
			return err
		}
	}
	return nil
}

type sourceRuntimeProviderManager struct {
	A.ProviderManager
	provider  A.Provider
	providers []A.Provider
}

func (m *sourceRuntimeProviderManager) Providers() []A.Provider {
	if m.providers != nil {
		return append([]A.Provider(nil), m.providers...)
	}
	return []A.Provider{m.provider}
}
func (m *sourceRuntimeProviderManager) Get(tag string) (A.Provider, bool) {
	for _, provider := range m.Providers() {
		if provider != nil && provider.Tag() == tag {
			return provider, true
		}
	}
	return nil, false
}

func TestA48SourceAdapterCopiesCanonicalTransportAliasesAndMetadata(t *testing.T) {
	hasher := testIdentityHasher(t)
	outbound := newTestOutbound("provider/node")
	options := option.Outbound{Type: "test", Options: struct {
		Server string `json:"server"`
	}{Server: "node.example"}}
	adapter := NewA48SourceAdapterV1(1, hasher, []A48SourceRoot{{Outbound: outbound, Options: &options, Source: "provider"}}, func(string) (A.Outbound, bool) { return nil, false })
	snapshot, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes) != 1 || len(snapshot.Nodes[0].Transport) != 1 || snapshot.Nodes[0].Transport[0] != "tcp" {
		t.Fatalf("transport was not canonicalized: %+v", snapshot.Nodes)
	}
	if snapshot.Nodes[0].Aliases[0] != "provider/node" || snapshot.Nodes[0].Metadata["source"] != "provider" {
		t.Fatalf("canonical metadata was not copied: %+v", snapshot.Nodes[0])
	}
	snapshot.Nodes[0].Aliases[0] = "changed"
	if snapshot.Nodes[0].Aliases[0] != "changed" {
		t.Fatal("test setup failed")
	}
	second, _ := adapter.Snapshot(context.Background())
	if second.Nodes[0].Aliases[0] != "provider/node" {
		t.Fatal("adapter leaked mutable aliases")
	}
}

func TestA48StaticRuntimeDescriptorIsStableAcrossSnapshots(t *testing.T) {
	hasher := testIdentityHasher(t)
	outbound := newTestOutbound("static-node")
	adapter := NewA48SourceAdapterV1(1, hasher, []A48SourceRoot{{Outbound: outbound, Source: "static"}}, func(string) (A.Outbound, bool) { return nil, false })
	first, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 || !first.Nodes[0].IdentityStable || first.Nodes[0].NodeID != second.Nodes[0].NodeID {
		t.Fatalf("static runtime descriptor was not stable: first=%+v second=%+v", first.Nodes, second.Nodes)
	}
}

func TestA48ManualNodeExclusionFiltersCanonicalNodesAndBindings(t *testing.T) {
	matcher, err := nodefilter.New([]string{"Gcore", "=airport/完整节点名"})
	if err != nil {
		t.Fatal(err)
	}
	keepID := NodeID{1}
	keywordID := NodeID{2}
	exactID := NodeID{3}
	publication := SourcePublication{
		SourceSnapshot: SourceSnapshot{Generation: 1, InputLeafCount: 3, Nodes: []CanonicalNode{
			{NodeID: keepID, SourceKey: "airport/普通节点", Aliases: []string{"airport/普通节点"}},
			{NodeID: keywordID, SourceKey: "provider/source", Aliases: []string{"airport/US-Gcore-01"}},
			{NodeID: exactID, SourceKey: "airport/完整节点名", Aliases: []string{"airport/完整节点名"}},
		}},
		Bindings: map[NodeID]ExecutionPort{keepID: newTestOutbound("keep"), keywordID: newTestOutbound("keyword"), exactID: newTestOutbound("exact")},
	}
	filtered := filterManualSourcePublication(publication, matcher)
	if len(filtered.Nodes) != 1 || filtered.Nodes[0].NodeID != keepID || len(filtered.Bindings) != 1 || filtered.Bindings[keepID] == nil || filtered.InputLeafCount != 1 {
		t.Fatalf("manual canonical filter failed: %+v bindings=%d", filtered.SourceSnapshot, len(filtered.Bindings))
	}
}

func TestA48SourceRuntimeOwnsProviderArraysAndCallbackLifecycle(t *testing.T) {
	candidate := newTestOutbound("provider/node")
	provider := &sourceRuntimeProvider{tag: "provider", outbounds: []A.Outbound{candidate}}
	outboundManager := &sourceRuntimeOutboundManager{byTag: map[string]A.Outbound{candidate.Tag(): candidate}}
	providerManager := &sourceRuntimeProviderManager{provider: provider}
	ctx := service.ContextWith[A.OutboundManager](context.Background(), outboundManager)
	ctx = service.ContextWith[A.ProviderManager](ctx, providerManager)
	runtime, err := NewA48SourceRuntimeV1(ctx, testIdentityHasher(t), SourceRuntimeConfig{ProviderTags: []string{"provider"}})
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	if err = runtime.Start(func() error { updates++; return nil }); err != nil {
		t.Fatal(err)
	}
	snapshot, err := runtime.Snapshot(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Nodes) != 1 || snapshot.Nodes[0].SourceKey != candidate.Tag() || snapshot.Nodes[0].Metadata["source"] != provider.tag {
		t.Fatalf("provider array did not terminate in canonical snapshot: %+v", snapshot)
	}
	if err = provider.notify(); err != nil || updates != 1 {
		t.Fatalf("provider callback was not reduced to source update: updates=%d err=%v", updates, err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.callbacks.Len() != 0 {
		t.Fatal("source runtime retained provider callback after Close")
	}
	if err = provider.notify(); err != nil || updates != 1 {
		t.Fatalf("closed source runtime received provider update: updates=%d err=%v", updates, err)
	}
}

func TestA48SourceRuntimeAppliesProviderDeltaWithoutFullArrayScan(t *testing.T) {
	oldCandidate := newTestOutbound("provider/node")
	newCandidate := newTestOutbound("provider/node")
	oldOptions := option.Outbound{Type: "test", Options: struct {
		Server string `json:"server"`
	}{Server: "old.example"}}
	newOptions := option.Outbound{Type: "test", Options: struct {
		Server string `json:"server"`
	}{Server: "new.example"}}
	provider := &sourceRuntimeProvider{tag: "provider", outbounds: []A.Outbound{oldCandidate}, options: map[string]option.Outbound{oldCandidate.Tag(): oldOptions}}
	manager := &sourceRuntimeOutboundManager{byTag: map[string]A.Outbound{oldCandidate.Tag(): oldCandidate}}
	providerManager := &sourceRuntimeProviderManager{provider: provider}
	ctx := service.ContextWith[A.OutboundManager](context.Background(), manager)
	ctx = service.ContextWith[A.ProviderManager](ctx, providerManager)
	runtime, err := NewA48SourceRuntimeV1(ctx, testIdentityHasher(t), SourceRuntimeConfig{ProviderTags: []string{"provider"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Start(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	baseline, err := runtime.Snapshot(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	provider.outbounds = []A.Outbound{newCandidate}
	provider.options = map[string]option.Outbound{newCandidate.Tag(): newOptions}
	provider.revision = 1
	provider.delta = A.ProviderDelta{BaseRevision: 0, Revision: 1, Upserts: []string{newCandidate.Tag()}}
	manager.byTag[newCandidate.Tag()] = newCandidate
	if err = provider.notify(); err != nil {
		t.Fatal(err)
	}
	delta, err := runtime.(IncrementalSourceRuntime).Delta(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Removes) != 1 || len(delta.Upserts) != 1 || delta.Upserts[0].NodeID == baseline.Nodes[0].NodeID {
		t.Fatalf("unexpected provider delta: removes=%v upserts=%+v", delta.Removes, delta.Upserts)
	}
	applied, err := ApplySourceDelta(baseline, delta)
	if err != nil || len(applied.Nodes) != 1 || applied.Nodes[0].NodeID != delta.Upserts[0].NodeID {
		t.Fatalf("provider delta did not apply: snapshot=%+v err=%v", applied.SourceSnapshot, err)
	}
}

func TestA48SourceRuntimeUseAllReconcilesDynamicProviders(t *testing.T) {
	ctx := context.Background()
	first := &sourceRuntimeProvider{tag: "first"}
	second := &sourceRuntimeProvider{tag: "second"}
	manager := &sourceRuntimeOutboundManager{byTag: map[string]A.Outbound{}}
	providerManager := &sourceRuntimeProviderManager{providers: []A.Provider{first}}
	ctx = service.ContextWith[A.OutboundManager](ctx, manager)
	ctx = service.ContextWith[A.ProviderManager](ctx, providerManager)
	runtime, err := NewA48SourceRuntimeV1(ctx, testIdentityHasher(t), SourceRuntimeConfig{UseAll: true, ProviderPollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var updates atomic.Int32
	onUpdate := func() error { updates.Add(1); return nil }
	if err = runtime.Start(onUpdate); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	providerManager.providers = []A.Provider{first, second}
	if err = runtime.(*A48SourceRuntimeV1).reconcileAllProviders(onUpdate); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 1 {
		t.Fatalf("dynamic provider set change did not trigger rebuild: updates=%d", updates.Load())
	}
	if err = second.notify(); err != nil || updates.Load() != 2 {
		t.Fatalf("dynamic provider callback was not registered: updates=%d err=%v", updates.Load(), err)
	}
	providerManager.providers = []A.Provider{second}
	if err = runtime.(*A48SourceRuntimeV1).reconcileAllProviders(onUpdate); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 3 {
		t.Fatalf("provider removal did not trigger rebuild: updates=%d", updates.Load())
	}
	if err = first.notify(); err != nil || updates.Load() != 3 {
		t.Fatalf("removed provider callback remained registered: updates=%d err=%v", updates.Load(), err)
	}
}
