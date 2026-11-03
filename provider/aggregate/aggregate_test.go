package aggregate

import (
	"context"
	"errors"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

type testOutbound struct{ outbound.Adapter }

func newTestOutbound(tag string) adapter.Outbound {
	return &testOutbound{Adapter: outbound.NewAdapter(constant.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil)}
}

func (o *testOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("test outbound")
}

func (o *testOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test outbound")
}

type testProvider struct {
	tag       string
	members   []adapter.Outbound
	updatedAt time.Time
	health    map[string]uint16
	healthErr error
	callbacks list.List[adapter.ProviderUpdateCallback]
}

func (p *testProvider) Type() string { return constant.ProviderTypeInline }
func (p *testProvider) Tag() string  { return p.tag }
func (p *testProvider) Outbounds() []adapter.Outbound {
	return append([]adapter.Outbound(nil), p.members...)
}
func (p *testProvider) Outbound(tag string) (adapter.Outbound, bool) {
	for _, member := range p.members {
		if member.Tag() == tag {
			return member, true
		}
	}
	return nil, false
}
func (p *testProvider) UpdatedAt() time.Time { return p.updatedAt }
func (p *testProvider) HealthCheck(context.Context) (map[string]uint16, error) {
	if p.healthErr != nil {
		return nil, p.healthErr
	}
	return p.health, nil
}
func (p *testProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return p.callbacks.PushBack(callback)
}
func (p *testProvider) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	p.callbacks.Remove(element)
}
func (p *testProvider) update(members ...adapter.Outbound) {
	p.members = append([]adapter.Outbound(nil), members...)
	for element := p.callbacks.Front(); element != nil; element = element.Next() {
		_ = element.Value(p.tag)
	}
}

type testManager struct {
	adapter.ProviderManager
	providers []adapter.Provider
}

func (m *testManager) Providers() []adapter.Provider {
	return append([]adapter.Provider(nil), m.providers...)
}
func (m *testManager) Get(tag string) (adapter.Provider, bool) {
	for _, provider := range m.providers {
		if provider.Tag() == tag {
			return provider, true
		}
	}
	return nil, false
}

func TestAggregateProviderCombinesAndKeepsSourcesIndependent(t *testing.T) {
	first := &testProvider{tag: "airport-a", members: []adapter.Outbound{newTestOutbound("HK")}}
	second := &testProvider{tag: "airport-b", members: []adapter.Outbound{newTestOutbound("HK"), newTestOutbound("US")}}
	manager := &testManager{providers: []adapter.Provider{first, second}}
	aggregate := &Provider{
		manager:        manager,
		tag:            "all-airports",
		configuredTags: []string{"airport-a", "airport-b"},
		include:        regexp.MustCompile(`HK|US|JP`),
		children:       make(map[string]adapter.Provider),
		childHandles:   make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		memberByTag:    make(map[string]adapter.Outbound),
	}
	if err := aggregate.StartContext(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	members := aggregate.Outbounds()
	if len(members) != 3 {
		t.Fatalf("aggregate members=%d, want 3", len(members))
	}
	if _, ok := aggregate.Outbound("HK"); !ok {
		t.Fatal("aggregate lost first member")
	}
	if _, ok := aggregate.Outbound("HK #2"); !ok {
		t.Fatal("aggregate did not deterministically suffix duplicate member")
	}
	if _, ok := first.Outbound("HK"); !ok {
		t.Fatal("source provider was not independently addressable")
	}
	second.update(newTestOutbound("JP"))
	updated := aggregate.Outbounds()
	if len(updated) != 2 {
		t.Fatalf("aggregate refresh members=%d, want 2", len(updated))
	}
	if _, ok := aggregate.Outbound("JP"); !ok {
		t.Fatal("aggregate did not publish child refresh")
	}
	if err := aggregate.Close(); err != nil {
		t.Fatal(err)
	}
	second.update(newTestOutbound("US"))
	if len(aggregate.Outbounds()) != 0 {
		t.Fatal("closed aggregate accepted a late child update")
	}
}

func TestAggregateProviderRejectsNestedAggregates(t *testing.T) {
	child := &Provider{tag: "child-aggregate"}
	leaf := &testProvider{tag: "airport"}
	manager := &testManager{providers: []adapter.Provider{child, leaf}}

	explicit := &Provider{
		manager:        manager,
		tag:            "parent",
		configuredTags: []string{"child-aggregate"},
	}
	if _, err := explicit.resolveChildren(true); err == nil {
		t.Fatal("explicit aggregate-of-aggregate should be rejected")
	}

	all := &Provider{
		manager: manager,
		tag:     "all",
		useAll:  true,
	}
	children, err := all.resolveChildren(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := children[child.tag]; ok {
		t.Fatal("use_all_providers must not include aggregate children")
	}
	if _, ok := children[leaf.tag]; !ok {
		t.Fatal("use_all_providers dropped a leaf provider")
	}
}

func TestAggregateProviderHealthCheckPreservesDuplicateTags(t *testing.T) {
	first := &testProvider{
		tag:     "airport-a",
		members: []adapter.Outbound{newTestOutbound("HK")},
		health:  map[string]uint16{"HK": 30},
	}
	second := &testProvider{
		tag:     "airport-b",
		members: []adapter.Outbound{newTestOutbound("HK"), newTestOutbound("US")},
		health:  map[string]uint16{"HK": 180, "US": 90},
	}
	manager := &testManager{providers: []adapter.Provider{first, second}}
	aggregate := &Provider{
		manager:        manager,
		tag:            "all-airports",
		configuredTags: []string{"airport-a", "airport-b"},
		children:       make(map[string]adapter.Provider),
		childHandles:   make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		memberByTag:    make(map[string]adapter.Outbound),
	}
	if err := aggregate.StartContext(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	checks, err := aggregate.HealthCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint16{"HK": 30, "HK #2": 180, "US": 90}
	if len(checks) != len(want) {
		t.Fatalf("health entries=%d, want %d: %#v", len(checks), len(want), checks)
	}
	for tag, delay := range want {
		if checks[tag] != delay {
			t.Fatalf("health[%q]=%d, want %d: %#v", tag, checks[tag], delay, checks)
		}
	}
	_ = aggregate.Close()
}

func TestAggregateProviderHealthCheckReturnsPartialResults(t *testing.T) {
	first := &testProvider{
		tag:     "airport-a",
		members: []adapter.Outbound{newTestOutbound("HK")},
		health:  map[string]uint16{"HK": 30},
	}
	second := &testProvider{
		tag:       "airport-b",
		members:   []adapter.Outbound{newTestOutbound("US")},
		healthErr: errors.New("probe failed"),
	}
	manager := &testManager{providers: []adapter.Provider{first, second}}
	aggregate := &Provider{
		manager:        manager,
		tag:            "all-airports",
		configuredTags: []string{"airport-a", "airport-b"},
		children:       make(map[string]adapter.Provider),
		childHandles:   make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		memberByTag:    make(map[string]adapter.Outbound),
	}
	if err := aggregate.StartContext(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	checks, err := aggregate.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected partial health-check error")
	}
	if checks["HK"] != 30 {
		t.Fatalf("partial health result lost healthy child: %#v", checks)
	}
	if checks["US"] != 0 {
		t.Fatalf("failed child must not publish a synthetic result: %#v", checks)
	}
	_ = aggregate.Close()
}
