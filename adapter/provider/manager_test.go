package provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

type managerTestProvider struct {
	tag       string
	closeErr  error
	closeSeen int
	startFn   func()
	startErr  error
}

func (p *managerTestProvider) Type() string                             { return "test" }
func (p *managerTestProvider) Tag() string                              { return p.tag }
func (p *managerTestProvider) Outbounds() []adapter.Outbound            { return nil }
func (p *managerTestProvider) Outbound(string) (adapter.Outbound, bool) { return nil, false }
func (p *managerTestProvider) UpdatedAt() time.Time                     { return time.Time{} }
func (p *managerTestProvider) HealthCheck(context.Context) (map[string]uint16, error) {
	return nil, nil
}
func (p *managerTestProvider) RegisterCallback(adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return nil
}
func (p *managerTestProvider) UnregisterCallback(*list.Element[adapter.ProviderUpdateCallback]) {}
func (p *managerTestProvider) StartContext(context.Context, *adapter.HTTPStartContext) error {
	if p.startFn != nil {
		p.startFn()
	}
	return p.startErr
}
func (p *managerTestProvider) Close() error {
	p.closeSeen++
	return p.closeErr
}

var _ adapter.Provider = (*managerTestProvider)(nil)

type managerTestRegistry struct {
	provider adapter.Provider
}

type managerUncomparableProvider struct {
	*managerTestProvider
	state []byte
}

func (managerTestRegistry) OptionTypes() []string            { return []string{"test"} }
func (managerTestRegistry) CreateOptions(string) (any, bool) { return nil, true }
func (r managerTestRegistry) CreateProvider(context.Context, adapter.Router, log.Factory, string, string, any) (adapter.Provider, error) {
	return r.provider, nil
}

var _ adapter.ProviderRegistry = managerTestRegistry{}

func TestManagerCloseReleasesProvidersBeforeStart(t *testing.T) {
	p := &managerTestProvider{tag: "p"}
	m := NewManager(context.Background(), logger.NOP(), nil)
	m.providers = []adapter.Provider{p}
	m.providerByTag[p.Tag()] = p

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if p.closeSeen != 1 {
		t.Fatalf("pre-start provider close count=%d, want 1", p.closeSeen)
	}
	if len(m.Providers()) != 0 {
		t.Fatal("manager retained providers after close")
	}
	m.closeAccess.Lock()
	if len(m.closeInflight) != 0 {
		t.Fatalf("close in-flight table retained %d providers", len(m.closeInflight))
	}
	m.closeAccess.Unlock()
}

func TestManagerSupportsUncomparableProviderValues(t *testing.T) {
	base := &managerTestProvider{tag: "value"}
	provider := managerUncomparableProvider{managerTestProvider: base, state: []byte{1, 2, 3}}
	m := NewManager(context.Background(), logger.NOP(), nil)
	m.providers = []adapter.Provider{provider}
	m.providerByTag[provider.Tag()] = provider
	if err := m.Remove(provider.Tag()); err != nil {
		t.Fatalf("remove uncomparable provider: %v", err)
	}
	if base.closeSeen != 1 {
		t.Fatalf("uncomparable provider close count=%d, want 1", base.closeSeen)
	}
}

func TestManagerReplacesUncomparableProviderValue(t *testing.T) {
	base := &managerTestProvider{tag: "value"}
	old := managerUncomparableProvider{managerTestProvider: base, state: []byte{1, 2, 3}}
	newProvider := &managerTestProvider{tag: old.Tag()}
	m := NewManager(context.Background(), logger.NOP(), managerTestRegistry{provider: newProvider})
	m.providers = []adapter.Provider{old}
	m.providerByTag[old.Tag()] = old
	if err := m.Create(context.Background(), nil, nil, old.Tag(), "test", nil); err != nil {
		t.Fatalf("replace uncomparable provider: %v", err)
	}
	current, ok := m.Get(old.Tag())
	if !ok || current != newProvider {
		t.Fatalf("replacement was not authoritative: %v %v", current, ok)
	}
	if base.closeSeen != 1 {
		t.Fatalf("replaced uncomparable provider close count=%d, want 1", base.closeSeen)
	}
}

func TestManagerReplacementPublishesNewProviderWhenOldCloseFails(t *testing.T) {
	old := &managerTestProvider{tag: "p", closeErr: errors.New("cleanup failed")}
	newProvider := &managerTestProvider{tag: "p"}
	m := NewManager(context.Background(), logger.NOP(), managerTestRegistry{provider: newProvider})
	m.started = true
	m.stage = adapter.StartStateStarted
	m.providers = []adapter.Provider{old}
	m.providerByTag[old.Tag()] = old

	if err := m.Create(context.Background(), nil, nil, "p", "test", nil); err != nil {
		t.Fatalf("cleanup warning must not make committed replacement fail: %v", err)
	}
	current, ok := m.Get("p")
	if !ok || current != newProvider {
		t.Fatalf("new provider was not authoritative after old close error: %v %v", current, ok)
	}
	if old.closeSeen != 1 {
		t.Fatalf("old provider close count=%d, want 1", old.closeSeen)
	}
}

func TestManagerStartRollsBackPartialFailure(t *testing.T) {
	first := &managerTestProvider{tag: "first"}
	second := &managerTestProvider{tag: "second", startErr: errors.New("start failed")}
	m := NewManager(context.Background(), logger.NOP(), nil)
	m.providers = []adapter.Provider{first, second}
	m.providerByTag[first.Tag()] = first
	m.providerByTag[second.Tag()] = second

	if err := m.Start(adapter.StartStateStart); err == nil {
		t.Fatal("expected start failure")
	}
	if first.closeSeen != 1 {
		t.Fatalf("started provider close count=%d, want 1", first.closeSeen)
	}
	if second.closeSeen != 1 {
		t.Fatalf("failed provider cleanup count=%d, want 1", second.closeSeen)
	}
	if m.started || m.stage != adapter.StartStateInitialize {
		t.Fatalf("manager state was not rolled back: started=%v stage=%v", m.started, m.stage)
	}
	second.startErr = nil
	if err := m.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if first.closeSeen != 2 || second.closeSeen != 2 {
		t.Fatalf("provider close counts after retry=%d,%d, want 2,2", first.closeSeen, second.closeSeen)
	}
}

func TestManagerCallbackCanReenterMutation(t *testing.T) {
	p := &managerTestProvider{tag: "p"}
	m := NewManager(context.Background(), logger.NOP(), managerTestRegistry{provider: p})
	done := make(chan struct{})
	var once sync.Once
	m.RegisterProviderCallback(func() {
		if _, ok := m.Get("p"); ok {
			_ = m.Remove("p")
		}
		once.Do(func() { close(done) })
	})
	if err := m.Create(context.Background(), nil, nil, "p", "test", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("provider callback re-entry deadlocked")
	}
}

func TestManagerStartHookCanReenterCreate(t *testing.T) {
	first := &managerTestProvider{tag: "first"}
	nested := &managerTestProvider{tag: "nested"}
	m := NewManager(context.Background(), logger.NOP(), managerTestRegistry{provider: nested})
	m.providers = []adapter.Provider{first}
	m.providerByTag[first.Tag()] = first
	first.startFn = func() {
		if err := m.Create(context.Background(), nil, nil, nested.Tag(), "test", nil); err == nil {
			t.Error("reentrant create must be rejected while start is transactional")
		}
	}

	done := make(chan error, 1)
	go func() { done <- m.Start(adapter.StartStateStart) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider start hook re-entry deadlocked")
	}
	if _, ok := m.Get(nested.Tag()); ok {
		t.Fatal("reentrant provider was published during an incomplete start")
	}
	if nested.closeSeen != 1 {
		t.Fatalf("reentrant provider close count=%d, want 1", nested.closeSeen)
	}
}

func TestManagerStartRejectsRemoveAndClose(t *testing.T) {
	provider := &managerTestProvider{tag: "provider"}
	m := NewManager(context.Background(), logger.NOP(), nil)
	m.providers = []adapter.Provider{provider}
	m.providerByTag[provider.Tag()] = provider
	provider.startFn = func() {
		if err := m.Remove(provider.Tag()); err == nil {
			t.Error("reentrant remove must be rejected while start is transactional")
		}
		if err := m.Close(); err == nil {
			t.Error("reentrant close must be rejected while start is transactional")
		}
	}
	if err := m.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(provider.Tag()); !ok {
		t.Fatal("provider was removed during an incomplete start")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if provider.closeSeen != 1 {
		t.Fatalf("provider close count=%d, want 1", provider.closeSeen)
	}
}

func TestManagerProviderStartCanReadManagerWithoutAccessDeadlock(t *testing.T) {
	m := NewManager(context.Background(), logger.NOP(), nil)
	old := &managerTestProvider{tag: "old"}
	m.providers = []adapter.Provider{old}
	m.providerByTag[old.Tag()] = old
	m.started = true
	m.stage = adapter.StartStateStarted
	newProvider := &managerTestProvider{tag: "new"}
	newProvider.startFn = func() {
		if _, ok := m.Get("old"); !ok {
			t.Error("manager lookup failed while provider was starting")
		}
	}
	m.registry = managerTestRegistry{provider: newProvider}
	if err := m.Create(context.Background(), nil, nil, "new", "test", nil); err != nil {
		t.Fatal(err)
	}
}
