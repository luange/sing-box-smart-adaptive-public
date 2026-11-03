package outbound

import (
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// lifecycleOutbound is deliberately minimal: the manager only needs the
// outbound identity and Lifecycle implementation while advancing a dynamically
// created provider member.
type lifecycleOutbound struct {
	adapter.Outbound
	tag    string
	stages []adapter.StartStage
}

type simpleLifecycleOutbound struct {
	adapter.Outbound
	tag     string
	started int
	closed  int
}

func (o *simpleLifecycleOutbound) Type() string { return "legacy-test" }
func (o *simpleLifecycleOutbound) Tag() string  { return o.tag }
func (o *simpleLifecycleOutbound) Start() error { o.started++; return nil }
func (o *simpleLifecycleOutbound) Close() error { o.closed++; return nil }

func (o *lifecycleOutbound) Type() string { return "test" }
func (o *lifecycleOutbound) Tag() string  { return o.tag }
func (o *lifecycleOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	o.stages = append(o.stages, stage)
	return nil
}

func TestStartDynamicOutboundReplaysLifecycleFrontier(t *testing.T) {
	manager := new(Manager)
	outbound := &lifecycleOutbound{tag: "provider/node"}
	if err := manager.startDynamicOutbound(adapter.NewScope(context.Background(), nil), adapter.StartStateStarted, outbound); err != nil {
		t.Fatal(err)
	}
	want := []adapter.StartStage{
		adapter.StartStateInitialize,
		adapter.StartStateStart,
		adapter.StartStatePostStart,
		adapter.StartStateStarted,
	}
	if !reflect.DeepEqual(outbound.stages, want) {
		t.Fatalf("lifecycle stages = %v, want %v", outbound.stages, want)
	}
}

func TestStartDynamicOutboundStopsAtCurrentFrontier(t *testing.T) {
	manager := new(Manager)
	outbound := &lifecycleOutbound{tag: "provider/node"}
	if err := manager.startDynamicOutbound(adapter.NewScope(context.Background(), nil), adapter.StartStateInitialize, outbound); err != nil {
		t.Fatal(err)
	}
	want := []adapter.StartStage{adapter.StartStateInitialize}
	if !reflect.DeepEqual(outbound.stages, want) {
		t.Fatalf("lifecycle stages = %v, want %v", outbound.stages, want)
	}
}

func TestStartDynamicOutboundStartsLegacyLifecycleAtStartFrontier(t *testing.T) {
	manager := new(Manager)
	outbound := &simpleLifecycleOutbound{tag: "smart"}
	if err := manager.startDynamicOutbound(adapter.NewScope(context.Background(), nil), adapter.StartStateStarted, outbound); err != nil {
		t.Fatal(err)
	}
	if outbound.started != 1 {
		t.Fatalf("legacy Start calls = %d, want 1", outbound.started)
	}
}
