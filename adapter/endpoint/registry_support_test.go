package endpoint

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestRegistrySupportDistinguishesSchemaStub(t *testing.T) {
	registry := NewRegistry()
	Register[option.WireGuardEndpointOptions](registry, "real", func(context.Context, adapter.Router, log.ContextLogger, string, option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
		return nil, nil
	})
	RegisterUnsupported[option.TailscaleEndpointOptions](registry, "stub", func(context.Context, adapter.Router, log.ContextLogger, string, option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
		return nil, nil
	})
	if !registry.IsSupported("real") || registry.IsSupported("stub") || registry.IsSupported("missing") {
		t.Fatalf("unexpected support state: real=%v stub=%v missing=%v", registry.IsSupported("real"), registry.IsSupported("stub"), registry.IsSupported("missing"))
	}
}
