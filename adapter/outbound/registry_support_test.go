package outbound

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestRegistrySupportDistinguishesSchemaStub(t *testing.T) {
	registry := NewRegistry()
	Register[option.SOCKSOutboundOptions](registry, "real", func(context.Context, adapter.Router, log.ContextLogger, string, option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		return nil, nil
	})
	RegisterUnsupported[option.NaiveOutboundOptions](registry, "stub", func(context.Context, adapter.Router, log.ContextLogger, string, option.NaiveOutboundOptions) (adapter.Outbound, error) {
		return nil, nil
	})
	if !registry.IsSupported("real") || registry.IsSupported("stub") || registry.IsSupported("missing") {
		t.Fatalf("unexpected support state: real=%v stub=%v missing=%v", registry.IsSupported("real"), registry.IsSupported("stub"), registry.IsSupported("missing"))
	}
}
