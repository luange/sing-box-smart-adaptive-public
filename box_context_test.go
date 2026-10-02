package box_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	providerparser "github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/service"
)

// Provider parsing runs with the normal box context, not a hand-built test
// context. Keep the capability interfaces wired there so a schema-only
// protocol cannot pass the provider boundary in a minimal build.
func TestContextRegistersProtocolCapabilityViews(t *testing.T) {
	ctx := include.Context(context.Background())

	outboundRegistry := service.FromContext[adapter.OutboundRegistry](ctx)
	outboundSupport := service.FromContext[option.OutboundSupportRegistry](ctx)
	if outboundRegistry == nil || outboundSupport == nil {
		t.Fatal("box context did not register outbound capability view")
	}
	if concrete, ok := outboundRegistry.(option.OutboundSupportRegistry); !ok || concrete != outboundSupport {
		t.Fatal("outbound capability view is not the active registry")
	}

	endpointRegistry := service.FromContext[adapter.EndpointRegistry](ctx)
	endpointSupport := service.FromContext[option.EndpointSupportRegistry](ctx)
	if endpointRegistry == nil || endpointSupport == nil {
		t.Fatal("box context did not register endpoint capability view")
	}
	if concrete, ok := endpointRegistry.(option.EndpointSupportRegistry); !ok || concrete != endpointSupport {
		t.Fatal("endpoint capability view is not the active registry")
	}
}

func TestContextProviderParserHonorsProtocolCapability(t *testing.T) {
	ctx := include.Context(context.Background())
	capabilities := service.FromContext[option.OutboundSupportRegistry](ctx)
	if capabilities == nil {
		t.Fatal("box context did not expose outbound capabilities")
	}
	naiveSupported := capabilities.IsSupported("naive")
	outbounds, endpoints, err := providerparser.ParseSubscription(ctx, `{
  "outbounds": [
    {"type":"socks", "tag":"valid", "server":"127.0.0.1", "server_port":1080},
    {"type":"naive", "tag":"not-in-this-build", "server":"127.0.0.1", "server_port":443}
  ]
}`, nil, nil, nil, "context-capability-test")
	if err != nil {
		t.Fatal(err)
	}
	expectedOutbounds := 1
	if naiveSupported {
		expectedOutbounds = 2
	}
	if len(endpoints) != 0 || len(outbounds) != expectedOutbounds || outbounds[0].Tag != "valid" {
		t.Fatalf("production context did not filter schema-only protocol: outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}
