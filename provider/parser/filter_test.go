package parser

import (
	"context"
	"errors"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type parserOutboundRegistry struct{}

func (parserOutboundRegistry) OptionTypes() []string { return []string{C.TypeSOCKS} }

func (parserOutboundRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeSOCKS {
		return nil, false
	}
	return new(option.SOCKSOutboundOptions), true
}

type parserEndpointRegistry struct{}

func (parserEndpointRegistry) OptionTypes() []string { return []string{C.TypeWireGuard} }

func (parserEndpointRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeWireGuard {
		return nil, false
	}
	return new(option.WireGuardEndpointOptions), true
}

func (parserEndpointRegistry) IsSupported(protocol string) bool { return protocol == C.TypeWireGuard }

type parserStubOutboundRegistry struct{}

func (parserStubOutboundRegistry) OptionTypes() []string { return []string{C.TypeNaive} }

func (parserStubOutboundRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeNaive {
		return nil, false
	}
	return new(option.NaiveOutboundOptions), true
}

func (parserStubOutboundRegistry) IsSupported(string) bool { return false }

type parserStubEndpointRegistry struct{}

func (parserStubEndpointRegistry) OptionTypes() []string { return []string{C.TypeWireGuard} }

func (parserStubEndpointRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeWireGuard {
		return nil, false
	}
	return new(option.WireGuardEndpointOptions), true
}

func (parserStubEndpointRegistry) IsSupported(string) bool { return false }

func parserContext() context.Context {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), parserOutboundRegistry{})
	return service.ContextWith[option.EndpointOptionsRegistry](ctx, parserEndpointRegistry{})
}

func TestParseBoxSubscriptionSkipsUnsupportedAndMalformedMembers(t *testing.T) {
	ctx := parserContext()
	outbounds, endpoints, err := ParseSubscription(ctx, `{
  "outbounds": [
    {"type":"socks", "tag":"valid", "server":"127.0.0.1", "server_port":1080},
    {"type":"made-up", "tag":"unsupported", "server":"127.0.0.1", "server_port":1080},
    {"type":"socks", "tag":"malformed", "server_port":"not-a-number"},
    {"type":"selector", "tag":"group", "outbounds":["valid"]}
  ]
}`, nil, nil, nil, "test-provider")
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 || len(outbounds) != 1 || outbounds[0].Tag != "valid" {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestParseClashSubscriptionSkipsUnsupportedAndMalformedMembers(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.WithValue(context.Background(), providerTagContextKey{}, "test-provider"), `
proxies:
  - name: valid
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: unsupported
    type: wireguard-lite
    server: 127.0.0.1
    port: 1080
  - name: malformed
    type: vmess
    server: 127.0.0.1
    port: nope
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 || len(outbounds) != 1 || outbounds[0].Tag != "valid" {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestFilterSupportedMembersUsesBuildRegistry(t *testing.T) {
	ctx := parserContext()
	outbounds, endpoints := filterSupportedMembers(ctx, []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "valid", Options: new(option.SOCKSOutboundOptions)},
		{Type: "not-built", Tag: "unsupported", Options: new(option.SOCKSOutboundOptions)},
		{Type: C.TypeSOCKS, Tag: "nil-options"},
	}, []option.Endpoint{
		{Type: C.TypeWireGuard, Tag: "wg", Options: new(option.WireGuardEndpointOptions)},
		{Type: "not-built", Tag: "bad"},
	}, "test-provider")
	if len(outbounds) != 1 || len(endpoints) != 1 {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestFilterSupportedMembersAlwaysDropsNilOptions(t *testing.T) {
	outbounds, endpoints := filterSupportedMembers(context.Background(), []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "broken"},
	}, []option.Endpoint{{Type: C.TypeWireGuard, Tag: "broken-endpoint"}}, "test")
	if len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("nil option members must be discarded without registries: outbounds=%d endpoints=%d", len(outbounds), len(endpoints))
	}
}

func TestFilterSupportedMembersDropsTypedNilOptions(t *testing.T) {
	ctx := parserContext()
	var outboundOptions *option.SOCKSOutboundOptions
	var endpointOptions *option.WireGuardEndpointOptions
	outbounds, endpoints := filterSupportedMembers(ctx, []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "typed-nil", Options: outboundOptions},
	}, []option.Endpoint{
		{Type: C.TypeWireGuard, Tag: "typed-nil", Options: endpointOptions},
	}, "test")
	if len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("typed nil options must be discarded: outbounds=%d endpoints=%d", len(outbounds), len(endpoints))
	}
}

func TestFilterSupportedMembersDropsSchemaOnlyStubs(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), parserStubOutboundRegistry{})
	ctx = service.ContextWith[option.OutboundSupportRegistry](ctx, parserStubOutboundRegistry{})
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, parserStubEndpointRegistry{})
	ctx = service.ContextWith[option.EndpointSupportRegistry](ctx, parserStubEndpointRegistry{})
	outbounds, endpoints := filterSupportedMembers(ctx, []option.Outbound{{
		Type: C.TypeNaive, Tag: "stub", Options: new(option.NaiveOutboundOptions),
	}}, []option.Endpoint{{
		Type: C.TypeWireGuard, Tag: "stub", Options: new(option.WireGuardEndpointOptions),
	}}, "test")
	if len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("schema-only stubs must be discarded: outbounds=%d endpoints=%d", len(outbounds), len(endpoints))
	}
}

func TestFilterSupportedMembersUsesCapabilityRegistryWithoutSchemaRegistry(t *testing.T) {
	ctx := service.ContextWith[option.OutboundSupportRegistry](context.Background(), parserStubOutboundRegistry{})
	outbounds, endpoints := filterSupportedMembers(ctx, []option.Outbound{
		{Type: C.TypeNaive, Tag: "stub", Options: new(option.NaiveOutboundOptions)},
	}, nil, "test")
	if len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("capability-only registry must still reject schema-only stubs: outbounds=%d endpoints=%d", len(outbounds), len(endpoints))
	}
}

func TestParseClashSubscriptionDropsSchemaOnlyStub(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), parserStubOutboundRegistry{})
	ctx = service.ContextWith[option.OutboundSupportRegistry](ctx, parserStubOutboundRegistry{})
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, parserEndpointRegistry{})
	ctx = service.ContextWith[option.EndpointSupportRegistry](ctx, parserEndpointRegistry{})
	outbounds, endpoints, err := ParseClashSubscription(ctx, `
proxies:
  - name: unavailable
    type: naive
    server: 127.0.0.1
    port: 443
`)
	if err == nil || len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("schema-only clash protocol must be dropped: outbounds=%d endpoints=%d err=%v", len(outbounds), len(endpoints), err)
	}
}

func TestParseBoxSubscriptionDropsSchemaOnlyStub(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), parserStubOutboundRegistry{})
	ctx = service.ContextWith[option.OutboundSupportRegistry](ctx, parserStubOutboundRegistry{})
	_, _, err := ParseBoxSubscription(ctx, `{
  "outbounds": [
    {"type":"naive", "tag":"unavailable", "server":"127.0.0.1", "server_port":443}
  ]
}`)
	if err == nil || !strings.Contains(err.Error(), "no supported servers found") {
		t.Fatalf("schema-only sing-box protocol must be dropped: err=%v", err)
	}
}

func TestProviderErrorReasonDoesNotEchoSubscriptionPayload(t *testing.T) {
	// URL and structured parsers commonly include the offending value in the
	// returned error. Logging that text would expose credentials or signed query
	// parameters, so the provider boundary must emit only a reason category.
	err := errors.New(`parse "vless://user:secret@example.invalid:443/path?token=private"`)
	reason := providerErrorReason(err)
	if reason != "malformed or invalid member" {
		t.Fatalf("unexpected reason: %q", reason)
	}
	for _, forbidden := range []string{"vless://", "secret", "token", "private", "example.invalid"} {
		if strings.Contains(reason, forbidden) {
			t.Fatalf("reason echoed sensitive payload %q: %q", forbidden, reason)
		}
	}
}

func TestWarningDeduperIsBounded(t *testing.T) {
	deduper := newWarningDeduper(2)
	if !deduper.first("a") || !deduper.first("b") || deduper.first("a") {
		t.Fatal("warning deduper did not suppress a repeated key")
	}
	if !deduper.first("c") {
		t.Fatal("warning deduper rejected a new key")
	}
	if deduper.first("b") {
		t.Fatal("warning deduper did not retain the newest keys")
	}
	if !deduper.first("a") {
		t.Fatal("warning deduper did not evict the oldest key")
	}
}
