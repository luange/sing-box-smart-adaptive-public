package provider

import (
	"regexp"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

func TestProviderLifecyclePauseAndConsumerCount(t *testing.T) {
	var provider Adapter
	if provider.ProviderPaused() {
		t.Fatal("provider must start unpaused")
	}
	provider.SetProviderPaused(true)
	if !provider.ProviderPaused() {
		t.Fatal("provider pause was not recorded")
	}
	handle := provider.RegisterCallback(func(string) error { return nil })
	if consumers := provider.ProviderConsumers(); consumers != 1 {
		t.Fatalf("unexpected consumer count: %d", consumers)
	}
	provider.UnregisterCallback(handle)
	if consumers := provider.ProviderConsumers(); consumers != 0 {
		t.Fatalf("consumer was not released: %d", consumers)
	}
	var _ adapter.ProviderLifecycleController = &provider
}

func TestFilterProviderOptionsSharedSemantics(t *testing.T) {
	outbounds := []option.Outbound{{Tag: "HK-香港 01"}, {Tag: "HK-Gcore 02"}, {Tag: "US-美国 01"}}
	endpoints := []option.Endpoint{{Tag: "HK-endpoint"}, {Tag: "US-endpoint"}}
	include := regexp.MustCompile(`HK|香港`)
	exclude := regexp.MustCompile(`Gcore`)
	filteredOutbounds, filteredEndpoints := FilterProviderOptions(outbounds, endpoints, include, exclude)
	if len(filteredOutbounds) != 1 || filteredOutbounds[0].Tag != "HK-香港 01" {
		t.Fatalf("unexpected filtered outbounds: %+v", filteredOutbounds)
	}
	if len(filteredEndpoints) != 1 || filteredEndpoints[0].Tag != "HK-endpoint" {
		t.Fatalf("unexpected filtered endpoints: %+v", filteredEndpoints)
	}
}
