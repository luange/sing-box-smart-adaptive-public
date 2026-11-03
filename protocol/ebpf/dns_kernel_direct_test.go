//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestNormalizeDNSKernelDirectDefaultsOff(t *testing.T) {
	enabled, prefixes, err := normalizeDNSKernelDirectOptions(option.EBPFDNSKernelDirectOptions{}, dnsModeHijack)
	if err != nil {
		t.Fatal(err)
	}
	if enabled || len(prefixes) != 0 {
		t.Fatalf("expected disabled empty, got enabled=%v prefixes=%v", enabled, prefixes)
	}
}

func TestNormalizeDNSKernelDirectRequiresHijack(t *testing.T) {
	_, _, err := normalizeDNSKernelDirectOptions(option.EBPFDNSKernelDirectOptions{
		Enabled:    true,
		ServerCIDR: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("223.5.5.5/32")},
	}, dnsModeOff)
	if err == nil {
		t.Fatal("expected error when dns_mode=off")
	}
}

func TestNormalizeDNSKernelDirectRequiresServerCIDR(t *testing.T) {
	_, _, err := normalizeDNSKernelDirectOptions(option.EBPFDNSKernelDirectOptions{
		Enabled: true,
	}, dnsModeHijack)
	if err == nil {
		t.Fatal("expected error when server_cidr empty")
	}
}

func TestNormalizeDNSKernelDirectImplicitEnable(t *testing.T) {
	enabled, prefixes, err := normalizeDNSKernelDirectOptions(option.EBPFDNSKernelDirectOptions{
		ServerCIDR: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("223.5.5.5/32"),
			netip.MustParsePrefix("119.29.29.29/32"),
		},
	}, dnsModeHijack)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || len(prefixes) != 2 {
		t.Fatalf("unexpected: enabled=%v prefixes=%v", enabled, prefixes)
	}
}

func TestDNSPrefillOptionsDefaultTTL(t *testing.T) {
	opts := dnsPrefillOptionsFrom(option.EBPFDNSPrefillOptions{Enabled: true})
	if !opts.enabled || opts.ttl != 60*time.Second {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}

func TestIsStableDirectLeafType(t *testing.T) {
	if !isStableDirectLeafType("direct") || !isStableDirectLeafType("ebpf") {
		t.Fatal("direct/ebpf should be stable")
	}
	if isStableDirectLeafType("smart") || isStableDirectLeafType("shadowsocks") || isStableDirectLeafType("") {
		t.Fatal("non-leaf must not be stable")
	}
}

func TestFilterPrefillAddresses(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.1"),  // dup
		netip.MustParseAddr("10.0.0.1"), // private
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::1"), // dup v6
	}
	out := filterPrefillAddresses(in)
	if len(out) != 3 {
		t.Fatalf("want 3 public unique, got %v", out)
	}
	if out[0].String() != "1.1.1.1" || out[1].String() != "8.8.8.8" {
		t.Fatalf("order/content: %v", out)
	}
}
