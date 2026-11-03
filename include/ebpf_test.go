package include

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestEBPFInboundMinimalOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{"type":"ebpf","tag":"ebpf-in"}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	if inboundOptions.Type != "ebpf" || inboundOptions.Tag != "ebpf-in" {
		t.Fatalf("unexpected inbound header: %+v", inboundOptions)
	}
	if _, loaded := inboundOptions.Options.(*option.EBPFInboundOptions); !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
}

func TestEBPFInboundListenOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"listen": "0.0.0.0",
		"listen_port": 12345,
		"reuse_addr": true,
		"udp_timeout": "45s",
		"detour": "detour-in",
		"dns_mode": "off",
		"network": "tcp"
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if ebpfOptions.Listen == nil || netip.Addr(*ebpfOptions.Listen) != netip.IPv4Unspecified() {
		t.Fatalf("unexpected listen address: %v", ebpfOptions.Listen)
	}
	if ebpfOptions.ListenPort != 12345 || !ebpfOptions.ReuseAddr || ebpfOptions.Detour != "detour-in" {
		t.Fatalf("unexpected listen options: %+v", ebpfOptions.ListenOptions)
	}
	if time.Duration(ebpfOptions.UDPTimeout) != 45*time.Second {
		t.Fatalf("unexpected UDP timeout: %v", time.Duration(ebpfOptions.UDPTimeout))
	}
	if ebpfOptions.DNSMode != "off" {
		t.Fatalf("unexpected DNS mode: %s", ebpfOptions.DNSMode)
	}
	network := ebpfOptions.Network.Build()
	if len(network) != 1 || network[0] != "tcp" {
		t.Fatalf("unexpected network: %v", network)
	}
}

func TestEBPFInboundRedirectAddresses(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"redirect_address": [
			"127.128.0.0/9",
			"fd53:696e:672d:626f::/64"
		],
		"bypass_rule_set": [
			"geoip-cn"
		]
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if len(ebpfOptions.RedirectAddress) != 2 {
		t.Fatalf("unexpected redirect addresses: %v", ebpfOptions.RedirectAddress)
	}
	if ebpfOptions.RedirectAddress[0] != netip.MustParsePrefix("127.128.0.0/9") ||
		ebpfOptions.RedirectAddress[1] != netip.MustParsePrefix("fd53:696e:672d:626f::/64") {
		t.Fatalf("unexpected redirect addresses: %v", ebpfOptions.RedirectAddress)
	}
	if len(ebpfOptions.BypassRuleSet) != 1 || ebpfOptions.BypassRuleSet[0] != "geoip-cn" {
		t.Fatalf("unexpected bypass rule-set: %v", ebpfOptions.BypassRuleSet)
	}
}

func TestEBPFInboundSharedNetworkOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"cgroup_path": "/sys/fs/cgroup/test.slice",
		"shared_network": {
			"enabled": true,
			"include_interface": ["wlan2"]
		}
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if ebpfOptions.CgroupPath != "/sys/fs/cgroup/test.slice" ||
		!ebpfOptions.SharedNetwork.Enabled ||
		len(ebpfOptions.SharedNetwork.IncludeInterface) != 1 ||
		ebpfOptions.SharedNetwork.IncludeInterface[0] != "wlan2" {
		t.Fatalf("unexpected eBPF shared-network options: %+v", ebpfOptions)
	}
}

func TestEBPFInboundOutboundOffloadOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"outbound_offload": {
			"splice": {
				"enabled": true,
				"max_pairs": 4096,
				"accounting": true,
				"half_close": "close",
				"idle_timeout": "2m"
			},
			"verdict": {
				"mode": "off",
				"ttl": "5m"
			}
		}
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	off := ebpfOptions.OutboundOffload
	if !off.Splice.Enabled {
		t.Fatalf("expected splice.enabled")
	}
	if off.Splice.MaxPairs != 4096 {
		t.Fatalf("unexpected max_pairs: %d", off.Splice.MaxPairs)
	}
	if off.Splice.Accounting == nil || !*off.Splice.Accounting {
		t.Fatalf("unexpected accounting: %+v", off.Splice.Accounting)
	}
	if off.Splice.HalfClose != "close" {
		t.Fatalf("unexpected half_close: %s", off.Splice.HalfClose)
	}
	if time.Duration(off.Splice.IdleTimeout) != 2*time.Minute {
		t.Fatalf("unexpected idle_timeout: %v", time.Duration(off.Splice.IdleTimeout))
	}
	if off.Verdict.Mode != "off" {
		t.Fatalf("unexpected verdict.mode: %s", off.Verdict.Mode)
	}
	if time.Duration(off.Verdict.TTL) != 5*time.Minute {
		t.Fatalf("unexpected verdict.ttl: %v", time.Duration(off.Verdict.TTL))
	}
}

func TestEBPFInboundDNSKernelDirectAndPrefillOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"dns_mode": "hijack",
		"dns_kernel_direct": {
			"enabled": true,
			"server_cidr": ["223.5.5.5/32", "8.8.8.8/32"]
		},
		"outbound_offload": {
			"dns_prefill": {
				"enabled": true,
				"ttl": "90s"
			},
			"verdict": { "mode": "off" }
		}
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if !ebpfOptions.DNSKernelDirect.Enabled || len(ebpfOptions.DNSKernelDirect.ServerCIDR) != 2 {
		t.Fatalf("unexpected dns_kernel_direct: %+v", ebpfOptions.DNSKernelDirect)
	}
	if ebpfOptions.DNSKernelDirect.ServerCIDR[0] != netip.MustParsePrefix("223.5.5.5/32") {
		t.Fatalf("unexpected server_cidr[0]: %v", ebpfOptions.DNSKernelDirect.ServerCIDR[0])
	}
	if !ebpfOptions.OutboundOffload.DNSPrefill.Enabled {
		t.Fatal("expected dns_prefill.enabled")
	}
	if time.Duration(ebpfOptions.OutboundOffload.DNSPrefill.TTL) != 90*time.Second {
		t.Fatalf("unexpected dns_prefill.ttl: %v", time.Duration(ebpfOptions.OutboundOffload.DNSPrefill.TTL))
	}
}
