//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Module: M-dns-kernel-direct — docs/ebpf-feature-modules-20260805.md
//
// Under dns_mode=hijack, server_cidr :53 stays kernel; all other :53 hijacked.

// normalizeDNSKernelDirectOptions: non-empty server_cidr enables the feature.
// enabled:true with empty list is an error; empty everything is off.
func normalizeDNSKernelDirectOptions(
	options option.EBPFDNSKernelDirectOptions,
	dnsMode string,
) (bool, []netip.Prefix, error) {
	if len(options.ServerCIDR) == 0 {
		if options.Enabled {
			return false, nil, E.New("dns_kernel_direct.enabled requires non-empty server_cidr")
		}
		return false, nil, nil
	}
	if dnsMode != dnsModeHijack {
		return false, nil, E.New("dns_kernel_direct requires dns_mode=hijack")
	}
	prefixes := make([]netip.Prefix, 0, len(options.ServerCIDR))
	for _, p := range options.ServerCIDR {
		if !p.IsValid() {
			return false, nil, E.New("dns_kernel_direct.server_cidr contains invalid prefix")
		}
		prefixes = append(prefixes, p.Masked())
	}
	return true, prefixes, nil
}

func (i *Inbound) applyDNSKernelDirect() error {
	if i == nil {
		return nil
	}
	backend := i.backendInstance()
	if backend == nil {
		return E.New("eBPF backend is not initialized")
	}
	var prefixes []netip.Prefix
	if i.dnsKernelDirectEnabled {
		prefixes = i.dnsKernelDirectCIDRs
	}
	// Always push (empty clears maps after reload/disable).
	updated, err := backend.UpdateDNSDirectCIDR(prefixes)
	if err != nil {
		return err
	}
	if i.dnsKernelDirectEnabled {
		v4, v6 := backend.DNSDirectCIDRCount()
		i.logger.Info("eBPF dns_kernel_direct enabled server_cidr v4=", v4, " v6=", v6)
	} else if updated {
		i.logger.Debug("eBPF dns_kernel_direct maps cleared")
	}
	return nil
}
