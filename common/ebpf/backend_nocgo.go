//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type Backend struct{}

func Prepare(string, uint16, bool, bool, netip.Prefix, netip.Prefix, Policy) (*Backend, error) {
	return nil, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) Attach() error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) Close() error {
	return nil
}

func (b *Backend) IsClosed() bool {
	return true
}

func (b *Backend) AddBypassPrefix(netip.Prefix) error {
	return E.New("ebpf unavailable")
}

func (b *Backend) DeleteBypassPrefix(netip.Prefix) error {
	return E.New("ebpf unavailable")
}

func (b *Backend) ListBypassCIDR() []netip.Prefix { return nil }

func (b *Backend) UpdateBypassCIDR([]netip.Prefix) (bool, error) {
	return false, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) BypassContains(netip.Addr) bool { return false }

func (b *Backend) BypassCIDRCount() (int, int) {
	return 0, 0
}

func (b *Backend) UpdateDNSDirectCIDR([]netip.Prefix) (bool, error) {
	return false, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) DNSDirectCIDRCount() (int, int) {
	return 0, 0
}

func (b *Backend) RuntimeStats() (RuntimeStats, error) {
	return RuntimeStats{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) CgroupPath() string {
	return ""
}

func (b *Backend) AttachedPrograms() []string {
	return nil
}

func (b *Backend) ProtectFunc() control.Func {
	return nil
}

func (b *Backend) ProtectHits() uint64 { return 0 }

func (b *Backend) RegisterSelfListenPort(uint16) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) OutVerdictMapFDs() (int, int, int) { return -1, -1, -1 }

func (b *Backend) FlowVerdictEnabled() bool { return false }

func (b *Backend) LookupOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) TakeOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *Backend) DeleteRedirect(uint8, netip.AddrPort) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}
