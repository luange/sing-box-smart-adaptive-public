//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
	"runtime"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
)

const SharedNetworkMapCapacity = 16384

type SharedNetworkBackend struct{}

func PrepareSharedNetwork(
	*Backend,
	uint16,
	bool,
	bool,
	netip.Prefix,
	netip.Prefix,
	bool,
	bool,
	uint32,
) (*SharedNetworkBackend, error) {
	return nil, unsupportedSharedNetworkError()
}

func unsupportedSharedNetworkError() error {
	return E.New("shared-network eBPF is not supported on ", runtime.GOOS, "/", runtime.GOARCH, " in this build")
}

func (b *SharedNetworkBackend) Enable() error { return unsupportedSharedNetworkError() }
func (b *SharedNetworkBackend) UpdateInterfaceMAC(uint32, []byte) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteInterfaceMAC(uint32) error { return nil }
func (b *SharedNetworkBackend) Disable() error                  { return nil }
func (b *SharedNetworkBackend) IngressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) EgressProgramFD() int {
	return -1
}
func (b *SharedNetworkBackend) RuntimeStats() (SharedNetworkRuntimeStats, error) {
	return SharedNetworkRuntimeStats{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) RegisterListenerSocket(uint32, int) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) LookupOriginal(uint8, netip.AddrPort, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteRedirect(uint8, netip.AddrPort, netip.AddrPort) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) UpdateHostAddresses([]netip.Addr) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) SetFlowDirect(bool) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) PutDirectFlow(uint8, netip.AddrPort, netip.AddrPort, time.Duration) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteDirectFlow(uint8, netip.AddrPort, netip.AddrPort) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) InvalidateFlowDirect() error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) TakeOriginal(uint8, netip.AddrPort, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) PublishStaticDirect([]netip.Prefix, uint32, uint32) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) MergeStaticDirect(netip.Prefix) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) MergeDynamicDirect(netip.Prefix, time.Duration) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) PublishDNSHint(netip.Addr, bool, uint8, uint32, time.Duration) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DrainDNSObservations(int) ([]ebpfv3.DNSObservation, error) {
	return nil, unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) PublishMACPolicies([]ebpfv3.MACPolicyEntry) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) DeleteMergedStaticDirect(netip.Prefix) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) WriteControlV3(bool, uint32, uint32, uint32, uint32) error {
	return unsupportedSharedNetworkError()
}
func (b *SharedNetworkBackend) PolicyGeneration() uint32 { return 0 }
func (b *SharedNetworkBackend) V3Stats() ([]uint64, uint32, uint32) {
	return nil, 0, 0
}
func (b *SharedNetworkBackend) Close() error   { return nil }
func (b *SharedNetworkBackend) IsClosed() bool { return true }

var _ SharedDataplane = (*SharedNetworkBackend)(nil)
