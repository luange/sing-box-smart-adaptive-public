//go:build !with_ebpf || (!linux && !android) || !cgo

package ebpf

import (
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// VerdictStats mirrors the cgo build (A2 kernel counters included).
type VerdictStats struct {
	Writes      uint64
	Skips       uint64
	KernelHits  uint64
	Expired     uint64
	GenMismatch uint64
}

type VerdictEntry struct {
	Destination netip.AddrPort
	Family      uint8
	Protocol    uint8
	Verdict     uint8
	Generation  uint32
	ExpireNs    uint64
}

type VerdictBackend struct{}

func NewVerdictBackend(int, int, int) (*VerdictBackend, error) {
	return nil, E.New("eBPF verdict requires with_ebpf, linux/android, and cgo")
}

func (v *VerdictBackend) PutDIRECT(uint8, netip.AddrPort, time.Duration) error {
	return E.New("verdict not available")
}
func (v *VerdictBackend) Skip()                {}
func (v *VerdictBackend) InvalidateAll() error { return E.New("verdict not available") }
func (v *VerdictBackend) SetEnabled(bool) error {
	return E.New("verdict not available")
}
func (v *VerdictBackend) Stats() VerdictStats { return VerdictStats{} }
func (v *VerdictBackend) Generation() uint32  { return 0 }
func (v *VerdictBackend) Close()              {}
