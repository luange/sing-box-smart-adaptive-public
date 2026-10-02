//go:build !with_ebpf || (!linux && !android) || !cgo

package ebpf

import (
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

type SpliceStats struct {
	PairsCreated     uint64
	PairsReleased    uint64
	Redirects        uint64
	RedirectFailures uint64
	PeerMisses       uint64
	Passthrough      uint64
	ActivePairs      uint64
}

type SplicePair struct{}

func (p *SplicePair) Release() error                 { return nil }
func (p *SplicePair) Bytes() (uint64, uint64, error) { return 0, 0, E.New("splice not available") }
func (p *SplicePair) SetOnRelease(func())            {}
func (p *SplicePair) LeftConn() net.Conn             { return nil }
func (p *SplicePair) RightConn() net.Conn            { return nil }

type SpliceBackend struct{}

func PrepareSplice(uint32, bool) (*SpliceBackend, error) {
	return nil, E.New("eBPF splice requires with_ebpf, linux/android, and cgo")
}

func (b *SpliceBackend) Attach() error { return E.New("splice not available") }
func (b *SpliceBackend) Close() error  { return nil }
func (b *SpliceBackend) IsClosed() bool {
	return true
}
func (b *SpliceBackend) Accounting() bool { return false }
func (b *SpliceBackend) Pair(net.Conn, net.Conn) (*SplicePair, error) {
	return nil, E.New("splice not available")
}
func (b *SpliceBackend) BeginPair(net.Conn, net.Conn) (*SplicePair, error) {
	return nil, E.New("splice not available")
}
func (p *SplicePair) Activate() error { return E.New("splice not available") }
func (b *SpliceBackend) RuntimeStats() (SpliceStats, error) {
	return SpliceStats{}, E.New("splice not available")
}
