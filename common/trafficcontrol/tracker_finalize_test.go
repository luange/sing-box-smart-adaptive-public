package trafficcontrol

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type finalizeStubOutbound struct {
	outbound.Adapter
	now string
}

func (s *finalizeStubOutbound) Now() string { return s.now }

func (s *finalizeStubOutbound) All() []string {
	if s.now == "" {
		return nil
	}
	return []string{s.now}
}

func (s *finalizeStubOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (s *finalizeStubOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type finalizeLeaf struct {
	outbound.Adapter
}

func (s *finalizeLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (s *finalizeLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type finalizeOutboundManager struct {
	byTag map[string]adapter.Outbound
}

func (m *finalizeOutboundManager) Start(adapter.StartStage) error { return nil }
func (m *finalizeOutboundManager) Close() error                   { return nil }
func (m *finalizeOutboundManager) Outbounds() []adapter.Outbound {
	out := make([]adapter.Outbound, 0, len(m.byTag))
	for _, o := range m.byTag {
		out = append(out, o)
	}
	return out
}
func (m *finalizeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.byTag[tag]
	return o, ok
}
func (m *finalizeOutboundManager) Default() adapter.Outbound { return nil }
func (m *finalizeOutboundManager) Remove(string) error       { return nil }
func (m *finalizeOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

func TestFinalizeChainPrefersRealOutboundOverStickyNow(t *testing.T) {
	leafA := &finalizeLeaf{Adapter: outbound.NewAdapter(C.TypeTrojan, "airport/a", []string{N.NetworkTCP}, nil)}
	leafB := &finalizeLeaf{Adapter: outbound.NewAdapter(C.TypeTrojan, "airport/b", []string{N.NetworkTCP}, nil)}
	group := &finalizeStubOutbound{
		Adapter: outbound.NewAdapter(C.TypeSmart, "HK", []string{N.NetworkTCP}, nil),
		now:     "airport/a",
	}
	fake := &finalizeOutboundManager{byTag: map[string]adapter.Outbound{
		"HK":        group,
		"airport/a": leafA,
		"airport/b": leafB,
	}}

	meta := adapter.InboundContext{}
	meta.InitExtended()
	meta.AppendRealOutbound("airport/b")

	tm := TrackerMetadata{
		Metadata:        meta,
		Chain:           []string{"airport/a", "HK"},
		Outbound:        "airport/a",
		OutboundType:    C.TypeTrojan,
		outboundManager: fake,
	}
	tm.FinalizeChain()
	if tm.Outbound != "airport/b" {
		t.Fatalf("outbound=%s want airport/b", tm.Outbound)
	}
	if len(tm.Chain) < 2 || tm.Chain[0] != "airport/b" || tm.Chain[len(tm.Chain)-1] != "HK" {
		t.Fatalf("chain=%v", tm.Chain)
	}
}
