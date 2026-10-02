package trafficcontrol

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type TrackerMetadata struct {
	ID              uuid.UUID
	Metadata        adapter.InboundContext
	CreatedAt       time.Time
	ClosedAt        time.Time
	Upload          *atomic.Int64
	Download        *atomic.Int64
	Chain           []string
	Rule            adapter.Rule
	Outbound        string
	OutboundType    string
	CloseReason     adapter.ConnectionCloseReason
	outboundManager adapter.OutboundManager
}

type Tracker interface {
	Metadata() *TrackerMetadata
	Close() error
}

// cloneTrackerMetadata returns a reader-owned view of tracker metadata. The
// byte counters intentionally keep their atomic pointers so dashboards can
// observe live totals, while route identity slices are copied to prevent a
// close/finalize operation from racing with JSON or protobuf encoding.
func cloneTrackerMetadata(source *TrackerMetadata) *TrackerMetadata {
	if source == nil {
		return nil
	}
	copy := *source
	copy.Chain = append([]string(nil), source.Chain...)
	return &copy
}

// FinalizeChain rebuilds Chain/Outbound from the route root plus any real leaf
// tags groups recorded during Dial (smart/selector/urltest/loadbalance/adaptive).
// Call on close so history sees the leaf that actually carried traffic, not the
// sticky Now() snapshotted at route time.
func (t *TrackerMetadata) FinalizeChain() {
	if t == nil || t.outboundManager == nil {
		return
	}
	root := ""
	if len(t.Chain) > 0 {
		// Display order is leaf → … → root.
		root = t.Chain[len(t.Chain)-1]
	} else if t.Outbound != "" {
		root = t.Outbound
	} else {
		return
	}
	real := t.Metadata.GetRealOutboundChain()
	var chain []string
	next := root
	realIdx := 0
	seen := make(map[string]struct{}, 8)
	for depth := 0; depth < 16 && next != ""; depth++ {
		if _, dup := seen[next]; dup {
			break
		}
		seen[next] = struct{}{}
		detour, loaded := t.outboundManager.Outbound(next)
		if !loaded {
			break
		}
		chain = append(chain, next)
		t.Outbound = detour.Tag()
		t.OutboundType = detour.Type()
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		if realIdx < len(real) {
			next = real[realIdx]
			realIdx++
			continue
		}
		next = group.Now()
	}
	if len(chain) > 0 {
		t.Chain = common.Reverse(chain)
	}
}

func (t *TrackerMetadata) SetCloseReason(reason adapter.ConnectionCloseReason) {
	if t == nil || reason == "" {
		return
	}
	if t.Metadata.Extended != nil {
		t.Metadata.Extended.SetCloseReason(reason)
	}
}

func (t *TrackerMetadata) LoadCloseReason() adapter.ConnectionCloseReason {
	if t == nil {
		return adapter.CloseReasonUnknown
	}
	if reason := t.Metadata.Extended.CloseReason(); reason != "" {
		return reason
	}
	if t.CloseReason != "" {
		return t.CloseReason
	}
	return adapter.CloseReasonUnknown
}

// EffectiveChain returns the finalized display chain (leaf first).
func (t TrackerMetadata) EffectiveChain() []string {
	if len(t.Chain) == 0 {
		return nil
	}
	return append([]string(nil), t.Chain...)
}

func (m *Manager) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	tracker := &connTracker{
		ExtendedConn: bufio.NewCounterConn(conn, []N.CountFunc{func(n int64) {
			upload.Add(n)
			m.uploadTotal.Add(n)
		}}, []N.CountFunc{func(n int64) {
			download.Add(n)
			m.downloadTotal.Add(n)
		}}),
		metadata: m.newTrackerMetadata(metadata, matchedRule, matchOutbound, upload, download),
		manager:  m,
	}
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	tracker := &packetConnTracker{
		PacketConn: bufio.NewCounterPacketConn(conn, []N.CountFunc{func(n int64) {
			upload.Add(n)
			m.uploadTotal.Add(n)
		}}, []N.CountFunc{func(n int64) {
			download.Add(n)
			m.downloadTotal.Add(n)
		}}),
		metadata: m.newTrackerMetadata(metadata, matchedRule, matchOutbound, upload, download),
		manager:  m,
	}
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return &flowTracker{
		metadata: m.newTrackerMetadata(metadata, matchedRule, matchOutbound, new(atomic.Int64), new(atomic.Int64)),
		manager:  m,
	}
}

func (m *Manager) newTrackerMetadata(metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound, upload *atomic.Int64, download *atomic.Int64) TrackerMetadata {
	// Ensure Extended is allocated so Dial-time AppendRealOutbound mutates the
	// same slice the tracker holds (value-copied InboundContext keeps the pointer).
	metadata.InitExtended()
	id, _ := uuid.NewV4()
	var (
		chain        []string
		next         string
		outbound     string
		outboundType string
	)
	if matchOutbound != nil {
		next = matchOutbound.Tag()
	} else {
		next = m.outbound.Default().Tag()
	}
	for {
		detour, loaded := m.outbound.Outbound(next)
		if !loaded {
			break
		}
		chain = append(chain, next)
		outbound = detour.Tag()
		outboundType = detour.Type()
		outboundGroup, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		next = outboundGroup.Now()
		if next == "" {
			break
		}
	}
	return TrackerMetadata{
		ID:              id,
		Metadata:        metadata,
		CreatedAt:       time.Now(),
		Upload:          upload,
		Download:        download,
		Chain:           common.Reverse(chain),
		Rule:            matchedRule,
		Outbound:        outbound,
		OutboundType:    outboundType,
		outboundManager: m.outbound,
	}
}

type connTracker struct {
	N.ExtendedConn
	metadata TrackerMetadata
	manager  *Manager
}

func (t *connTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *connTracker) Close() error {
	t.manager.leave(t)
	return t.ExtendedConn.Close()
}

func (t *connTracker) Upstream() any {
	return t.ExtendedConn
}

func (t *connTracker) ReaderReplaceable() bool {
	return true
}

func (t *connTracker) WriterReplaceable() bool {
	return true
}

var (
	_ Tracker         = (*flowTracker)(nil)
	_ tun.FlowTracker = (*flowTracker)(nil)
)

type flowTracker struct {
	metadata TrackerMetadata
	manager  *Manager
	handle   tun.FlowHandle
}

func (t *flowTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *flowTracker) AttachFlow(handle tun.FlowHandle) {
	t.handle = handle
	t.manager.join(t)
}

func (t *flowTracker) CountForward(n int) {
	t.metadata.Upload.Add(int64(n))
	t.manager.uploadTotal.Add(int64(n))
}

func (t *flowTracker) CountReverse(n int) {
	t.metadata.Download.Add(int64(n))
	t.manager.downloadTotal.Add(int64(n))
}

func (t *flowTracker) FlowEstablished() {
}

func (t *flowTracker) CloseFlow(reason tun.FlowCloseReason) {
	t.manager.leave(t)
}

func (t *flowTracker) Close() error {
	handle := t.handle
	if handle != nil {
		handle.CloseFlow()
	} else {
		t.manager.leave(t)
	}
	return nil
}

type packetConnTracker struct {
	N.PacketConn
	metadata TrackerMetadata
	manager  *Manager
}

func (t *packetConnTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *packetConnTracker) Close() error {
	t.manager.leave(t)
	return t.PacketConn.Close()
}

func (t *packetConnTracker) Upstream() any {
	return t.PacketConn
}

func (t *packetConnTracker) ReaderReplaceable() bool {
	return true
}

func (t *packetConnTracker) WriterReplaceable() bool {
	return true
}
