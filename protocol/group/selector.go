package group

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup           = (*Selector)(nil)
	_ adapter.SelectorGroup           = (*Selector)(nil)
	_ adapter.PreMatchOutboundGroup   = (*Selector)(nil)
	_ adapter.ConnectionHandler       = (*Selector)(nil)
	_ adapter.PacketConnectionHandler = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       logger.ContextLogger
	baseTags                     []string
	defaultTag                   string
	providerSource               *groupProviderSource
	membership                   atomic.Pointer[groupOutboundSnapshot]
	stateAccess                  sync.Mutex
	closed                       bool
	selected                     common.TypedValue[adapter.Outbound]
	history                      *urltest.HistoryStorage
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, nil, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		baseTags:                     options.Outbounds,
		defaultTag:                   options.Default,
		providerSource:               newGroupProviderSource(ctx, options.GroupCommonOption),
		history:                      service.PtrFromContext[urltest.HistoryStorage](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(options.Outbounds) == 0 && len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, E.New("missing tags")
	}
	outbound.membership.Store(newGroupOutboundSnapshot(nil, nil))
	return outbound, nil
}

func (s *Selector) snapshot() *groupOutboundSnapshot {
	return s.membership.Load()
}

func (s *Selector) rebuildSnapshot(providerTag string) *groupOutboundSnapshot {
	tags := append([]string(nil), s.baseTags...)
	byTag := make(map[string]adapter.Outbound, len(tags))
	for _, tag := range tags {
		if detour, loaded := s.outbound.Outbound(tag); loaded && detour != nil {
			byTag[tag] = detour
		}
	}
	if s.providerSource.has() {
		_, members := s.providerSource.memberOutbounds(providerTag)
		providerTags, renamed := renameProviderMembers(members, func() map[string]struct{} {
			occupied := make(map[string]struct{}, len(tags))
			for _, tag := range tags {
				occupied[tag] = struct{}{}
			}
			return occupied
		}())
		for _, member := range renamed {
			byTag[member.Tag()] = member
		}
		tags = append(tags, providerTags...)
	}
	return newGroupOutboundSnapshot(tags, byTag)
}

func (s *Selector) setFallbackLocked(snapshot *groupOutboundSnapshot) {
	if snapshot == nil {
		s.selected.Store(nil)
		return
	}
	if current := s.selected.Load(); current != nil {
		if next, loaded := snapshot.outbounds[current.Tag()]; loaded && sameOutboundIdentity(current, next) {
			s.selected.Store(next)
			return
		}
		// A provider refresh may legitimately renumber a duplicate display tag
		// (for example HK #2 becomes HK after HK #1 disappears). Preserve the
		// selected endpoint by identity, never by a coincidental UI tag.
		for _, tag := range snapshot.tags {
			next := snapshot.outbounds[tag]
			if sameOutboundIdentity(current, next) {
				s.selected.Store(next)
				return
			}
		}
	}
	if s.defaultTag != "" {
		if next, loaded := snapshot.outbounds[s.defaultTag]; loaded {
			s.selected.Store(next)
			return
		}
	}
	for _, tag := range snapshot.tags {
		if next := snapshot.outbounds[tag]; next != nil {
			s.selected.Store(next)
			return
		}
	}
	s.selected.Store(nil)
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return E.New("selector is closed")
	}
	baseTags := append([]string(nil), s.baseTags...)
	defaultTag := s.defaultTag
	s.stateAccess.Unlock()
	for i, tag := range baseTags {
		if _, loaded := s.outbound.Outbound(tag); !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
	}
	if s.providerSource.has() {
		if err := s.providerSource.register(s.onProviderUpdated); err != nil {
			return err
		}
	}
	snapshot := s.rebuildSnapshot("")
	var cachedTag string
	var cachedRecord adapter.SelectedRecord
	var cachedRecordLoaded bool
	if s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if store, ok := cacheFile.(adapter.SelectedRecordStore); ok {
				cachedRecord, cachedRecordLoaded = store.LoadSelectedRecord(s.Tag())
			}
			cachedTag = cacheFile.LoadSelected(s.Tag())
		}
	}
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		s.providerSource.close()
		return E.New("selector is closed")
	}
	s.membership.Store(snapshot)

	if cachedRecordLoaded {
		if detour := resolveSelectionRecord(snapshotOutbounds(snapshot), cachedRecord); detour != nil {
			s.selected.Store(detour)
			s.stateAccess.Unlock()
			return nil
		}
	}
	if cachedTag != "" {
		if detour, loaded := snapshot.outbounds[cachedTag]; loaded {
			s.selected.Store(detour)
			s.stateAccess.Unlock()
			if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
				if err := storeSelectedRecord(cacheFile, s.Tag(), detour); err != nil {
					s.logger.Error("migrate selected identity: ", err)
				}
			}
			return nil
		}
	}

	var startErr error
	if defaultTag != "" {
		detour, loaded := snapshot.outbounds[defaultTag]
		if !loaded {
			startErr = E.New("default outbound not found: ", defaultTag)
		} else {
			s.selected.Store(detour)
		}
	} else {
		s.setFallbackLocked(snapshot)
	}
	s.stateAccess.Unlock()
	if startErr != nil {
		s.providerSource.close()
		return startErr
	}
	return nil
}

func (s *Selector) onProviderUpdated(tag string) error {
	s.stateAccess.Lock()
	if s.closed || !s.providerSource.has() {
		s.stateAccess.Unlock()
		return E.New("outbound provider not found: ", tag)
	}
	s.stateAccess.Unlock()
	if tag != "" && !s.providerSource.hasProvider(tag) {
		return E.New("outbound provider not found: ", tag)
	}
	snapshot := s.rebuildSnapshot(tag)
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return nil
	}
	s.membership.Store(snapshot)
	s.setFallbackLocked(snapshot)
	selected := s.selected.Load()
	s.stateAccess.Unlock()
	// A provider refresh may renumber a duplicate alias. Persist the resolved
	// identity so a subsequent restart follows the same endpoint, not the old
	// display suffix.
	if selected != nil && s.Tag() != "" {
		if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
			if err := storeSelectedRecord(cacheFile, s.Tag(), selected); err != nil {
				s.logger.Error("update selected identity: ", err)
			}
		}
	}
	return nil
}

func (s *Selector) Now() string {
	selected := s.selected.Load()
	if selected == nil {
		if snapshot := s.snapshot(); snapshot != nil && len(snapshot.tags) > 0 {
			return snapshot.tags[0]
		}
		return ""
	}
	return selected.Tag()
}

func (s *Selector) All() []string {
	return s.snapshot().all()
}

func (s *Selector) Selected() adapter.Outbound {
	return s.selected.Load()
}

func (s *Selector) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	_ = metadata
	selected := s.selected.Load()
	if selected == nil {
		return nil, adapter.PreMatchContinue
	}
	return selectOutbound(selected)
}

func (s *Selector) SelectOutbound(tag string) bool {
	s.stateAccess.Lock()
	snapshot := s.snapshot()
	if snapshot == nil {
		s.stateAccess.Unlock()
		return false
	}
	detour, loaded := snapshot.outbounds[tag]
	if !loaded {
		s.stateAccess.Unlock()
		return false
	}
	changed := s.selected.Swap(detour) != detour
	s.stateAccess.Unlock()
	if !changed {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := storeSelectedRecord(cacheFile, s.Tag(), detour)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	if s.history != nil {
		s.history.NotifyUpdated()
	}
	return true
}

func (s *Selector) Close() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return nil
	}
	s.closed = true
	s.membership.Store(newGroupOutboundSnapshot(nil, nil))
	s.selected.Store(nil)
	s.stateAccess.Unlock()
	// Provider unregistration is external lifecycle code and may call back
	// synchronously; never hold selector stateAccess across it.
	s.providerSource.close()
	return nil
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	selected := s.selected.Load()
	if selected == nil {
		return nil, E.New("selector has no selected outbound")
	}
	adapter.NoteRealOutbound(ctx, selected)
	conn, err := selected.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	selected := s.selected.Load()
	if selected == nil {
		return nil, E.New("selector has no selected outbound")
	}
	adapter.NoteRealOutbound(ctx, selected)
	conn, err := selected.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if selected == nil {
		return
	}
	if outboundHandler, isHandler := selected.(adapter.ConnectionHandler); isHandler {
		outboundHandler.NewConnection(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if selected == nil {
		return
	}
	if outboundHandler, isHandler := selected.(adapter.PacketConnectionHandler); isHandler {
		outboundHandler.NewPacketConnection(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewPacketConnection(ctx, selected, conn, metadata, onClose)
	}
}

func RealTag(outboundManager adapter.OutboundManager, detour adapter.Outbound) string {
	tag := detour.Tag()
	for {
		group, isGroup := detour.(adapter.OutboundGroup)
		if !isGroup {
			return tag
		}
		tag = group.Now()
		var loaded bool
		detour, loaded = outboundManager.Outbound(tag)
		if !loaded {
			return tag
		}
	}
}
