package group

import (
	"context"
	"maps"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.PreMatchOutboundGroup = (*URLTest)(nil)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.DashboardURLTestGroup   = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

const (
	dashboardURLTestLimit       = 12
	dashboardURLTestConcurrency = 4
)

var dashboardURLTestSlots = make(chan struct{}, dashboardURLTestConcurrency)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	baseTags                     []string
	providerSource               *groupProviderSource
	membership                   atomic.Pointer[groupOutboundSnapshot]
	stateAccess                  sync.RWMutex
	closed                       bool
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		baseTags:                     options.Outbounds,
		providerSource:               newGroupProviderSource(ctx, options.GroupCommonOption),
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(options.Outbounds) == 0 && len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, E.New("missing tags")
	}
	outbound.membership.Store(newGroupOutboundSnapshot(nil, nil))
	return outbound, nil
}

func (s *URLTest) snapshot() *groupOutboundSnapshot {
	return s.membership.Load()
}

func (s *URLTest) rebuildSnapshot(providerTag string) *groupOutboundSnapshot {
	tags := append([]string(nil), s.baseTags...)
	byTag := make(map[string]adapter.Outbound, len(tags))
	for _, tag := range tags {
		if detour, loaded := s.outbound.Outbound(tag); loaded && detour != nil {
			byTag[tag] = detour
		}
	}
	if s.providerSource.has() {
		_, members := s.providerSource.memberOutbounds(providerTag)
		occupied := make(map[string]struct{}, len(tags))
		for _, tag := range tags {
			occupied[tag] = struct{}{}
		}
		providerTags, renamed := renameProviderMembers(members, occupied)
		for _, member := range renamed {
			byTag[member.Tag()] = member
		}
		tags = append(tags, providerTags...)
	}
	return newGroupOutboundSnapshot(tags, byTag)
}

func (s *URLTest) Start() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return E.New("url-test is closed")
	}
	baseTags := append([]string(nil), s.baseTags...)
	s.stateAccess.Unlock()
	for i, tag := range baseTags {
		_, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
	}
	if s.providerSource.has() {
		if err := s.providerSource.register(s.onProviderUpdated); err != nil {
			return err
		}
	}
	snapshot := s.rebuildSnapshot("")
	outbounds := make([]adapter.Outbound, 0, len(snapshot.tags))
	for _, memberTag := range snapshot.tags {
		if detour := snapshot.outbounds[memberTag]; detour != nil {
			outbounds = append(outbounds, detour)
		}
	}
	s.membership.Store(snapshot)
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		s.providerSource.close()
		return err
	}
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		_ = group.Close()
		s.providerSource.close()
		return E.New("url-test is closed")
	}
	s.group = group
	s.stateAccess.Unlock()
	return nil
}

func (s *URLTest) PostStart() error {
	if group := s.groupRef(); group != nil {
		group.PostStart()
	}
	return nil
}

func (s *URLTest) Close() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return nil
	}
	s.closed = true
	group := s.group
	s.group = nil
	s.membership.Store(newGroupOutboundSnapshot(nil, nil))
	s.stateAccess.Unlock()
	// Provider unregistration can execute provider-owned synchronization and
	// must not run while URLTest's state lock is held.
	s.providerSource.close()
	// Start may fail before URLTestGroup is constructed (for example when
	// interval validation rejects the configuration).  common.Close invokes
	// Close through reflection and does not treat a typed nil pointer as an
	// empty close set, so guard the optional group explicitly.
	if group == nil {
		return nil
	}
	return common.Close(group)
}

func (s *URLTest) groupRef() *URLTestGroup {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	return s.group
}

func (s *URLTest) Now() string {
	if group := s.groupRef(); group != nil {
		if selected := group.selected(N.NetworkTCP); selected != nil {
			return selected.Tag()
		} else if selected := group.selected(N.NetworkUDP); selected != nil {
			return selected.Tag()
		}
	}
	// Surge's default cold start uses the first configured policy while the
	// initial test runs in the background. Keep the dashboard/current-policy
	// view consistent with the actual first-use fallback.
	if snapshot := s.snapshot(); snapshot != nil && len(snapshot.tags) > 0 {
		return snapshot.tags[0]
	}
	return ""
}

func (s *URLTest) All() []string {
	return s.snapshot().all()
}

func (s *URLTest) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	group := s.groupRef()
	if group == nil {
		return nil, adapter.PreMatchContinue
	}
	network := ""
	if metadata != nil {
		network = metadata.Network
	}
	var outbound adapter.Outbound
	selectionNetwork := network
	switch network {
	case N.NetworkTCP:
		outbound = group.selected(N.NetworkTCP)
	case N.NetworkUDP:
		outbound = group.selected(N.NetworkUDP)
	default:
		outbound = group.selected(N.NetworkTCP)
		if outbound == nil {
			outbound = group.selected(N.NetworkUDP)
		}
		selectionNetwork = N.NetworkTCP
	}
	if outbound == nil {
		outbound, _ = group.Select(selectionNetwork)
	}
	if outbound == nil {
		return nil, adapter.PreMatchContinue
	}
	return selectOutbound(outbound)
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	if group := s.groupRef(); group != nil {
		return group.URLTest(ctx)
	}
	return map[string]uint16{}, nil
}

// DashboardURLTest is the control-plane variant of URLTest. The configured
// URL-test scheduler may cover the complete catalog, but a panel refresh must
// use the shared sampled path instead of creating a full fan-out.
func (s *URLTest) DashboardURLTest(ctx context.Context) (map[string]uint16, error) {
	group := s.groupRef()
	if group == nil {
		return map[string]uint16{}, nil
	}
	return dashboardURLTestOutbounds(ctx, s.outbound, group.history, s.logger, group.OutboundsSnapshot(), group.link, group.profileRegistry), nil
}

func (s *URLTest) CheckOutbounds() {
	if group := s.groupRef(); group != nil {
		group.CheckOutbounds(s.ctx, true)
	}
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return E.New("outbound provider not found: ", tag)
	}
	s.stateAccess.Unlock()
	if !s.providerSource.has() {
		return E.New("outbound provider not found: ", tag)
	}
	if tag != "" && !s.providerSource.hasProvider(tag) {
		return E.New("outbound provider not found: ", tag)
	}
	snapshot := s.rebuildSnapshot(tag)
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return nil
	}
	group := s.group
	s.membership.Store(snapshot)
	s.stateAccess.Unlock()
	if group == nil {
		return nil
	}
	outbounds := make([]adapter.Outbound, 0, len(snapshot.tags))
	for _, memberTag := range snapshot.tags {
		if detour := snapshot.outbounds[memberTag]; detour != nil {
			outbounds = append(outbounds, detour)
		}
	}
	group.replaceOutbounds(outbounds)
	go group.CheckOutbounds(s.ctx, true)
	return nil
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.groupRef()
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		group.CheckOutbounds(ctx, true)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	group := s.groupRef()
	if group == nil {
		return nil, E.New("url-test group is not started")
	}
	group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = group.selected(N.NetworkTCP)
	case N.NetworkUDP:
		outbound = group.selected(N.NetworkUDP)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil {
		outbound, _ = group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	adapter.NoteRealOutbound(ctx, outbound)
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		group.profileRegistry.recordPassive(groupTCPPassiveProfileKey(outbound, network), true, 0, 0)
		return group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	group.profileRegistry.recordPassive(groupTCPPassiveProfileKey(outbound, network), false, 0, groupPassiveFailureTTL)
	key := historyKeyForOutbound(s.outbound, outbound, group.link, network)
	group.history.DeleteURLTestHistoryKey(key)
	return nil, err
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	group := s.groupRef()
	if group == nil {
		return nil, E.New("url-test group is not started")
	}
	group.Touch()
	outbound := group.selected(N.NetworkUDP)
	if outbound == nil {
		outbound, _ = group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	adapter.NoteRealOutbound(ctx, outbound)
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		group.profileRegistry.recordPassive(groupUDPProfileKey(outbound), true, 0, 0)
		return group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	// UDP failure is transport-scoped passive evidence. Do not erase the
	// authenticated TCP URL-test observation; suppress this member briefly and
	// let the next bounded test refresh the control-plane state.
	group.profileRegistry.recordPassive(groupUDPProfileKey(outbound), false, 0, groupPassiveFailureTTL)
	return nil, err
}

func (s *URLTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     atomic.Bool
	lastCheck                    atomic.Int64
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	profileRegistry              *nodeProfileRegistry
	releaseProfileRegistry       func()
	selectionAccess              sync.RWMutex
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	closed                       bool
	lastActive                   common.TypedValue[time.Time]
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	profileRegistry, releaseProfileRegistry := acquireGroupProfileRegistry(ctx, outboundManager)
	return &URLTestGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		profileRegistry:              profileRegistry,
		releaseProfileRegistry:       releaseProfileRegistry,
	}, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return
	}
	g.started = true
	g.lastActive.Store(time.Now())
	g.access.Unlock()
}

func (g *URLTestGroup) Touch() {
	g.access.Lock()
	if !g.started || g.closed {
		g.access.Unlock()
		return
	}
	lastCheck := g.lastCheck.Load()
	needsProbe := lastCheck == 0 || time.Since(time.Unix(0, lastCheck)) >= g.interval
	g.lastActive.Store(time.Now())
	if g.ticker != nil {
		g.access.Unlock()
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.access.Unlock()
	// pause.Manager is an external callback registry. Register outside the
	// group lock so a synchronous callback cannot re-enter Touch/Close.
	go g.loopCheck(ticker, g.close)
	callback := pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	g.access.Lock()
	if g.closed || g.ticker != ticker {
		g.access.Unlock()
		ticker.Stop()
		if callback != nil {
			g.pause.UnregisterCallback(callback)
		}
	} else {
		g.pauseCallback = callback
		g.access.Unlock()
	}
	if needsProbe {
		// Match Surge's cold start: the first configured member is usable
		// immediately; the complete test round runs in the background.
		go g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) Close() error {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return nil
	}
	g.closed = true
	ticker := g.ticker
	g.ticker = nil
	callback := g.pauseCallback
	g.pauseCallback = nil
	close(g.close)
	g.access.Unlock()
	if ticker != nil {
		ticker.Stop()
	}
	if callback != nil {
		g.pause.UnregisterCallback(callback)
	}
	if g.releaseProfileRegistry != nil {
		g.releaseProfileRegistry()
		g.releaseProfileRegistry = nil
	}
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	isUDP := N.NetworkName(network) == N.NetworkUDP
	g.selectionAccess.RLock()
	var selected adapter.Outbound
	switch network {
	case N.NetworkTCP:
		selected = g.selectedOutboundTCP
	case N.NetworkUDP:
		selected = g.selectedOutboundUDP
	}
	g.selectionAccess.RUnlock()
	var minDelay uint16
	var minOutbound adapter.Outbound
	if selected != nil {
		profile, loaded := groupTCPProfileSnapshot(g.profileRegistry, selected, g.link, network)
		if loaded && profile.success && groupTransportAvailable(g.profileRegistry, selected, network) {
			if g.containsOutbound(selected, network) {
				minOutbound = selected
				minDelay = profile.delay
			}
		} else if g.profileRegistry == nil {
			key := historyKeyForOutbound(g.outbound, selected, g.link, N.NetworkTCP)
			if history := g.history.LoadURLTestHistoryKey(key); history != nil && g.containsOutbound(selected, network) {
				minOutbound = selected
				minDelay = history.Delay
			}
		}
	}
	outbounds := g.OutboundsSnapshot()
	for _, detour := range outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		if isUDP && !groupUDPAvailable(g.profileRegistry, detour) {
			continue
		}
		profile, loaded := groupTCPProfileSnapshot(g.profileRegistry, detour, g.link, network)
		var delay uint16
		if loaded && profile.success && groupTransportAvailable(g.profileRegistry, detour, network) {
			delay = profile.delay
		} else if g.profileRegistry == nil {
			key := historyKeyForOutbound(g.outbound, detour, g.link, N.NetworkTCP)
			history := g.history.LoadURLTestHistoryKey(key)
			if history != nil {
				delay = history.Delay
			}
		}
		if delay == 0 {
			continue
		}
		if minDelay == 0 || uint32(minDelay) > uint32(delay)+uint32(g.tolerance) {
			minDelay = delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			if isUDP && !groupUDPAvailable(g.profileRegistry, detour) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) containsOutbound(selected adapter.Outbound, network string) bool {
	if selected == nil {
		return false
	}
	for _, detour := range g.OutboundsSnapshot() {
		if detour == selected || detour.Tag() == selected.Tag() {
			return common.Contains(detour.Network(), network)
		}
	}
	return false
}

func (g *URLTestGroup) selected(network string) adapter.Outbound {
	g.selectionAccess.RLock()
	defer g.selectionAccess.RUnlock()
	if network == N.NetworkUDP {
		return g.selectedOutboundUDP
	}
	return g.selectedOutboundTCP
}

func (g *URLTestGroup) OutboundsSnapshot() []adapter.Outbound {
	g.access.Lock()
	defer g.access.Unlock()
	return append([]adapter.Outbound(nil), g.outbounds...)
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker = nil
				callback := g.pauseCallback
				g.pauseCallback = nil
				g.access.Unlock()
				ticker.Stop()
				if callback != nil {
					g.pause.UnregisterCallback(callback)
				}
				return
			}
			g.access.Unlock()
			continue
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, true)
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	g.access.Lock()
	closed := g.closed
	g.access.Unlock()
	if closed {
		return map[string]uint16{}, nil
	}
	if g.checking.Swap(true) {
		return make(map[string]uint16), nil
	}
	defer g.checking.Store(false)
	result := urlTestOutbounds(ctx, g.outbound, g.history, g.logger, g.OutboundsSnapshot(), g.link, g.interval, force, false, 10, g.profileRegistry)
	g.lastCheck.Store(time.Now().UnixNano())
	g.performUpdateCheck()
	return result, nil
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestBatch struct {
	ctx       context.Context
	outbound  adapter.OutboundManager
	history   *urltest.HistoryStorage
	logger    log.Logger
	batch     *batch.Batch[any]
	checked   map[string]bool
	groups    []adapter.OutboundGroup
	access    sync.Mutex
	result    map[string]uint16
	dashboard bool
	profiles  *nodeProfileRegistry
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, interval, force, false, 10, existingGroupProfileRegistry(outboundManager))
}

// DashboardURLTestOutbounds follows Surge's control-plane rule: sample the
// most recently observed and stalest leaves, while nested Smart/Adaptive/URLTest
// groups keep ownership of their own bounded scheduler. It is intentionally
// separate from URLTestOutbounds so periodic full checks retain their contract.
func DashboardURLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string) map[string]uint16 {
	return dashboardURLTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, existingGroupProfileRegistry(outboundManager))
}

func dashboardURLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, profiles *nodeProfileRegistry) map[string]uint16 {
	leaves, dashboardGroups := collectDashboardOutbounds(outboundManager, outbounds)
	selectedLeaves := selectDashboardOutbounds(history, leaves, dashboardURLTestLimit, link)
	result := make(map[string]uint16)
	var resultAccess sync.Mutex
	if len(selectedLeaves) > 0 {
		maps.Copy(result, urlTestOutbounds(ctx, outboundManager, history, logger, selectedLeaves, link, 0, true, true, dashboardURLTestConcurrency, profiles))
	}
	groupBatch, _ := batch.New(ctx, batch.WithConcurrencyNum[any](dashboardURLTestConcurrency))
	for _, dashboardGroup := range dashboardGroups {
		group := dashboardGroup
		groupBatch.Go(group.Tag(), func() (any, error) {
			groupResult, err := group.DashboardURLTest(ctx)
			resultAccess.Lock()
			maps.Copy(result, groupResult)
			resultAccess.Unlock()
			return nil, err
		})
	}
	groupBatch.Wait()
	return result
}

func urlTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force, dashboard bool, concurrency int, profiles *nodeProfileRegistry) map[string]uint16 {
	if concurrency <= 0 {
		concurrency = 1
	}
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](concurrency))
	testBatch := &urlTestBatch{
		ctx:       ctx,
		outbound:  outboundManager,
		history:   history,
		logger:    logger,
		batch:     b,
		checked:   make(map[string]bool),
		result:    make(map[string]uint16),
		dashboard: dashboard,
		profiles:  profiles,
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		key := historyKeyForOutbound(outboundManager, outboundGroup, link, N.NetworkTCP)
		groupHistory := history.LoadURLTestHistoryKey(key)
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func collectDashboardOutbounds(outboundManager adapter.OutboundManager, outbounds []adapter.Outbound) ([]adapter.Outbound, []adapter.DashboardURLTestGroup) {
	visited := make(map[string]bool)
	leaves := make([]adapter.Outbound, 0, len(outbounds))
	groups := make([]adapter.DashboardURLTestGroup, 0)
	var walk func(adapter.Outbound)
	walk = func(detour adapter.Outbound) {
		if detour == nil || visited[detour.Tag()] {
			return
		}
		visited[detour.Tag()] = true
		if dashboardGroup, ok := detour.(adapter.DashboardURLTestGroup); ok {
			groups = append(groups, dashboardGroup)
			return
		}
		if outboundGroup, ok := detour.(adapter.OutboundGroup); ok {
			for _, childTag := range outboundGroup.All() {
				child, loaded := outboundManager.Outbound(childTag)
				if loaded {
					walk(child)
				}
			}
			return
		}
		leaves = append(leaves, detour)
	}
	for _, detour := range outbounds {
		walk(detour)
	}
	return leaves, groups
}

func selectDashboardOutbounds(history *urltest.HistoryStorage, outbounds []adapter.Outbound, limit int, probeLinks ...string) []adapter.Outbound {
	if limit <= 0 || len(outbounds) <= limit {
		return outbounds
	}
	type candidate struct {
		outbound adapter.Outbound
		history  *adapter.URLTestHistory
	}
	items := make([]candidate, 0, len(outbounds))
	for _, outbound := range outbounds {
		var itemHistory *adapter.URLTestHistory
		if history != nil {
			if len(probeLinks) > 0 && probeLinks[0] != "" {
				itemHistory = history.LoadURLTestHistoryKey(urltest.KeyForOutbound(outbound, probeLinks[0], N.NetworkTCP))
			} else {
				itemHistory = history.LoadLatestURLTestHistoryForOutbound(outbound, N.NetworkTCP)
			}
		}
		items = append(items, candidate{outbound: outbound, history: itemHistory})
	}
	recent := append([]candidate(nil), items...)
	oldest := append([]candidate(nil), items...)
	sort.SliceStable(recent, func(i, j int) bool {
		if recent[i].history == nil && recent[j].history == nil {
			return false
		}
		if recent[i].history == nil {
			return false
		}
		if recent[j].history == nil {
			return true
		}
		return recent[i].history.Time.After(recent[j].history.Time)
	})
	sort.SliceStable(oldest, func(i, j int) bool {
		if oldest[i].history == nil && oldest[j].history == nil {
			return false
		}
		if oldest[i].history == nil {
			return true
		}
		if oldest[j].history == nil {
			return false
		}
		return oldest[i].history.Time.Before(oldest[j].history.Time)
	})
	selected := make([]adapter.Outbound, 0, limit)
	seen := make(map[string]struct{}, limit)
	appendCandidate := func(item candidate) {
		if len(selected) >= limit {
			return
		}
		if _, exists := seen[item.outbound.Tag()]; exists {
			return
		}
		seen[item.outbound.Tag()] = struct{}{}
		selected = append(selected, item.outbound)
	}
	// Always reserve at least one slot for the most recent target-specific
	// observation. With a one-entry dashboard budget, limit/2 would be zero
	// and the stale/untested pass could select an unrelated target instead.
	recentCount := (limit + 1) / 2
	for _, item := range recent[:min(len(recent), recentCount)] {
		appendCandidate(item)
	}
	for _, item := range oldest {
		appendCandidate(item)
	}
	for _, item := range items {
		appendCandidate(item)
	}
	return selected
}

func runDashboardLeafProbe(ctx context.Context, probe func(context.Context) (uint16, error)) (uint16, error) {
	select {
	case dashboardURLTestSlots <- struct{}{}:
		defer func() { <-dashboardURLTestSlots }()
		return probe(ctx)
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case *URLTest:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nestedResult, _ := nested.group.urlTest(b.ctx, force)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.DashboardURLTestGroup:
			// Do not recursively expand Smart/Adaptive candidates when they are
			// nested below another group. Their dashboard method owns endpoint
			// deduplication and the bounded sample budget.
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				nestedResult, nestedErr := nested.DashboardURLTest(b.ctx)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nestedErr
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			key := historyKeyForOutbound(b.outbound, detour, link, N.NetworkTCP)
			endpointKey, profileKey := groupTCPProfileKey(detour, link)
			checkedKey := tag
			if b.profiles != nil {
				checkedKey = "profile\x00" + profileKey
				if !force {
					if profile, loaded := b.profiles.snapshot(profileKey); loaded && time.Now().Before(profile.nextProbeAt) {
						if profile.success {
							b.access.Lock()
							b.result[tag] = profile.delay
							b.access.Unlock()
						} else {
							b.history.DeleteURLTestHistoryKey(key)
						}
						continue
					}
				}
			} else {
				history := b.history.LoadURLTestHistoryKey(key)
				if !force && history != nil && time.Since(history.Time) < interval {
					continue
				}
			}
			if b.checked[checkedKey] {
				continue
			}
			b.checked[checkedKey] = true
			b.batch.Go(tag, func() (any, error) {
				testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
				defer cancel()
				var testResult urlTestResult
				if b.profiles != nil {
					probe := func(probeCtx context.Context) (uint16, error) {
						return urltest.URLTest(probeCtx, link, detour)
					}
					if b.dashboard {
						testResult.delay, testResult.err = runDashboardLeafProbe(testCtx, func(probeCtx context.Context) (uint16, error) {
							delay, probeErr, _ := b.profiles.runProbeMode(probeCtx, endpointKey, profileKey, C.TCPTimeout, interval, force, probe)
							return delay, probeErr
						})
					} else {
						testResult.delay, testResult.err, _ = b.profiles.runProbeMode(testCtx, endpointKey, profileKey, C.TCPTimeout, interval, force, probe)
					}
				} else if b.dashboard {
					testResult.delay, testResult.err = runDashboardLeafProbe(testCtx, func(probeCtx context.Context) (uint16, error) {
						return urltest.URLTest(probeCtx, link, detour)
					})
				} else {
					testChan := make(chan urlTestResult, 1)
					go func() {
						delay, testErr := urltest.URLTest(testCtx, link, detour)
						testChan <- urlTestResult{delay, testErr}
					}()
					select {
					case testResult = <-testChan:
					case <-testCtx.Done():
						testResult.err = testCtx.Err()
					}
				}
				if testResult.err != nil {
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.history.DeleteURLTestHistoryKey(key)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistoryKey(key, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) replaceOutbounds(outbounds []adapter.Outbound) {
	g.access.Lock()
	g.outbounds = append([]adapter.Outbound(nil), outbounds...)
	g.selectionAccess.Lock()
	g.selectedOutboundTCP = remapGroupSelection(g.selectedOutboundTCP, outbounds)
	g.selectedOutboundUDP = remapGroupSelection(g.selectedOutboundUDP, outbounds)
	g.selectionAccess.Unlock()
	g.access.Unlock()
}

func remapGroupSelection(selected adapter.Outbound, outbounds []adapter.Outbound) adapter.Outbound {
	if selected == nil {
		return nil
	}
	// Prefer the same display tag only when it still identifies the same
	// endpoint. A provider can reuse a suffix for a different node after a
	// refresh, so tag equality alone is not safe.
	for _, candidate := range outbounds {
		if candidate != nil && candidate.Tag() == selected.Tag() && sameOutboundIdentity(selected, candidate) {
			return candidate
		}
	}
	// If the suffix changed, keep the selection attached to the same endpoint.
	for _, candidate := range outbounds {
		if sameOutboundIdentity(selected, candidate) {
			return candidate
		}
	}
	return nil
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	var updated bool
	currentTCP := g.selected(N.NetworkTCP)
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (currentTCP == nil || (exists && outbound != currentTCP)) {
		g.selectionAccess.Lock()
		if g.selectedOutboundTCP != nil {
			updated = true
		}
		g.selectedOutboundTCP = outbound
		g.selectionAccess.Unlock()
	}
	currentUDP := g.selected(N.NetworkUDP)
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (currentUDP == nil || (exists && outbound != currentUDP)) {
		g.selectionAccess.Lock()
		if g.selectedOutboundUDP != nil {
			updated = true
		}
		g.selectedOutboundUDP = outbound
		g.selectionAccess.Unlock()
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
}
