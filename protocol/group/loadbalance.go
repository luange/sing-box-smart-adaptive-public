package group

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
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
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/net/publicsuffix"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.LoadBalanceOutboundOptions](registry, C.TypeLoadBalance, NewLoadBalance)
}

var (
	_ adapter.PreMatchOutboundGroup   = (*LoadBalance)(nil)
	_ adapter.InterfaceUpdateListener = (*LoadBalance)(nil)
	_ adapter.DashboardURLTestGroup   = (*LoadBalance)(nil)
)

const (
	// StrategyRandom picks uniformly from the currently available members per
	// connection. The Surge-compatible default is StrategyConsistentHashing
	// (per-destination host affinity); StrategyRandom must be requested
	// explicitly.
	StrategyRandom            = "random"
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"
)

type LoadBalance struct {
	outbound.Adapter
	ctx                          context.Context
	router                       adapter.Router
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	baseTags                     []string
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	ttl                          time.Duration
	group                        *LoadBalanceGroup
	interruptExternalConnections bool
	strategy                     string
	persistent                   bool
	providerSource               *groupProviderSource
	stateAccess                  sync.RWMutex
	closed                       bool
	cancel                       context.CancelFunc
}

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.LoadBalanceOutboundOptions) (adapter.Outbound, error) {
	strategy := options.Strategy
	if strategy == "" {
		// Surge's load-balance default is per-destination host affinity (the
		// same target host keeps the same outbound), not per-connection random.
		strategy = StrategyConsistentHashing
	}
	switch strategy {
	case StrategyRandom, StrategyRoundRobin, StrategyConsistentHashing, StrategyStickySessions:
	default:
		return nil, E.New("load-balance strategy not found: ", strategy)
	}
	outbound := &LoadBalance{
		Adapter:                      outbound.NewAdapter(C.TypeLoadBalance, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		router:                       router,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		baseTags:                     append([]string(nil), options.Outbounds...),
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		ttl:                          time.Duration(options.TTL),
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
		strategy:                     strategy,
		persistent:                   options.Persistent,

		providerSource: newGroupProviderSource(ctx, options.GroupCommonOption),
	}
	return outbound, nil
}

func (s *LoadBalance) Start() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return E.New("load-balance is closed")
	}
	baseTags := append([]string(nil), s.baseTags...)
	s.stateAccess.Unlock()
	if len(baseTags) == 0 && !s.providerSource.has() {
		return E.New("missing outbound and provider tags")
	}
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
	outbounds := s.rebuildOutbounds("")
	if len(outbounds) == 0 && len(baseTags) == 0 {
		detour, _ := s.outbound.Outbound("Compatible")
		if detour != nil {
			outbounds = append(outbounds, detour)
		}
	}
	if len(outbounds) == 0 {
		s.providerSource.close()
		return E.New("missing load-balance outbounds")
	}
	group, err := NewLoadBalanceGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.idleTimeout, s.ttl, s.interruptExternalConnections, s.strategy, s.persistent)
	if err != nil {
		s.providerSource.close()
		return err
	}
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		_ = group.Close()
		s.providerSource.close()
		return E.New("load-balance closed during start")
	}
	s.group = group
	s.stateAccess.Unlock()
	return nil
}

func (s *LoadBalance) PostStart() error {
	if group := s.groupRef(); group != nil {
		group.PostStart()
	}
	return nil
}

func (s *LoadBalance) Close() error {
	s.stateAccess.Lock()
	if s.closed {
		s.stateAccess.Unlock()
		return nil
	}
	s.closed = true
	group := s.group
	s.group = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.stateAccess.Unlock()
	s.providerSource.close()
	return common.Close(group)
}

func (s *LoadBalance) groupRef() *LoadBalanceGroup {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	return s.group
}

func (s *LoadBalance) Now() string {
	group := s.groupRef()
	if group == nil {
		return ""
	}
	return group.LastUsedTag()
}

func (s *LoadBalance) All() []string {
	group := s.groupRef()
	if group == nil {
		return nil
	}
	var all []string
	for _, outbound := range group.outboundsSnapshot() {
		all = append(all, outbound.Tag())
	}
	return all
}

func (s *LoadBalance) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	group := s.groupRef()
	if group == nil {
		return nil, adapter.PreMatchContinue
	}
	group.Touch()
	var (
		preMatchOutbound adapter.Outbound
		preMatchAction   adapter.PreMatchAction
	)
	group.UnwrapPreMatch(metadata, func(outbound adapter.Outbound) bool {
		preMatchOutbound, preMatchAction = selectOutbound(outbound)
		return preMatchOutbound != nil
	})
	return preMatchOutbound, preMatchAction
}

func (s *LoadBalance) URLTest(ctx context.Context) (map[string]uint16, error) {
	if group := s.groupRef(); group != nil {
		return group.URLTest(ctx)
	}
	return map[string]uint16{}, nil
}

// DashboardURLTest keeps a panel refresh on the same bounded sampled path as
// the other automatic groups.  It must not turn a nested load-balance group
// into a full provider fan-out.
func (s *LoadBalance) DashboardURLTest(ctx context.Context) (map[string]uint16, error) {
	group := s.groupRef()
	if group == nil {
		return map[string]uint16{}, nil
	}
	return dashboardURLTestOutbounds(ctx, s.outbound, group.history, s.logger, group.outboundsSnapshot(), group.link, group.profileRegistry), nil
}

func (s *LoadBalance) CheckOutbounds() {
	if group := s.groupRef(); group != nil {
		group.CheckOutbounds(true)
	}
}

func (s *LoadBalance) InterfaceUpdated(_ context.Context) {
	group := s.groupRef()
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go group.CheckOutbounds(true)
}

func (s *LoadBalance) isGroupActive() bool {
	group := s.groupRef()
	if group == nil {
		return false
	}
	group.access.Lock()
	started := group.started
	idleTimeout := group.idleTimeout
	group.access.Unlock()
	return started && time.Since(group.lastActive.Load()) <= idleTimeout
}

func (s *LoadBalance) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	group := s.groupRef()
	if group == nil {
		return nil, E.New("load-balance is not started")
	}
	group.Touch()
	metadata := loadBalanceMetadataWithNetwork(adapter.ContextFrom(ctx), network)
	outbound := group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), network) {
		return nil, E.New("missing supported outbound")
	}
	adapter.NoteRealOutbound(ctx, outbound)
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		group.profileRegistry.recordPassive(groupTCPPassiveProfileKey(outbound, network), true, 0, 0)
		return group.interruptGroup.NewConnEx(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	group.profileRegistry.recordPassive(groupTCPPassiveProfileKey(outbound, network), false, 0, groupPassiveFailureTTL)
	key := historyKeyForOutbound(s.outbound, outbound, group.link, network)
	group.history.DeleteURLTestHistoryKey(key)
	go group.CheckOutbounds(true)
	return nil, err
}

func (s *LoadBalance) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	group := s.groupRef()
	if group == nil {
		return nil, E.New("load-balance is not started")
	}
	group.Touch()
	metadata := loadBalanceMetadataWithNetwork(adapter.ContextFrom(ctx), N.NetworkUDP)
	outbound := group.Unwrap(metadata, true)
	if outbound == nil || !common.Contains(outbound.Network(), N.NetworkUDP) {
		return nil, E.New("missing supported outbound")
	}
	adapter.NoteRealOutbound(ctx, outbound)
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		group.profileRegistry.recordPassive(groupUDPProfileKey(outbound), true, 0, 0)
		return group.interruptGroup.NewPacketConnEx(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	// UDP failure is transport-scoped passive evidence. Keep the TCP URL-test
	// history intact; only suppress this endpoint for a short UDP cooldown and
	// let the normal bounded check refresh its control-plane view.
	group.profileRegistry.recordPassive(groupUDPProfileKey(outbound), false, 0, groupPassiveFailureTTL)
	go group.CheckOutbounds(true)
	return nil, err
}

func loadBalanceMetadataWithNetwork(metadata *adapter.InboundContext, network string) *adapter.InboundContext {
	network = N.NetworkName(network)
	if metadata == nil {
		return &adapter.InboundContext{Network: network}
	}
	if N.NetworkName(metadata.Network) == network {
		return metadata
	}
	copyMetadata := *metadata
	copyMetadata.Network = network
	return &copyMetadata
}

func (s *LoadBalance) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *LoadBalance) onProviderUpdated(tag string) error {
	s.stateAccess.RLock()
	closed := s.closed
	group := s.group
	s.stateAccess.RUnlock()
	if closed || group == nil {
		return nil
	}
	if tag != "" && !s.providerSource.hasProvider(tag) {
		return E.New("outbound provider not found: ", tag)
	}
	outbounds := s.rebuildOutbounds(tag)
	if len(outbounds) == 0 {
		return E.New("load-balance provider update removed all outbounds")
	}
	group.replaceOutbounds(outbounds)
	if s.isGroupActive() {
		group.access.Lock()
		if group.ticker != nil {
			group.ticker.Reset(group.interval)
		}
		group.access.Unlock()
		ctx, cancel := context.WithCancel(s.ctx)
		s.stateAccess.Lock()
		if s.cancel != nil {
			s.cancel()
		}
		s.cancel = cancel
		s.stateAccess.Unlock()
		s.URLTest(ctx)
	}
	return nil
}

func (s *LoadBalance) rebuildOutbounds(updatedProvider string) []adapter.Outbound {
	s.stateAccess.RLock()
	baseTags := append([]string(nil), s.baseTags...)
	s.stateAccess.RUnlock()
	outbounds := make([]adapter.Outbound, 0, len(baseTags))
	occupied := make(map[string]struct{}, len(baseTags))
	for _, tag := range baseTags {
		if detour, loaded := s.outbound.Outbound(tag); loaded && detour != nil {
			outbounds = append(outbounds, detour)
			occupied[tag] = struct{}{}
		}
	}
	if s.providerSource.has() {
		_, members := s.providerSource.memberOutbounds(updatedProvider)
		_, renamed := renameProviderMembers(members, occupied)
		outbounds = append(outbounds, renamed...)
	}
	return outbounds
}

type outboundMatcher = func(outbound adapter.Outbound) bool

type strategyFn = func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound

type LoadBalanceGroup struct {
	ctx context.Context
	// router                       adapter.Router
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	idleTimeout                  time.Duration
	ttl                          time.Duration
	persistent                   bool
	history                      *urltest.HistoryStorage
	checking                     atomic.Bool
	lastCheck                    atomic.Int64
	fallbackIdx                  atomic.Uint32
	fallbackAccess               sync.Mutex
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	outboundsAccess              sync.RWMutex
	profileRegistry              *nodeProfileRegistry
	releaseProfileRegistry       func()
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	closed                       bool
	lastActive                   common.TypedValue[time.Time]
	strategyFn                   strategyFn
	// snapshotCache is rebuilt only in replaceOutbounds; strategy functions
	// read it per dial without paying a slice copy.
	snapshotCache []adapter.Outbound
	lastUsedTag   atomic.Pointer[string]
}

// LastUsedTag reports the member the strategy last handed out, for the
// dashboard "now" view of a group that has no single selected outbound.
func (g *LoadBalanceGroup) LastUsedTag() string {
	if tag := g.lastUsedTag.Load(); tag != nil {
		return *tag
	}
	return ""
}

func NewLoadBalanceGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, idleTimeout time.Duration, ttl time.Duration, interruptExternalConnections bool, strategy string, persistent bool) (*LoadBalanceGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if ttl == 0 {
		ttl = time.Minute * 10
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	profileRegistry, releaseProfileRegistry := acquireGroupProfileRegistry(ctx, outboundManager)
	loadBalanceGroup := &LoadBalanceGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		snapshotCache:                append([]adapter.Outbound(nil), outbounds...),
		link:                         link,
		interval:                     interval,
		idleTimeout:                  idleTimeout,
		ttl:                          ttl,
		persistent:                   persistent,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		profileRegistry:              profileRegistry,
		releaseProfileRegistry:       releaseProfileRegistry,
	}
	if persistent {
		// Surge's persistent mode is host-affinity over the currently available
		// set.  It takes precedence over the legacy per-connection strategy.
		loadBalanceGroup.strategyFn = strategyPersistentHashing(loadBalanceGroup, link)
	} else {
		switch strategy {
		case StrategyRandom:
			loadBalanceGroup.strategyFn = strategyRandom(loadBalanceGroup, link)
		case StrategyRoundRobin:
			loadBalanceGroup.strategyFn = strategyRoundRobin(loadBalanceGroup, link)
		case StrategyConsistentHashing:
			loadBalanceGroup.strategyFn = strategyConsistentHashing(loadBalanceGroup, link)
		case StrategyStickySessions:
			loadBalanceGroup.strategyFn = strategyStickySessions(loadBalanceGroup, link)
		}
	}
	return loadBalanceGroup, nil
}

func (g *LoadBalanceGroup) PostStart() {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return
	}
	g.started = true
	g.lastActive.Store(time.Now())
	g.access.Unlock()
}

func (g *LoadBalanceGroup) Touch() {
	lastCheck := g.lastCheck.Load()
	needsProbe := lastCheck == 0 || time.Since(time.Unix(0, lastCheck)) >= g.interval
	g.access.Lock()
	if !g.started || g.closed {
		g.access.Unlock()
		return
	}
	g.lastActive.Store(time.Now())
	if g.ticker != nil {
		g.access.Unlock()
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.access.Unlock()
	// RegisterTicker is an external callback registry; do not call it while
	// holding the group lock. A concurrent Close can win this race, in which
	// case the callback is immediately unregistered below.
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
		// Surge uses the first configured member immediately and evaluates the
		// group in the background on first use.  Do not block the first user
		// connection on a full catalog probe.
		go g.CheckOutbounds(false)
	}
}

func (g *LoadBalanceGroup) Close() error {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return nil
	}
	g.closed = true
	g.started = false
	ticker := g.ticker
	callback := g.pauseCallback
	g.ticker = nil
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

func (g *LoadBalanceGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		g.access.Lock()
		closed := g.closed
		g.access.Unlock()
		if closed {
			return
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker != ticker {
				g.access.Unlock()
				return
			}
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
		g.CheckOutbounds(false)
	}
}

func (g *LoadBalanceGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

func (g *LoadBalanceGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	// A caller-visible manual test is an explicit full round.  Background
	// checks use CheckOutbounds(false), which preserves fresh history and only
	// refreshes expired members.
	return g.urlTest(ctx, true)
}

func (g *LoadBalanceGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	g.access.Lock()
	closed := g.closed
	g.access.Unlock()
	if closed {
		return result, nil
	}
	if g.checking.Swap(true) {
		return result, nil
	}
	defer g.checking.Store(false)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.outboundsSnapshot() {
		tag := detour.Tag()
		realTag := RealTag(g.outbound, detour)
		endpointKey, profileKey := groupTCPProfileKey(detour, g.link)
		if checked[profileKey] {
			continue
		}
		key := historyKeyForOutbound(g.outbound, detour, g.link, N.NetworkTCP)
		if !force {
			if g.profileRegistry != nil {
				if profile, loaded := g.profileRegistry.snapshot(profileKey); loaded && time.Now().Before(profile.nextProbeAt) {
					if profile.success {
						resultAccess.Lock()
						result[tag] = profile.delay
						resultAccess.Unlock()
					} else {
						g.history.DeleteURLTestHistoryKey(key)
					}
					continue
				}
			} else if history := g.history.LoadURLTestHistoryKey(key); history != nil && time.Since(history.Time) < g.interval {
				continue
			}
		}
		checked[profileKey] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
			defer cancel()
			var t uint16
			var err error
			if g.profileRegistry != nil {
				t, err, _ = g.profileRegistry.runProbeMode(testCtx, endpointKey, profileKey, C.TCPTimeout, g.interval, force, func(probeCtx context.Context) (uint16, error) {
					return urltest.URLTest(probeCtx, g.link, p)
				})
			} else {
				t, err = urltest.URLTest(testCtx, g.link, p)
			}
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.history.DeleteURLTestHistoryKey(key)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.history.StoreURLTestHistoryKey(key, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	g.lastCheck.Store(time.Now().UnixNano())
	return result, nil
}

// outboundsSnapshot returns the cached member list. Callers must treat it as
// read-only; the slice is shared and only replaced wholesale in
// replaceOutbounds.
func (g *LoadBalanceGroup) outboundsSnapshot() []adapter.Outbound {
	g.outboundsAccess.RLock()
	defer g.outboundsAccess.RUnlock()
	if g.snapshotCache != nil {
		return g.snapshotCache
	}
	return g.outbounds
}

func (g *LoadBalanceGroup) replaceOutbounds(outbounds []adapter.Outbound) {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return
	}
	g.access.Unlock()
	g.outboundsAccess.Lock()
	g.snapshotCache = append([]adapter.Outbound(nil), outbounds...)
	g.outbounds = g.snapshotCache
	g.outboundsAccess.Unlock()
}

func (g *LoadBalanceGroup) Unwrap(metadata *adapter.InboundContext, touch bool) adapter.Outbound {
	outbound := g.strategyFn(metadata, touch, nil)
	if outbound != nil {
		tag := outbound.Tag()
		g.lastUsedTag.Store(&tag)
	}
	return outbound
}

func (g *LoadBalanceGroup) UnwrapPreMatch(metadata *adapter.InboundContext, matcher outboundMatcher) adapter.Outbound {
	return g.strategyFn(metadata, true, matcher)
}

// AliveForTestUrl trusts a member only while its last benchmark is fresh
// (within the check interval). A stale entry describes a node that may have
// died since; Surge re-benchmarks before trusting it again. Untested members
// are not alive here — strategies keep their own recovery fallbacks.
func (g *LoadBalanceGroup) AliveForTestUrl(proxy adapter.Outbound, network ...string) bool {
	if g.profileRegistry != nil {
		return groupProfileBaselineAlive(g.profileRegistry, proxy, g.link, g.alivenessWindow(), network...)
	}
	key := historyKeyForOutbound(g.outbound, proxy, g.link, N.NetworkTCP)
	if history := g.history.LoadURLTestHistoryKey(key); history != nil {
		// A zero Time never occurs in production (StoreURLTestHistoryKey stamps
		// now); treat it as plain tested for hand-built storages.
		return history.Time.IsZero() || time.Since(history.Time) < g.alivenessWindow()
	}
	return false
}

func (g *LoadBalanceGroup) memberAvailable(proxy adapter.Outbound, metadata *adapter.InboundContext) bool {
	var network string
	if metadata != nil {
		network = metadata.Network
	}
	if !g.AliveForTestUrl(proxy, network) {
		return false
	}
	if !groupTransportAvailable(g.profileRegistry, proxy, network) {
		return false
	}
	return true
}

func (g *LoadBalanceGroup) alivenessWindow() time.Duration {
	if g.interval > 0 {
		return g.interval
	}
	return C.DefaultURLTestInterval
}

func (g *LoadBalanceGroup) nextFallback(touch bool, matcher outboundMatcher) adapter.Outbound {
	g.fallbackAccess.Lock()
	defer g.fallbackAccess.Unlock()
	outbounds := g.outboundsSnapshot()
	length := len(outbounds)
	if length == 0 {
		return nil
	}
	nextIndex := g.fallbackIdx.Load()
	if matcher == nil || touch {
		g.fallbackIdx.Store(nextIndex + 1)
	}
	outbound := outbounds[int(nextIndex)%length]
	if matcher != nil && !matcher(outbound) {
		return nil
	}
	return outbound
}

// strategyRandom implements Surge's default load-balance behavior: choose
// uniformly from the latest successful test set. If every member is
// unavailable or untested, all members remain candidates so the group can
// recover instead of becoming a hard reject policy.
func strategyRandom(g *LoadBalanceGroup, _ string) strategyFn {
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		_ = metadata
		_ = touch
		outbounds := g.outboundsSnapshot()
		if len(outbounds) == 0 {
			return nil
		}
		available := make([]adapter.Outbound, 0, len(outbounds))
		for _, proxy := range outbounds {
			if !g.memberAvailable(proxy, metadata) {
				continue
			}
			if matcher != nil && !matcher(proxy) {
				continue
			}
			available = append(available, proxy)
		}
		if len(available) == 0 {
			for _, proxy := range outbounds {
				if matcher == nil || matcher(proxy) {
					available = append(available, proxy)
				}
			}
		}
		if len(available) == 0 {
			return nil
		}
		return available[rand.Intn(len(available))]
	}
}

func getKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}

	var metadataHost string
	if metadata.Destination.IsDomain() {
		metadataHost = metadata.Destination.Fqdn
	} else if metadata.SniffHost != "" {
		metadataHost = metadata.SniffHost
	} else {
		metadataHost = metadata.Domain
	}

	if metadataHost != "" {
		// ip host
		if ip := net.ParseIP(metadataHost); ip != nil {
			return metadataHost
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadataHost); err == nil {
			return etld
		}
	}

	var destinationAddr netip.Addr
	if len(metadata.DestinationAddresses) > 0 {
		destinationAddr = metadata.DestinationAddresses[0]
	} else {
		destinationAddr = metadata.Destination.Addr
	}

	if !destinationAddr.IsValid() {
		return ""
	}

	return destinationAddr.String()
}

func getTargetHostKey(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	var host string
	if metadata.Destination.IsDomain() {
		host = metadata.Destination.Fqdn
	} else if metadata.SniffHost != "" {
		host = metadata.SniffHost
	} else {
		host = metadata.Domain
	}
	if host != "" {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return getKey(metadata)
}

func getKeyWithSrcAndDst(metadata *adapter.InboundContext) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.Source.Addr.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

func strategyRoundRobin(g *LoadBalanceGroup, url string) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		_ = metadata
		_ = url
		idxMutex.Lock()
		defer idxMutex.Unlock()

		outbounds := g.outboundsSnapshot()
		length := len(outbounds)
		if length == 0 {
			return nil
		}
		idx %= length
		for offset := 0; offset < length; offset++ {
			id := (idx + offset) % length
			proxy := outbounds[id]
			if g.memberAvailable(proxy, metadata) {
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				if touch {
					idx = (id + 1) % length
				}
				return proxy
			}
		}

		return g.nextFallback(touch, matcher)
	}
}

func strategyConsistentHashing(g *LoadBalanceGroup, url string) strategyFn {
	return strategyHashing(g, url, false)
}

func strategyPersistentHashing(g *LoadBalanceGroup, url string) strategyFn {
	return strategyHashing(g, url, true)
}

func strategyHashing(g *LoadBalanceGroup, url string, fullHost bool) strategyFn {
	maxRetry := 5
	hash := maphash.NewHasher[string]()
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		_ = touch
		_ = url
		outbounds := g.outboundsSnapshot()
		if len(outbounds) == 0 {
			return nil
		}
		keyString := getKey(metadata)
		if fullHost {
			keyString = getTargetHostKey(metadata)
		}
		key := hash.Hash(keyString)
		buckets := int32(len(outbounds))
		for i := 0; i < maxRetry; i++ {
			idx := jumpHash(key, buckets)
			proxy := outbounds[idx]
			if g.memberAvailable(proxy, metadata) {
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				return proxy
			}
			// A golden-ratio stride guarantees a different probe sequence per
			// retry; key+1 can re-select the same dead bucket.
			key += uint64(i+1) * 0x9e3779b97f4a7c15
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range outbounds {
			if g.memberAvailable(proxy, metadata) {
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				return proxy
			}
		}

		return g.nextFallback(touch, matcher)
	}
}

func strategyStickySessions(g *LoadBalanceGroup, url string) strategyFn {
	return strategyStickySessionsWithIndex(g, func(key uint64, length int) int {
		return int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
	})
}

func strategyStickySessionsWithIndex(g *LoadBalanceGroup, selectIndex func(key uint64, length int) int) strategyFn {
	maxRetry := 5
	// Store the selected endpoint identity, never its position in the current
	// member slice. Provider refreshes routinely reorder or remove members; an
	// index would silently turn a session pinned to A into a session pinned to B.
	lruCache := common.Must1(freelru.New[uint64, adapter.SelectedRecord](1000, maphash.NewHasher[uint64]().Hash32, true))
	lruCache.SetLifetime(g.ttl)
	hash := maphash.NewHasher[string]()
	return func(metadata *adapter.InboundContext, touch bool, matcher outboundMatcher) adapter.Outbound {
		_ = touch
		key := hash.Hash(getKeyWithSrcAndDst(metadata))
		outbounds := g.outboundsSnapshot()
		length := len(outbounds)
		if length == 0 {
			return nil
		}
		var cachedRecord adapter.SelectedRecord
		var has bool
		if matcher == nil {
			cachedRecord, has = lruCache.Get(key)
		} else {
			cachedRecord, has = lruCache.Peek(key)
		}
		if has {
			// Runtime affinity is credential-sensitive. If the authenticated
			// member disappeared during a provider refresh, treat the mapping as
			// a miss and run the strategy again instead of silently moving the
			// session to another credential on the same network path.
			if preferred := resolveStickySessionRecord(outbounds, cachedRecord); preferred != nil && g.memberAvailable(preferred, metadata) {
				if matcher != nil {
					if !matcher(preferred) {
						return nil
					}
					lruCache.Get(key)
				}
				return preferred
			}
		}

		idx := selectIndex(key, length)
		for i := 0; i < maxRetry; i++ {
			idx %= length
			proxy := outbounds[idx]
			if g.memberAvailable(proxy, metadata) {
				lruCache.Add(key, selectedRecordForOutbound(proxy))
				if matcher != nil && !matcher(proxy) {
					return nil
				}
				return proxy
			}
			idx = selectIndex(key, length)
		}
		fbIdx := int(jumpHash(key, int32(length)))
		matched := matcher == nil || matcher(outbounds[fbIdx])
		lruCache.Add(key, selectedRecordForOutbound(outbounds[fbIdx]))
		if !matched {
			return nil
		}
		return outbounds[fbIdx]
	}
}
