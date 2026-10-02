//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dnsmux"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	defaultListenPort      = 65532
	androidTetheringDNSUID = 1052
	dnsModeHijack          = "hijack"
	dnsModeOff             = "off"
)

var defaultRedirectIPv4 = netip.MustParsePrefix("127.128.0.0/9")

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.EBPFInboundOptions](registry, C.TypeEBPF, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx                context.Context
	router             adapter.Router
	logger             log.ContextLogger
	networkManager     adapter.NetworkManager
	listenOptions      option.ListenOptions
	cgroupPath         string
	listener4          *listener.Listener
	listener6          *listener.Listener
	udpNat             *udpnat.Service
	dnsMux             *dnsmux.Service
	backend            *ECommon.Backend
	protectRegistered  bool
	listenPort         uint16
	enableTCP          bool
	enableUDP          bool
	dnsMode            string
	redirectIPv4       netip.Prefix
	redirectIPv6       netip.Prefix
	policy             ECommon.Policy
	localRoutes        []*localRoute
	sharedOptions      option.EBPFSharedNetworkOptions
	sharedNetwork      *sharedNetwork
	offloadOptions     option.EBPFOutboundOffloadOptions
	outboundCoord      *outboundCoordinator
	backendAccess      sync.RWMutex
	closeAccess        sync.Mutex
	statsCancel        context.CancelFunc
	statsDone          chan struct{}
	dnsObserveCancel   context.CancelFunc
	dnsObserveDone     chan struct{}
	udpCleanupInterval time.Duration
	udpCleanupCancel   context.CancelFunc
	udpCleanupDone     chan struct{}
	udpSessionCapacity uint32
	dnsSessionCapacity uint32

	bypassRuleSetAccess    sync.Mutex
	bypassRuleSet          []adapter.RuleSet
	bypassRuleSetCallbacks []*list.Element[adapter.RuleSetUpdateCallback]
	bypassRuleSetStarted   bool
	// promotedBypass: learn/route/prefill → TC /32 (addr → expire). Gateway high hit-rate path.
	promotedBypass map[netip.Addr]time.Time
	// routeDirectPromotes counts NoteRoutedDirect TC publishes (ops / periodic metrics).
	routeDirectPromotes atomic.Uint64
	// bypassMiss samples userspace admits vs static LPM (PBR CN gap detector).
	bypassMiss *bypassMissSampler
	// dnsPrefillPromotes counts successful dns_prefill TC publishes.
	dnsPrefillPromotes atomic.Uint64
	// dnsPrefillQueueDrops counts advisory DNS hints dropped while the bounded
	// async prefill workers are busy. Dropping a hint is fail-open; allowing an
	// unbounded goroutine burst would make DNS traffic a heap amplifier.
	dnsPrefillQueueDrops atomic.Uint64

	// dns_kernel_direct: :53 server CIDR exceptions (empty when disabled).
	dnsKernelDirectEnabled bool
	dnsKernelDirectCIDRs   []netip.Prefix

	// weak dns_prefill (outbound_offload.dns_prefill).
	dnsPrefill          dnsPrefillOptions
	dnsPrefillRouter    adapter.Router
	dnsPrefillOutbounds adapter.OutboundManager
	dnsPrefillClosed    atomic.Bool // set on Close; async workers check
	dnsPrefillAccess    sync.Mutex
	dnsPrefillSlots     chan struct{}
	dnsPrefillWorkers   sync.WaitGroup

	// N8: throttle repeated "splice metrics unavailable" warns.
	spliceStatsErrLogged bool

	udpClients  udpClientTable
	udpWarnings udpWarningLimiters
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EBPFInboundOptions) (adapter.Inbound, error) {
	listenOptions, err := normalizeListenOptions(options.ListenOptions)
	if err != nil {
		return nil, err
	}
	cgroupPath, err := normalizeCgroupPath(options.CgroupPath)
	if err != nil {
		return nil, err
	}
	redirectIPv4, redirectIPv6, err := normalizeRedirectAddresses(options.RedirectAddress)
	if err != nil {
		return nil, err
	}
	dnsMode, err := normalizeDNSMode(options.DNSMode)
	if err != nil {
		return nil, err
	}
	includeUID, err := parseUIDRanges(options.IncludeUID, options.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUID, err := parseUIDRanges(options.ExcludeUID, options.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	excludeUID = append(excludeUID, platformExcludedUIDRanges(runtime.GOOS)...)
	sharedOptions, err := normalizeSharedNetworkOptions(options.SharedNetwork)
	if err != nil {
		return nil, err
	}
	// PA/PBR gateway default: no root-cgroup connect hijack (design + 117 canary).
	options.CaptureLocal = defaultCaptureLocal(options.CaptureLocal, sharedOptions.Enabled)
	offloadOptions, clampWarnings, err := normalizeOutboundOffloadOptions(options.OutboundOffload)
	if err != nil {
		return nil, err
	}
	if sharedOptions.FlowVerdict && offloadOptions.Verdict.Mode != "learn" {
		return nil, E.New("shared_network.flow_verdict requires outbound_offload.verdict.mode=learn")
	}
	for _, w := range clampWarnings {
		logger.Warn(w)
	}
	dnsKernelEnabled, dnsKernelCIDRs, err := normalizeDNSKernelDirectOptions(options.DNSKernelDirect, dnsMode)
	if err != nil {
		return nil, err
	}
	if err = validateLocalCaptureOptions(options, sharedOptions); err != nil {
		return nil, err
	}
	network := options.Network.Build()
	enableTCP := common.Contains(network, N.NetworkTCP)
	enableUDP := common.Contains(network, N.NetworkUDP)
	if err = validateSharedNetworkProtocols(sharedOptions, enableUDP, dnsMode); err != nil {
		return nil, err
	}
	udpSessionCapacity, dnsSessionCapacity, capacityWarnings := normalizeUDPNATCapacities(
		options.UDPSessionCapacity,
		options.DNSSessionCapacity,
	)
	for _, warning := range capacityWarnings {
		logger.Warn(warning)
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	inbound := &Inbound{
		Adapter:                inbound.NewAdapter(C.TypeEBPF, tag),
		ctx:                    ctx,
		router:                 router,
		logger:                 logger,
		networkManager:         networkManager,
		listenOptions:          listenOptions,
		cgroupPath:             cgroupPath,
		listenPort:             listenOptions.ListenPort,
		enableTCP:              enableTCP,
		enableUDP:              enableUDP,
		dnsMode:                dnsMode,
		redirectIPv4:           redirectIPv4,
		redirectIPv6:           redirectIPv6,
		sharedOptions:          sharedOptions,
		offloadOptions:         offloadOptions,
		dnsKernelDirectEnabled: dnsKernelEnabled,
		dnsKernelDirectCIDRs:   dnsKernelCIDRs,
		dnsPrefill:             dnsPrefillOptionsFrom(offloadOptions.DNSPrefill),
		bypassMiss:             newBypassMissSampler(),
		policy: ECommon.Policy{
			DisableLocalCapture: options.CaptureLocal != nil && !*options.CaptureLocal,
			HijackDNS:           dnsMode == dnsModeHijack,
			IncludeUID:          includeUID,
			ExcludeUID:          excludeUID,
		},
		udpSessionCapacity: udpSessionCapacity,
		dnsSessionCapacity: dnsSessionCapacity,
	}
	udpTimeout := C.UDPTimeout
	if listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(listenOptions.UDPTimeout)
	}
	// Coordinator covers splice and/or verdict learn. DNS prefill / route DIRECT
	// offload use inbound.promoteLearnedBypass directly and do not need it.
	if offloadOptions.Splice.Enabled || (offloadOptions.Verdict.Mode != "" && offloadOptions.Verdict.Mode != "off") {
		inbound.outboundCoord = newOutboundCoordinator(logger, offloadOptions, udpTimeout)
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := router.RuleSet(ruleSetTag)
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inbound.bypassRuleSet = append(inbound.bypassRuleSet, ruleSet)
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	inbound.dnsMux = dnsmux.New(dnsmux.Options{
		Handle:  inbound.handleDNSPacket,
		Timeout: min(udpTimeout, C.DNSTimeout),
		Prepare: func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			ok, prepareCtx, writer, onClose := inbound.preparePacketConnection(source, destination, userData)
			if !ok {
				return prepareCtx, nil, onClose
			}
			return prepareCtx, writer, onClose
		},
	})
	inbound.udpCleanupInterval = udpNATCleanupInterval(udpTimeout)
	if redirectIPv4.IsValid() {
		inbound.listener4 = inbound.newListener(network, false)
	}
	if redirectIPv6.IsValid() {
		inbound.listener6 = inbound.newListener(network, true)
	}
	return inbound, nil
}

func (i *Inbound) handleDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, _ any) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Protocol:    C.ProtocolDNS,
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = i.listenOptions.Detour
	if clientState, loaded := i.udpClients.load(source.AddrPort()); loaded {
		metadata.UDPConnect = clientState.isConnected()
		if restored, err := restoreOriginalSource(source, destination.Addr, clientState.sourceUID()); err == nil {
			metadata.Source = restored
		} else {
			i.logger.DebugContext(ctx, "restore DNS original source: ", err)
		}
	}
	i.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func normalizeUDPNATCapacities(dataCapacity, dnsCapacity uint32) (uint32, uint32, []string) {
	const (
		defaultDataCapacity = 1024
		defaultDNSCapacity  = 1024
		minimumDataCapacity = 64
		minimumDNSCapacity  = 16
		maximumCapacity     = 8192
	)
	var warnings []string
	normalize := func(value, defaultValue, minimum uint32, name string) uint32 {
		if value == 0 {
			return defaultValue
		}
		if value < minimum {
			warnings = append(warnings, name+" clamped to minimum")
			return minimum
		}
		if value > maximumCapacity {
			warnings = append(warnings, name+" clamped to maximum")
			return maximumCapacity
		}
		return value
	}
	return normalize(dataCapacity, defaultDataCapacity, minimumDataCapacity, "udp_session_capacity"),
		normalize(dnsCapacity, defaultDNSCapacity, minimumDNSCapacity, "dns_session_capacity"), warnings
}

// defaultCaptureLocal: shared_network gateways default false; pure host proxy defaults true.
func defaultCaptureLocal(explicit *bool, sharedNetworkEnabled bool) *bool {
	if explicit != nil {
		return explicit
	}
	v := !sharedNetworkEnabled
	return &v
}

func validateLocalCaptureOptions(
	options option.EBPFInboundOptions,
	sharedOptions option.EBPFSharedNetworkOptions,
) error {
	if options.CaptureLocal == nil || *options.CaptureLocal {
		return nil
	}
	if !sharedOptions.Enabled {
		return E.New("capture_local=false requires shared_network.enabled=true")
	}
	if options.CgroupPath != "" || len(options.IncludeUID) != 0 || len(options.IncludeUIDRange) != 0 ||
		len(options.ExcludeUID) != 0 || len(options.ExcludeUIDRange) != 0 {
		return E.New("cgroup_path and UID filters are invalid when capture_local=false")
	}
	return nil
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeOff:
		return dnsModeOff, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func normalizeCgroupPath(cgroupPath string) (string, error) {
	if cgroupPath == "" {
		return "", nil
	}
	if !filepath.IsAbs(cgroupPath) {
		return "", E.New("eBPF cgroup_path must be absolute")
	}
	return filepath.Clean(cgroupPath), nil
}

func (i *Inbound) newListener(network []string, ipv6 bool) *listener.Listener {
	listenOptions := i.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6 {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	return listener.New(listener.Options{
		Context:             i.ctx,
		Logger:              i.logger,
		Network:             network,
		Listen:              listenOptions,
		ConnectionHandler:   i,
		OOBPacketHandler:    i,
		DisablePacketOutput: true,
		SocketControl:       i.socketControl(ipv6),
	})
}

func normalizeListenOptions(options option.ListenOptions) (option.ListenOptions, error) {
	if options.NetNs != "" {
		return option.ListenOptions{}, E.New("netns is not supported by eBPF inbound")
	}
	if options.BindInterface != "" && options.BindInterface != "lo" {
		return option.ListenOptions{}, E.New("eBPF inbound bind_interface must be lo")
	}
	if options.Listen != nil {
		listenAddress := netip.Addr(*options.Listen)
		if !listenAddress.IsValid() || !listenAddress.IsUnspecified() {
			return option.ListenOptions{}, E.New("eBPF inbound listen address must be unspecified")
		}
	}
	if options.ProxyProtocol || options.ProxyProtocolAcceptNoHeader {
		return option.ListenOptions{}, E.New("proxy_protocol is not supported by eBPF inbound")
	}
	options.Listen = common.Ptr(badoption.Addr(netip.IPv4Unspecified()))
	if options.ListenPort == 0 {
		options.ListenPort = defaultListenPort
	}
	return options, nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		if err := ECommon.ValidateRedirectPrefix(address); err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func platformExcludedUIDRanges(goos string) []ECommon.UIDRange {
	if goos != "android" {
		return nil
	}
	return []ECommon.UIDRange{{Start: androidTetheringDNSUID, End: androidTetheringDNSUID}}
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		policy := i.policy
		policy.EnableBypassCIDR = true
		// Module A: create verdict maps when mode != off (maps owned by inbound runtime).
		if i.offloadOptions.Verdict.Mode != "" && i.offloadOptions.Verdict.Mode != "off" {
			policy.EnableFlowVerdict = true
			// A5: wire MaxEntries (0 → default 65536 in C).
			policy.FlowVerdictMaxEntries = i.offloadOptions.Verdict.MaxEntries
		}
		backend, err := ECommon.Prepare(i.cgroupPath, i.listenPort,
			i.enableTCP, i.enableUDP, i.redirectIPv4, i.redirectIPv6, policy)
		if err != nil {
			return err
		}
		i.setBackend(backend)
		if !i.policy.DisableLocalCapture {
			if err = i.networkManager.RegisterSocketProtectFunc(backend.ProtectFunc()); err != nil {
				closeErr := backend.Close()
				if backend.IsClosed() {
					i.setBackend(nil)
				}
				if closeErr != nil {
					closeErr = E.Cause(closeErr, "close eBPF backend")
				}
				return E.Errors(err, closeErr)
			}
			i.protectRegistered = true
		}
		if i.sharedOptions.Enabled {
			i.sharedNetwork = newSharedNetwork(i, i.sharedOptions)
		}
	case adapter.StartStateStart:
		backend := i.backendInstance()
		if backend == nil {
			return E.New("eBPF backend is not initialized")
		}
		if err := i.applyDNSKernelDirect(); err != nil {
			return combineStartError(
				E.Cause(err, "initialize eBPF dns_kernel_direct"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.startBypassRuleSets(); err != nil {
			return combineStartError(
				E.Cause(err, "initialize eBPF bypass_rule_set"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.setupLocalRoutes(); err != nil {
			return combineStartError(
				E.Cause(err, "configure eBPF redirect routes"),
				i.cleanupStartFailure(),
			)
		}
		if err := i.startListeners(); err != nil {
			return combineStartError(err, i.cleanupStartFailure())
		}
		if i.sharedNetwork != nil {
			if err := i.sharedNetwork.Start(backend); err != nil {
				return combineStartError(err, i.cleanupStartFailure())
			}
		}
		if err := backend.Attach(); err != nil {
			return combineStartError(err, i.cleanupStartFailure())
		}
		if err := i.startOutboundOffload(); err != nil {
			return combineStartError(err, i.cleanupStartFailure())
		}
		// Route-time DIRECT→TC publish (independent of verdict learn mode).
		if hub := service.FromContext[*adapter.DirectOffloadHub](i.ctx); hub != nil {
			hub.Add(i)
		} else {
			service.MustRegister[adapter.DirectOffload](i.ctx, i)
		}
		i.wireDNSPrefill()
		i.startDNSObservationMonitor()
		i.startRuntimeStatsMonitor(backend)
		i.startUDPNATCleanup()
		bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
		dnsDirectV4, dnsDirectV6 := backend.DNSDirectCIDRCount()
		i.logger.Info(
			"eBPF inbound attached: local_capture=", !i.policy.DisableLocalCapture,
			", cgroup=", backend.CgroupPath(),
			", dns_mode=", i.dnsMode,
			", dns_kernel_direct=", i.dnsKernelDirectEnabled,
			", dns_direct_cidr={ipv4:", dnsDirectV4, ", ipv6:", dnsDirectV6, "}",
			", dns_prefill=", i.dnsPrefill.enabled,
			", redirect_address=[", strings.Join(i.redirectAddressStrings(), ", "), "]",
			", bypass_cidr={ipv4:", bypassIPv4Count, ", ipv6:", bypassIPv6Count, "}",
			", redirect_map_capacity={tcp:", ECommon.TCPRedirectMapCapacity,
			", udp:", ECommon.UDPRedirectMapCapacity, "}",
			", outbound_splice=", i.offloadOptions.Splice.Enabled,
			", outbound_verdict=", i.offloadOptions.Verdict.Mode,
			", flow_verdict=", i.sharedOptions.FlowVerdict,
			", exact_flow_learn=", i.sharedNetwork != nil && i.sharedNetwork.shouldLearnExactFlow(),
			", direct_offload=route+prefill+learn",
			", programs=[", strings.Join(backend.AttachedPrograms(), ", "), "]",
		)
	}
	return nil
}

func combineStartError(startErr error, cleanupErr error) error {
	if cleanupErr == nil {
		return startErr
	}
	return E.Errors(startErr, E.Cause(cleanupErr, "cleanup eBPF inbound"))
}

func (i *Inbound) Close() error {
	i.closeAccess.Lock()
	defer i.closeAccess.Unlock()
	return i.closeLocked()
}

func (i *Inbound) startListeners() error {
	if i.listener4 != nil {
		if err := i.listener4.Start(); err != nil {
			return err
		}
	}
	if i.listener6 != nil {
		if err := i.listener6.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (i *Inbound) closeListeners() error {
	var listener4Err error
	var listener6Err error
	if i.listener4 != nil {
		listener4Err = i.listener4.Close()
	}
	if i.listener6 != nil {
		listener6Err = i.listener6.Close()
	}
	return E.Errors(listener4Err, listener6Err)
}

// cleanupStartFailure tears down a partial Start without taking closeAccess.
// Callers already own the inbound lifecycle; behavior matches Close body.
func (i *Inbound) cleanupStartFailure() error {
	return i.closeLocked()
}

// closeLocked is the shared teardown path for Close and cleanupStartFailure.
// Always finish hub unregister / listener teardown even when a backend
// reports a partial close failure — incomplete cleanup leaves maps and
// hub slots live across restarts and hurts HA.
func (i *Inbound) closeLocked() error {
	i.stopDNSPrefill()
	i.stopDNSObservationMonitor()
	i.stopRuntimeStatsMonitor()
	i.stopUDPNATCleanup()
	i.udpNat.Purge()
	i.dnsMux.Close()
	i.stopBypassRuleSets()
	offloadErr := i.closeOutboundOffload()
	var sharedErr error
	if i.sharedNetwork != nil {
		sharedErr = i.sharedNetwork.Close()
		if !i.sharedNetwork.IsClosed() {
			if sharedErr == nil {
				sharedErr = E.New("shared-network eBPF backend remained open after close")
			}
			// Continue teardown: listeners/hubs must not leak on partial eBPF close.
		} else {
			i.sharedNetwork = nil
		}
	}
	backend := i.backendInstance()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			if backendErr == nil {
				backendErr = E.New("eBPF backend remained open after close")
			}
		} else {
			i.setBackend(nil)
		}
	}
	if hub := service.FromContext[*adapter.DirectOffloadHub](i.ctx); hub != nil {
		hub.Remove(i)
	}
	i.unregisterSocketProtector()
	return E.Errors(offloadErr, sharedErr, backendErr, i.closeListeners(), i.removeLocalRoutes())
}

func udpNATCleanupInterval(timeout time.Duration) time.Duration {
	interval := timeout / 2
	if interval < 5*time.Second {
		return 5 * time.Second
	}
	if interval > time.Minute {
		return time.Minute
	}
	return interval
}

func (i *Inbound) startUDPNATCleanup() {
	if i.udpCleanupCancel != nil || i.udpCleanupInterval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.udpCleanupCancel = cancel
	i.udpCleanupDone = done
	go func() {
		defer close(done)
		ticker := time.NewTicker(i.udpCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				i.udpNat.PurgeExpired()
				if i.sharedNetwork != nil {
					i.sharedNetwork.udpNat.PurgeExpired()
				}
				// Promoted DIRECT prefixes have their own TTL and must be
				// collected even when outbound verdict learning is disabled.
				// Previously GC was only reached from verdict metrics, so a
				// dns_prefill-only deployment retained expired LPM entries.
				i.gcPromotedBypass()
				if i.sharedNetwork != nil {
					if expired := i.sharedNetwork.gcV3Promoted(time.Now()); expired > 0 && i.logger != nil {
						i.logger.Info("eBPF gc promoted v3 DIRECT entries expired=", expired)
					}
				}
			}
		}
	}()
}

func (i *Inbound) stopUDPNATCleanup() {
	if i.udpCleanupCancel == nil {
		return
	}
	i.udpCleanupCancel()
	<-i.udpCleanupDone
	i.udpCleanupCancel = nil
	i.udpCleanupDone = nil
}

func (i *Inbound) startOutboundOffload() error {
	if i.outboundCoord == nil {
		return nil
	}
	if err := i.outboundCoord.Start(); err != nil {
		return err
	}
	// Module A: wire verdict against inbound-owned maps (fail-open inside StartVerdict).
	if i.outboundCoord.verdictEnabled() {
		if err := i.outboundCoord.StartVerdict(i.backendInstance()); err != nil {
			return err
		}
	}
	i.wireVerdictLearner()
	i.wirePromoteAndSpliceHooks()
	return nil
}

func (i *Inbound) closeOutboundOffload() error {
	if i == nil {
		return nil
	}
	if hub := service.FromContext[*adapter.VerdictLearnerHub](i.ctx); hub != nil {
		hub.Remove(i)
	}
	if hub := service.FromContext[*adapter.ConnectionSplicerHub](i.ctx); hub != nil {
		hub.Remove(i)
	}
	if i.outboundCoord == nil {
		return nil
	}
	// Q1: do not nil the pointer — coordinator Close() marks closed and no-ops entries.
	// Concurrent MaybeLearnTCP/TrySpliceTCP/stats may still hold the pointer.
	return i.outboundCoord.Close()
}

// NoteRoutedDirect implements adapter.DirectOffload.
// Called when route selected a DIRECT/ebpf leaf for an eBPF inbound connection.
// Publishes destination IPs into TC bypass LPM so subsequent packets skip userspace
// without waiting for dial-time learn. Smart/proxy outbounds are ignored unless
// their sticky Now() leaf is already a stable DIRECT/ebpf type.
func (i *Inbound) NoteRoutedDirect(metadata adapter.InboundContext, outbound adapter.Outbound) {
	if i == nil || outbound == nil {
		return
	}
	// Accept eBPF inbound and shared-network flows that still carry mixed metadata.
	if metadata.InboundType != C.TypeEBPF && metadata.InboundType != C.TypeMixed {
		return
	}
	// Unwrap sticky group Now() when the route target is a group parked on DIRECT.
	outbounds := service.FromContext[adapter.OutboundManager](i.ctx)
	for depth := 0; depth < 8 && outbound != nil; depth++ {
		if isStableDirectLeafType(outbound.Type()) {
			break
		}
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup || outbounds == nil {
			return
		}
		now := group.Now()
		if now == "" {
			return
		}
		next, loaded := outbounds.Outbound(now)
		if !loaded || next == nil {
			return
		}
		outbound = next
	}
	if outbound == nil || !isStableDirectLeafType(outbound.Type()) {
		return
	}
	addrs := collectDirectOffloadAddrs(metadata)
	if len(addrs) == 0 {
		return
	}
	// The /32 promote lands in the shared static bank, so after this call it
	// applies to every client, not just the one whose route produced DIRECT.
	// With mac_source_policy the kernel consults source identity before the
	// static bank, but clients without a MAC row would silently inherit this
	// bypass even when their own route says proxy — the same identity-blind
	// hazard that disables DNS/FakeIP promotion (v3-control-plane-integrity).
	// Exact-flow publication below stays: it carries the full client tuple.
	ttl := i.directPromoteTTL()
	for _, addr := range addrs {
		if !i.dnsPrefillIdentitySafe() {
			break
		}
		if i.promoteLearnedBypass(addr, ttl) {
			i.routeDirectPromotes.Add(1)
		}
	}
	// Exact-flow publish when flow_verdict is armed (needs full client/dest tuple).
	if i.sharedNetwork == nil || !i.sharedNetwork.flowVerdict || i.sharedNetwork.backend == nil {
		return
	}
	source := metadata.Source.AddrPort()
	if !source.IsValid() || source.Port() == 0 {
		return
	}
	dest := metadata.Destination.AddrPort()
	if !dest.IsValid() || !dest.Addr().IsValid() || dest.Port() == 0 {
		// Fall back to first resolved address + original port when dest is domain-form.
		if len(addrs) == 0 {
			return
		}
		port := metadata.Destination.Port
		if port == 0 {
			return
		}
		dest = netip.AddrPortFrom(addrs[0], port)
	}
	if dest.Port() == 53 {
		return
	}
	var proto uint8 = ECommon.ProtocolTCP
	if metadata.Network == N.NetworkUDP {
		proto = ECommon.ProtocolUDP
	}
	if err := i.sharedNetwork.backend.PutDirectFlow(proto, source, dest, ttl); err != nil {
		i.logger.Debug("eBPF route direct flow publish skipped: ", err)
	}
}

func (i *Inbound) directPromoteTTL() time.Duration {
	if i == nil {
		return 5 * time.Minute
	}
	if i.outboundCoord != nil && i.outboundCoord.verdictLearn.ttl > 0 {
		return i.outboundCoord.verdictLearn.ttl
	}
	if i.dnsPrefill.enabled && i.dnsPrefill.ttl > 0 {
		return i.dnsPrefill.ttl
	}
	return 5 * time.Minute
}

// collectDirectOffloadAddrs returns public destination IPs eligible for TC promote.
func collectDirectOffloadAddrs(metadata adapter.InboundContext) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, 4)
	var out []netip.Addr
	add := func(addr netip.Addr) {
		if !addr.IsValid() {
			return
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
			addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if metadata.Destination.IsValid() && metadata.Destination.IsIP() {
		add(metadata.Destination.Addr)
	}
	for _, addr := range metadata.DestinationAddresses {
		add(addr)
	}
	return out
}

// ebpfLearnEligible is true for native eBPF inbounds and shared-network
// transparent paths that still surface as mixed in metadata.
// Aligns with package-level verdictInboundEligible; extra gate: mixed only
// when this inbound actually runs shared_network (avoids bare mixed poisoning).
func (i *Inbound) ebpfLearnEligible(inboundType string) bool {
	if inboundType == C.TypeEBPF {
		return true
	}
	return inboundType == C.TypeMixed && i != nil && i.sharedOptions.Enabled
}

// MaybeLearnTCP implements adapter.VerdictLearner (Module A learn path).
func (i *Inbound) MaybeLearnTCP(
	ctx context.Context,
	dialer N.Dialer,
	metadata adapter.InboundContext,
	remote netip.AddrPort,
) {
	if i == nil || i.outboundCoord == nil {
		return
	}
	if !i.ebpfLearnEligible(metadata.InboundType) {
		return
	}
	i.outboundCoord.MaybeLearnTCP(ctx, dialer, metadata, remote)
	// Publish the same exact-flow verdict used by UDP after the first
	// userspace connection is proven DIRECT. The existing destination-level
	// learner remains the compatibility path; this tuple path is opt-in through
	// shared_network.flow_verdict and cannot bypass a proxy dialer.
	if i.sharedNetwork == nil || !i.sharedNetwork.shouldLearnExactFlow() ||
		!verdictIsEmptyDirect(dialer) || !remote.IsValid() {
		return
	}
	opts := i.outboundCoord.verdictLearn
	dest, reason := resolveLearnDestination(metadata, remote)
	if reason != verdictSkipNone || !dest.IsValid() || opts.mode != "learn" {
		return
	}
	ok, _ := evaluateVerdictLearn(opts, dialer, metadata, dest)
	if !ok {
		return
	}
	source := metadata.Source.AddrPort()
	if !source.IsValid() || source.Port() == 0 {
		return
	}
	if i.sharedNetwork.engineV3 {
		// Unified path: lifecycle+sink owns kernel write (no double PutDirectFlow).
		i.sharedNetwork.learnV3Flow(ECommon.ProtocolTCP, source, dest)
		return
	}
	if err := i.sharedNetwork.backend.PutDirectFlow(ECommon.ProtocolTCP, source, dest, opts.ttl); err != nil {
		i.logger.Debug("eBPF shared-network direct TCP learn skipped: ", err)
	}
}

// MaybeLearnUDP publishes only a proven DIRECT UDP flow. The shared-network
// backend uses the exact client/destination tuple, so a direct verdict cannot
// affect another client, region, or Smart policy group.
func (i *Inbound) MaybeLearnUDP(
	ctx context.Context,
	dialer N.Dialer,
	metadata adapter.InboundContext,
	remote netip.AddrPort,
) {
	if i == nil || !i.ebpfLearnEligible(metadata.InboundType) {
		return
	}
	if i.outboundCoord != nil {
		i.outboundCoord.MaybeLearnUDP(ctx, dialer, metadata, remote)
	}
	if i.sharedNetwork == nil || !i.sharedNetwork.shouldLearnExactFlow() || i.outboundCoord == nil {
		return
	}
	if !verdictIsEmptyDirect(dialer) || !remote.IsValid() || remote.Port() == 53 {
		return
	}
	opts := i.outboundCoord.verdictLearn
	ok, _ := evaluateVerdictLearn(opts, dialer, metadata, remote)
	if opts.mode != "learn" || !ok {
		return
	}
	source := metadata.Source.AddrPort()
	if !source.IsValid() || source.Port() == 0 {
		return
	}
	if i.sharedNetwork.engineV3 {
		i.sharedNetwork.learnV3Flow(ECommon.ProtocolUDP, source, remote)
		return
	}
	if err := i.sharedNetwork.backend.PutDirectFlow(ECommon.ProtocolUDP, source, remote, opts.ttl); err != nil {
		i.logger.Debug("eBPF shared-network direct UDP learn skipped: ", err)
	}
}

// RevokeExactFlow clears a learned exact-flow after a proven path failure.
func (i *Inbound) RevokeExactFlow(protocol uint8, client, dest netip.AddrPort) {
	if i == nil || i.sharedNetwork == nil {
		return
	}
	i.sharedNetwork.revokeExactFlow(protocol, client, dest)
}

// TrySpliceTCP implements adapter.ConnectionSplicer.
func (i *Inbound) TrySpliceTCP(
	ctx context.Context,
	inboundType string,
	dialer N.Dialer,
	local net.Conn,
	remote net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) bool {
	if i == nil || i.outboundCoord == nil {
		return false
	}
	if inboundType == "" {
		inboundType = C.TypeEBPF
	}
	// Shared-network socket_assign preserves the original tuple while the
	// ingress metadata may still be reported as mixed by the transparent
	// listener. Treat that path as an eBPF inbound for splice eligibility;
	// outbound type allow-listing remains the final safety gate.
	if inboundType == C.TypeMixed && i.sharedOptions.DataPlane == sharedNetworkDataPlaneSocketAssign {
		inboundType = C.TypeEBPF
	}
	var track func(io.Closer)
	if manager := service.FromContext[adapter.ConnectionManager](ctx); manager != nil {
		track = func(c io.Closer) {
			_ = manager.TrackCloser(c)
		}
	}
	return TrySpliceTCP(ctx, i.outboundCoord, inboundType, dialer, local, remote, metadata, onClose, track)
}

func (i *Inbound) backendInstance() *ECommon.Backend {
	i.backendAccess.RLock()
	defer i.backendAccess.RUnlock()
	return i.backend
}

func (i *Inbound) setBackend(backend *ECommon.Backend) {
	i.backendAccess.Lock()
	i.backend = backend
	i.backendAccess.Unlock()
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4.IsValid() {
		addresses = append(addresses, i.redirectIPv4.String())
	}
	if i.redirectIPv6.IsValid() {
		addresses = append(addresses, i.redirectIPv6.String())
	}
	return addresses
}

func (i *Inbound) unregisterSocketProtector() {
	if !i.protectRegistered {
		return
	}
	i.networkManager.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(
			i.bypassRuleSetCallbacks,
			ruleSet.RegisterCallback(i.updateBypassRuleSet),
		)
	}
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassRuleSetsLocked(true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		backend := i.backendInstance()
		if backend != nil && !backend.IsClosed() {
			i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(warnEmpty bool) (bool, error) {
	prefixes := i.localInterfacePrefixes()
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if warnEmpty && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	// Merge non-expired learn→TC promotions (dae-style gateway high trigger).
	now := time.Now()
	var expiredPromotions []netip.Addr
	if i.promotedBypass != nil {
		for addr, exp := range i.promotedBypass {
			if now.After(exp) {
				expiredPromotions = append(expiredPromotions, addr)
				continue
			}
			bits := 32
			if !addr.Is4() {
				bits = 128
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	backend := i.backendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	updated, err := backend.UpdateBypassCIDR(prefixes)
	if err != nil {
		return false, err
	}
	// Do not drop expired entries from the authoritative Go table until the
	// backend accepted the rebuilt snapshot.  Keeping them on a failed refresh
	// allows the next retry to remove both the Go and kernel mirrors together.
	for _, addr := range expiredPromotions {
		delete(i.promotedBypass, addr)
	}
	// v3 static banks must track bypass_rule_set reloads (double-buffer commit).
	if updated && i.sharedNetwork != nil {
		if refreshErr := i.sharedNetwork.RefreshV3Static(backend); refreshErr != nil {
			i.logger.Warn("refresh eBPF v3 static policy: ", refreshErr)
		}
	}
	return updated, nil
}

func (i *Inbound) localInterfacePrefixes() []netip.Prefix {
	return localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
}

func localInterfacePrefixes(interfaces []control.Interface) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			address := prefix.Addr().Unmap()
			prefixBits := prefix.Bits()
			if prefix.Addr().Is4In6() {
				if prefixBits < 96 {
					continue
				}
				prefixBits -= 96
			}
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, prefixBits).Masked())
		}
	}
	return prefixes
}

const promotedBypassMaxEntries = 8192

func clonePromotedBypass(entries map[netip.Addr]time.Time) map[netip.Addr]time.Time {
	if len(entries) == 0 {
		return nil
	}
	clone := make(map[netip.Addr]time.Time, len(entries))
	for addr, expiresAt := range entries {
		clone[addr] = expiresAt
	}
	return clone
}

// promotedBypassEviction returns expired entries and, separately, the live
// entry that should be evicted when the bounded table is full.  It is kept
// pure so the selection policy can be tested without a live eBPF backend.
func promotedBypassEviction(entries map[netip.Addr]time.Time, now time.Time) (evict netip.Addr, expired []netip.Addr) {
	var evictAt time.Time
	for addr, exp := range entries {
		if now.After(exp) {
			expired = append(expired, addr)
			continue
		}
		if !evict.IsValid() || exp.Before(evictAt) {
			evict, evictAt = addr, exp
		}
	}
	return evict, expired
}

// promoteLearnedBypass installs addr/32|/128 into TC bypass LPM.
// Returns true when a new map entry is created (false on refresh/skip/error).
func (i *Inbound) promoteLearnedBypass(addr netip.Addr, ttl time.Duration) bool {
	if i == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
		return false
	}
	// RFC1918 already TC builtin-bypassed; promoting is redundant noise.
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return false
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.promotedBypass == nil {
		i.promotedBypass = make(map[netip.Addr]time.Time)
	}
	previousExpiry, existed := i.promotedBypass[addr]
	// A snapshot is only needed on the bounded-table path, where eviction may
	// be followed by a full backend rebuild. The common hot path avoids copying
	// the table and remains a single map update.
	var previousPromoted map[netip.Addr]time.Time
	if len(i.promotedBypass) >= promotedBypassMaxEntries {
		previousPromoted = clonePromotedBypass(i.promotedBypass)
	}
	var removed []netip.Addr
	if len(i.promotedBypass) >= promotedBypassMaxEntries {
		// Expired entries must be removed from the kernel mirror as well as the
		// bounded Go table.  Otherwise a full table can keep stale LPM entries
		// alive until the map itself fills.  Batch the removals so one refresh
		// also updates the v3 static bank when it is active.
		evict, expired := promotedBypassEviction(i.promotedBypass, time.Now())
		for _, a := range expired {
			delete(i.promotedBypass, a)
			removed = append(removed, a)
		}
		if !existed {
			// Evict the entry closest to expiry first.  Map iteration order is
			// random; arbitrary eviction made hot destinations disappear while
			// long-lived entries occupied the bounded table.
			if evict.IsValid() {
				delete(i.promotedBypass, evict)
				removed = append(removed, evict)
			}
		}
	}
	i.promotedBypass[addr] = time.Now().Add(ttl)
	bits := 32
	if !addr.Is4() {
		bits = 128
	}
	prefix := netip.PrefixFrom(addr, bits)
	backend := i.backendInstance()
	if backend != nil {
		if len(removed) > 0 {
			// Rebuild from rule-set state when an entry is removed.  An expired
			// promotion may overlap a permanent bypass rule; deleting it directly
			// would accidentally remove that rule from the kernel mirror.  The
			// authoritative rebuild preserves such overlaps and refreshes v3's
			// separate static bank in the same operation.
			if _, err2 := i.refreshBypassRuleSetsLocked(false); err2 != nil {
				i.promotedBypass = previousPromoted
				i.logger.Debug("promote learned bypass refresh: ", err2)
				return false
			}
		} else if err := backend.AddBypassPrefix(prefix); err != nil {
			i.logger.Debug("promote AddBypassPrefix: ", err, " fallback full refresh")
			if previousPromoted == nil {
				// Reconstruct the pre-update table before taking the
				// snapshot; copying after insertion would make a failed
				// fallback appear committed on the next request.
				newExpiry := i.promotedBypass[addr]
				if existed {
					i.promotedBypass[addr] = previousExpiry
				} else {
					delete(i.promotedBypass, addr)
				}
				previousPromoted = clonePromotedBypass(i.promotedBypass)
				i.promotedBypass[addr] = newExpiry
			}
			if _, err2 := i.refreshBypassRuleSetsLocked(false); err2 != nil {
				i.promotedBypass = previousPromoted
				i.logger.Debug("promote learned bypass refresh: ", err2)
				return false
			}
		}
	} else {
		if previousPromoted == nil {
			newExpiry := i.promotedBypass[addr]
			if existed {
				i.promotedBypass[addr] = previousExpiry
			} else {
				delete(i.promotedBypass, addr)
			}
			previousPromoted = clonePromotedBypass(i.promotedBypass)
			i.promotedBypass[addr] = newExpiry
		}
		if _, err := i.refreshBypassRuleSetsLocked(false); err != nil {
			i.promotedBypass = previousPromoted
			i.logger.Debug("promote learned bypass refresh: ", err)
			return false
		}
	}
	// engine=v3: feed the unified kernel policy surface only after the parent
	// bypass update succeeded. This prevents a failed parent rebuild from
	// leaving a v3 static entry with no authoritative Go/TC counterpart.
	if i.sharedNetwork != nil && i.sharedNetwork.engineV3 {
		i.sharedNetwork.promoteV3Direct(addr, ttl)
	}
	if !existed {
		i.logger.Debug("eBPF promote TC bypass /32: ", addr.String(), " ttl=", ttl, " promoted=", len(i.promotedBypass))
	} else {
		i.logger.Debug("eBPF promote TC bypass refresh: ", addr.String(), " ttl=", ttl)
	}
	return !existed
}

// gcPromotedBypass drops TTL-expired learn→TC entries from the LPM.  Expiry is
// uncommon, so a single authoritative rebuild per batch is preferable to
// risking removal of an overlapping permanent bypass rule.
func (i *Inbound) gcPromotedBypass() {
	if i == nil {
		return
	}
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if len(i.promotedBypass) == 0 {
		return
	}
	now := time.Now()
	var expired []netip.Addr
	for addr, exp := range i.promotedBypass {
		if now.After(exp) {
			expired = append(expired, addr)
		}
	}
	if len(expired) == 0 {
		return
	}
	previousPromoted := clonePromotedBypass(i.promotedBypass)
	for _, addr := range expired {
		delete(i.promotedBypass, addr)
	}
	backend := i.backendInstance()
	if backend == nil {
		i.promotedBypass = previousPromoted
		return
	}
	// Rebuild from the authoritative rule-set state rather than deleting each
	// address incrementally.  This preserves a permanent bypass rule if it
	// happens to share an address with an expired learned promotion and updates
	// the v3 static bank without a second, divergent path.
	if _, err := i.refreshBypassRuleSetsLocked(false); err != nil {
		i.promotedBypass = previousPromoted
		i.logger.Debug("gc promoted bypass full refresh: ", err)
	}
	i.logger.Info("eBPF gc promoted TC bypass expired=", len(expired), " remain=", len(i.promotedBypass))
}

func (i *Inbound) clearPromotedBypass() {
	if i == nil {
		return
	}
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if len(i.promotedBypass) == 0 {
		return
	}
	i.promotedBypass = make(map[netip.Addr]time.Time)
	if _, err := i.refreshBypassRuleSetsLocked(false); err != nil {
		i.logger.Debug("clear promoted bypass refresh: ", err)
		return
	}
	i.logger.Info("eBPF cleared promoted TC bypass entries")
}

func (i *Inbound) logBypassCIDRUpdate() {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	ipv4Count, ipv6Count := backend.BypassCIDRCount()
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) InterfaceUpdated(_ context.Context) {
	if i == nil {
		return
	}
	i.closeAccess.Lock()
	defer i.closeAccess.Unlock()
	if i.udpNat == nil || i.dnsMux == nil {
		return
	}
	i.udpNat.Purge()
	i.dnsMux.Purge()
	i.bypassRuleSetAccess.Lock()
	var updated bool
	var refreshErr error
	if i.bypassRuleSetStarted {
		updated, refreshErr = i.refreshBypassRuleSetsLocked(false)
		if refreshErr != nil {
			i.logger.Error("refresh eBPF local interface bypass: ", refreshErr)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	// Fingerprint local+bypass prefixes even when rule-set path is idle (Q2/N2).
	fp := bypassFingerprint(i.localInterfacePrefixes())
	if backend := i.backendInstance(); backend != nil {
		v4, v6 := backend.BypassCIDRCount()
		fp = fp + "|map=" + strconv.Itoa(v4) + "," + strconv.Itoa(v6)
	}
	i.bypassRuleSetAccess.Unlock()
	// N2: force invalidate on refresh failure or rule-set content change; else fingerprint gate.
	if i.outboundCoord != nil {
		switch {
		case refreshErr != nil:
			i.outboundCoord.InvalidateVerdictNow("bypass-refresh-failed")
		case updated:
			i.outboundCoord.InvalidateVerdictNow("bypass-ruleset-updated")
			i.outboundCoord.NoteBypassFingerprint(fp)
		default:
			i.outboundCoord.InvalidateVerdictIfNeeded(fp, "interface-updated")
		}
	}
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}

func bypassFingerprint(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "empty"
	}
	// Sort for stability.
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := i.backendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	original, err := backend.TakeOriginal(
		ECommon.ProtocolTCP,
		M.SocksaddrFromNet(conn.LocalAddr()).AddrPort(),
	)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	metadata.Source, err = restoreOriginalSource(metadata.Source, original.Destination.Addr(), original.UID)
	if err != nil {
		i.logger.DebugContext(ctx, "restore TCP original source: ", err)
	}
	// Connection-level spam is Debug: gateway traffic can be thousands/s.
	i.logger.DebugContext(ctx, "inbound connection to ", metadata.Destination)
	if dest := metadata.Destination.Addr; dest.IsValid() {
		i.bypassMiss.ObserveTCP(i, dest)
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warnError(i.logger, "read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listenPort)
	original, err := backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
	if err != nil {
		i.udpWarnings.originalDestination.warnError(i.logger, "lookup UDP original destination: ", err)
		return
	}
	releasedRedirects := i.udpClients.setBinding(
		client,
		original.Destination,
		redirectAddress,
		original.ConnectedUDP,
	)
	i.udpClients.setUID(client, original.UID)
	i.deleteUDPRedirects(releasedRedirects)
	if original.Destination.Port() == 53 {
		i.dnsMux.NewPacket(buffer.Bytes(), source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
		return
	}
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	//nolint:staticcheck
	metadata.InboundDetour = i.listenOptions.Detour
	if clientState, loaded := i.udpClients.load(source.AddrPort()); loaded {
		metadata.UDPConnect = clientState.isConnected()
		var err error
		metadata.Source, err = restoreOriginalSource(source, destination.Addr, clientState.sourceUID())
		if err != nil {
			i.logger.DebugContext(ctx, "restore UDP original source: ", err)
		}
	}
	i.logger.DebugContext(ctx, "inbound packet connection from ", metadata.Source)
	i.logger.DebugContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	clientState := i.udpClients.retain(client)
	clientState.setConnected(connectedUDP)
	writer := &udpPacketWriter{
		inbound:     i,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		i.deleteUDPRedirects(i.udpClients.delete(writer.client, writer.clientState))
	}
}

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirect := netip.AddrPortFrom(redirectAddress, i.listenPort)
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirect); err != nil {
			i.udpWarnings.cleanup.warnValueError(i.logger, "delete UDP redirect mapping for ", redirect, ": ", err)
		}
	}
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
				return nil
			})
		}
		switch network {
		case "udp4":
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		default:
			return nil
		}
	}
}

type udpPacketWriter struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.inbound.listener4 == nil {
			return E.New("IPv4 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.inbound.listener6 == nil {
			return E.New("IPv6 eBPF listener is unavailable")
		}
		udpConn = w.inbound.listener6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage4 ipv4.ControlMessage
	if err := controlMessage4.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage4.Dst); loaded && address.Is4() {
			return address.Unmap(), nil
		}
	}
	var controlMessage6 ipv6.ControlMessage
	if err := controlMessage6.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage6.Dst); loaded && address.Is6() && !address.Is4In6() {
			return address, nil
		}
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}

// wireVerdictLearner registers this inbound as a verdict learner whenever the
// outbound coordinator owns a verdict map. This hook was once a silent no-op
// (registered without route/conn.go wiring); keep it contract-tested via
// TestInboundWiresVerdictLearnerAndSpliceHooks.
func (i *Inbound) wireVerdictLearner() {
	if i.outboundCoord != nil && i.outboundCoord.Verdict() != nil {
		if hub := service.FromContext[*adapter.VerdictLearnerHub](i.ctx); hub != nil {
			hub.Add(i)
		} else {
			service.MustRegister[adapter.VerdictLearner](i.ctx, i)
		}
	}
}

// wirePromoteAndSpliceHooks binds the /32 promote callbacks and the
// fail-open splice registration (master §6.1).
func (i *Inbound) wirePromoteAndSpliceHooks() {
	if i.outboundCoord != nil {
		i.outboundCoord.SetPromoteHooks(func(addr netip.Addr, ttl time.Duration) {
			_ = i.promoteLearnedBypass(addr, ttl)
		}, i.clearPromotedBypass)
	}
	if i.outboundCoord.enabled() && i.outboundCoord.Splice() != nil {
		if hub := service.FromContext[*adapter.ConnectionSplicerHub](i.ctx); hub != nil {
			hub.Add(i)
		} else {
			service.MustRegister[adapter.ConnectionSplicer](i.ctx, i)
		}
	}
}
