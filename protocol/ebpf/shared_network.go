//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dnsmux"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	ebpfabi "github.com/sagernet/sing-box/common/ebpf/v3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/sagernet/sing-box/option"
	ebpfv3 "github.com/sagernet/sing-box/protocol/ebpf/v3"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	sharedNetworkRefresh               = 3 * time.Second
	sharedNetworkDataPlaneToken        = "token"
	sharedNetworkDataPlaneSocketAssign = "socket_assign"
	sharedNetworkRoutingMarkDefault    = 0x53420001
	sharedNetworkRoutingTableDefault   = 2026
	// Default TC priority: run before Android tethering offload (IPv6 prio 2, IPv4 prio 3).
	// Lower value runs earlier. Override via shared_network.tc_priority.
	sharedNetworkTCPriorityDefault = 1
	sharedIngressFilterHandle      = 0x5342
	sharedEgressFilterHandle       = 0x5343
)

type sharedNetwork struct {
	parent             *Inbound
	interfaces         []string
	tcPriority         uint16
	dropUDP443         bool
	dataPlane          string
	flowVerdict        bool
	engineV3           bool
	v3                 *ebpfv3.Lifecycle
	transparentAccess  sync.Mutex
	transparentWriters map[netip.AddrPort]*transparentWriterEntry
	routingMark        uint32
	routingTable       uint32
	backend            ECommon.SharedDataplane
	policyRoute        *sharedNetworkPolicyRoute
	tc                 *sharedTCManager
	staticDirect       []netip.Prefix
	v3PromoteAccess    sync.Mutex
	v3Promoted         map[netip.Addr]time.Time
	tcp4               *listener.Listener
	tcp6               *listener.Listener
	udp4               *listener.Listener
	udp6               *listener.Listener
	udpNat             *udpnat.Service
	dnsMux             *dnsmux.Service
	udpClients         udpClientTable
	udpWarnings        udpWarningLimiters
	listenPort         uint16
	closeAccess        sync.RWMutex
}

type sharedNetworkIngressInterfaceKey struct{}

func sharedNetworkIngressInterface(ifIndex uint32) string {
	if ifIndex == 0 {
		return ""
	}
	device, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return ""
	}
	return device.Name
}

func normalizeSharedNetworkOptions(options option.EBPFSharedNetworkOptions) (option.EBPFSharedNetworkOptions, error) {
	if !options.Enabled {
		return option.EBPFSharedNetworkOptions{}, nil
	}
	// v3 engine validation/defaults (empty engine stays v2).
	var err error
	options, err = ebpfv3.NormalizeSharedNetwork(options)
	if err != nil {
		return option.EBPFSharedNetworkOptions{}, err
	}
	switch options.DataPlane {
	case "":
		// socket_assign is the safe default: it preserves the original tuple
		// and avoids the per-flow token/session state retained by compatibility
		// mode. Set data_plane="token" explicitly only for legacy deployments.
		options.DataPlane = sharedNetworkDataPlaneSocketAssign
	case sharedNetworkDataPlaneToken:
	case sharedNetworkDataPlaneSocketAssign:
	default:
		return option.EBPFSharedNetworkOptions{}, E.New("unknown shared_network.data_plane: ", options.DataPlane)
	}
	if options.DataPlane == sharedNetworkDataPlaneToken && (options.RoutingMark != 0 || options.RoutingTable != 0) {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network routing_mark/routing_table require data_plane=socket_assign")
	}
	if options.FlowVerdict && options.DataPlane != sharedNetworkDataPlaneSocketAssign {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.flow_verdict requires data_plane=socket_assign")
	}
	if ebpfv3.IsV3(options) && options.DataPlane != sharedNetworkDataPlaneSocketAssign {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.engine=v3 requires data_plane=socket_assign")
	}
	if options.DataPlane == sharedNetworkDataPlaneSocketAssign {
		if options.RoutingMark == 0 {
			options.RoutingMark = sharedNetworkRoutingMarkDefault
		}
		if options.RoutingTable == 0 {
			options.RoutingTable = sharedNetworkRoutingTableDefault
		}
		if options.RoutingTable > 0xffffffff {
			return option.EBPFSharedNetworkOptions{}, E.New("invalid shared_network.routing_table")
		}
	}
	if len(options.IncludeInterface) == 0 {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not be empty")
	}
	seen := make(map[string]struct{}, len(options.IncludeInterface))
	interfaces := make(badoption.Listable[string], 0, len(options.IncludeInterface))
	for _, interfaceName := range options.IncludeInterface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.IncludeInterface = interfaces
	return options, nil
}

func validateSharedNetworkProtocols(options option.EBPFSharedNetworkOptions, enableUDP bool, dnsMode string) error {
	if options.Enabled && dnsMode == dnsModeHijack && !enableUDP {
		return E.New("shared_network with dns_mode hijack requires UDP")
	}
	return nil
}

func sharedNetworkDropUDP443(options option.EBPFSharedNetworkOptions) bool {
	if options.DropUDP443 == nil {
		return false
	}
	return *options.DropUDP443
}

func sharedNetworkResolveTCPriority(options option.EBPFSharedNetworkOptions) uint16 {
	if options.TCPriority == 0 {
		return sharedNetworkTCPriorityDefault
	}
	return options.TCPriority
}

func newSharedNetwork(parent *Inbound, options option.EBPFSharedNetworkOptions) *sharedNetwork {
	shared := &sharedNetwork{
		parent:       parent,
		interfaces:   append([]string(nil), options.IncludeInterface...),
		tcPriority:   sharedNetworkResolveTCPriority(options),
		dropUDP443:   sharedNetworkDropUDP443(options),
		dataPlane:    options.DataPlane,
		flowVerdict:  options.FlowVerdict || (ebpfv3.IsV3(options) && options.PolicyOffload.ExactFlowLearning),
		engineV3:     ebpfv3.IsV3(options),
		routingMark:  options.RoutingMark,
		routingTable: options.RoutingTable,
	}
	if shared.engineV3 {
		// Control-plane always available. Kernel TC v3 object attach is Linux
		// generate+load (common/ebpf/v3/kern); until then packet path stays v2
		// socket_assign while learn/DNS models accumulate in Lifecycle.
		lc, err := ebpfv3.NewLifecycle(options, 0)
		if err != nil {
			parent.logger.Warn("eBPF v3 lifecycle: ", err)
		} else {
			shared.v3 = lc
			enableTCP := parent.enableTCP
			enableUDP := parent.enableUDP
			if err := lc.ApplyControlFlags(true, true, enableTCP, enableUDP, parent.dnsMode == dnsModeHijack, options.RoutingMark); err != nil {
				parent.logger.Warn("eBPF v3 control flags push failed: ", err)
			}
			parent.logger.Info("eBPF shared-network engine=v3 control-plane ready (policy_offload=",
				options.PolicyOffload.Enabled, "); kernel tc.bpf attach uses generate on Linux")
		}
	}
	udpTimeout := C.UDPTimeout
	if parent.listenOptions.UDPTimeout != 0 {
		udpTimeout = time.Duration(parent.listenOptions.UDPTimeout)
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, udpTimeout, false)
	shared.dnsMux = dnsmux.New(dnsmux.Options{
		Handle:  shared.handleDNSPacket,
		Timeout: min(udpTimeout, C.DNSTimeout),
		LaneKey: func(source M.Socksaddr, userData any) string {
			var suffix string
			if ifIndex, loaded := userData.(uint32); loaded {
				suffix = strconv.FormatUint(uint64(ifIndex), 10)
			}
			return dnsmux.AddressLaneKey(source, suffix)
		},
		Prepare: func(source, destination M.Socksaddr, userData any) (context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			ok, prepareCtx, writer, onClose := shared.preparePacketConnection(source, destination, userData)
			if !ok {
				return prepareCtx, nil, onClose
			}
			return prepareCtx, writer, onClose
		},
	})
	return shared
}

func (s *sharedNetwork) handleDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, source, destination M.Socksaddr, _ any) {
	metadata := adapter.InboundContext{
		Inbound:     s.parent.Tag(),
		InboundType: s.parent.Type(),
		Network:     N.NetworkUDP,
		Protocol:    C.ProtocolDNS,
		Source:      source,
		Destination: destination,
	}
	if interfaceName, loaded := ctx.Value(sharedNetworkIngressInterfaceKey{}).(string); loaded {
		metadata.InboundInterface = interfaceName
	}
	//nolint:staticcheck
	metadata.InboundDetour = s.parent.listenOptions.Detour
	s.parent.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (s *sharedNetwork) Start(parentBackend *ECommon.Backend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	var backend ECommon.SharedDataplane
	var err error
	wantV3 := s.engineV3
	if wantV3 {
		po := s.parent.sharedOptions.PolicyOffload
		// Default exact-flow on when policy_offload enabled and not explicitly sparse.
		flowLearn := po.ExactFlowLearning || s.flowVerdict
		staticRules := po.StaticRules
		if po.Enabled && !po.ExactFlowLearning && !po.StaticRules && !s.flowVerdict {
			// enabled with zero sub-flags → turn on the safe defaults from design §13.
			staticRules = true
			flowLearn = true
		}
		dnsHint := po.Enabled && (po.DNSIPHint == "safe" || po.DNSIPHint == "strong")
		fakeIP := po.Enabled && po.FakeIP
		backend, err = ECommon.PrepareSharedNetworkV3(
			s.parent.enableTCP,
			s.parent.enableUDP,
			s.parent.redirectIPv4.IsValid(),
			s.parent.redirectIPv6.IsValid(),
			s.parent.dnsMode == dnsModeHijack,
			s.dropUDP443,
			s.routingMark,
			staticRules,
			flowLearn,
			dnsHint,
			fakeIP,
			0,
		)
		if err != nil {
			// Fail-open to v2 dataplane so canary hosts never lose PBR (design §15).
			s.parent.logger.Warn("eBPF v3 kernel dataplane unavailable, falling back to v2: ", err)
			s.engineV3 = false
			backend = nil
			err = nil
		} else {
			s.parent.logger.Info("eBPF shared-network engine=v3 kernel dataplane loaded")
			// Single control plane: memory lifecycle + kernel maps stay in lockstep.
			if s.v3 != nil {
				s.v3.BindSink(v3KernelSink{dp: backend})
			}
		}
	}
	if backend == nil {
		backend, err = ECommon.PrepareSharedNetwork(
			parentBackend,
			s.listenPort,
			s.parent.enableTCP,
			s.parent.enableUDP,
			s.parent.redirectIPv4,
			s.parent.redirectIPv6,
			s.dropUDP443,
			s.dataPlane == sharedNetworkDataPlaneSocketAssign,
			s.routingMark,
		)
		if err != nil {
			return E.Errors(err, s.closeListeners())
		}
		if wantV3 && !s.engineV3 {
			s.parent.logger.Info("eBPF shared-network using v2 TC dataplane (v3 control-plane model still active when lifecycle present)")
		}
	}
	s.backend = backend
	if err = backend.SetFlowDirect(s.flowVerdict || s.engineV3); err != nil {
		return E.Errors(E.Cause(err, "configure shared-network flow verdict"), s.Close())
	}
	if s.engineV3 {
		if err = s.publishV3StaticFromParent(parentBackend); err != nil {
			return E.Errors(E.Cause(err, "publish eBPF v3 static policy"), s.Close())
		}
		s.probeXDP(parentBackend)
	}
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		if err = s.registerListenerSockets(); err != nil {
			return E.Errors(E.Cause(err, "register shared-network transparent listeners"), s.Close())
		}
		s.policyRoute, err = installSharedNetworkPolicyRoute(
			s.routingMark,
			s.routingTable,
			s.parent.redirectIPv4.IsValid(),
			s.parent.redirectIPv6.IsValid(),
		)
		if err != nil {
			return E.Errors(err, s.Close())
		}
	}
	s.tc = &sharedTCManager{
		backend:      backend,
		logger:       s.parent.logger,
		interfaces:   s.interfaces,
		priority:     s.tcPriority,
		enableIPv4:   s.parent.redirectIPv4.IsValid(),
		attachEgress: s.dataPlane != sharedNetworkDataPlaneSocketAssign && !s.engineV3,
		attachments:  make(map[string]*sharedTCAttachment),
	}
	if err = s.tc.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	programs := "tc/ingress,tc/egress"
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		programs = "tc/ingress+socket-assign"
	}
	s.parent.logger.Info(
		"eBPF shared-network ready: interfaces=[", s.tc.InterfaceString(),
		"], listen_port=", s.listenPort,
		", dns_mode=", s.parent.dnsMode,
		", tc_priority=", s.tcPriority,
		", drop_udp_443=", s.dropUDP443,
		", data_plane=", s.dataPlane,
		", programs=[", programs, "]",
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	type listenerSpec struct {
		network string
		ipv6    bool
		target  **listener.Listener
	}
	var specs []listenerSpec
	if s.parent.redirectIPv4.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, false, &s.tcp4})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, false, &s.udp4})
		}
	}
	if s.parent.redirectIPv6.IsValid() {
		if s.parent.enableTCP {
			specs = append(specs, listenerSpec{N.NetworkTCP, true, &s.tcp6})
		}
		if s.parent.enableUDP {
			specs = append(specs, listenerSpec{N.NetworkUDP, true, &s.udp6})
		}
	}
	for _, spec := range specs {
		current := s.newListener(spec.network, spec.ipv6, s.listenPort)
		*spec.target = current
		if err := current.Start(); err != nil {
			return err
		}
		if s.listenPort == 0 {
			var address net.Addr
			if spec.network == N.NetworkTCP {
				address = current.TCPListener().Addr()
			} else {
				address = current.UDPConn().LocalAddr()
			}
			s.listenPort = M.SocksaddrFromNet(address).Port
			if s.listenPort == 0 {
				return E.New("shared-network listener selected an invalid port")
			}
		}
	}
	if s.listenPort == 0 {
		return E.New("shared-network has no enabled listener")
	}
	return nil
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	listenOptions := s.parent.listenOptions
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	listenOptions.Listen = common.Ptr(badoption.Addr(listenAddress))
	listenOptions.ListenPort = port
	listenOptions.BindInterface = ""
	socketAssign := s.dataPlane == sharedNetworkDataPlaneSocketAssign
	return listener.New(listener.Options{
		Context:             s.parent.ctx,
		Logger:              s.parent.logger,
		Network:             []string{network},
		Listen:              listenOptions,
		ConnectionHandler:   s,
		OOBPacketHandler:    s,
		DisablePacketOutput: true,
		TProxy:              socketAssign,
		// E5: MPTCP forced off only for socket_assign (SOCKMAP/sk_assign).
		ForceNoMPTCP:  socketAssign,
		SocketControl: s.parent.socketControl(ipv6Listener),
	})
}

func (s *sharedNetwork) registerListenerSockets() error {
	type registration struct {
		key      uint32
		listener syscall.Conn
	}
	var registrations []registration
	if s.tcp4 != nil {
		conn, ok := s.tcp4.TCPListener().(syscall.Conn)
		if !ok {
			return E.New("IPv4 TCP listener does not expose syscall connection")
		}
		registrations = append(registrations, registration{0, conn})
	}
	if s.udp4 != nil {
		registrations = append(registrations, registration{1, s.udp4.UDPConn()})
	}
	if s.tcp6 != nil {
		conn, ok := s.tcp6.TCPListener().(syscall.Conn)
		if !ok {
			return E.New("IPv6 TCP listener does not expose syscall connection")
		}
		registrations = append(registrations, registration{2, conn})
	}
	if s.udp6 != nil {
		registrations = append(registrations, registration{3, s.udp6.UDPConn()})
	}
	for _, registration := range registrations {
		raw, err := registration.listener.SyscallConn()
		if err != nil {
			return err
		}
		var registerErr error
		if err = raw.Control(func(fd uintptr) {
			registerErr = s.backend.RegisterListenerSocket(registration.key, int(fd))
		}); err != nil {
			return err
		}
		if registerErr != nil {
			return registerErr
		}
	}
	return nil
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpNat.Purge()
	s.dnsMux.Purge()
	// One coherent invalidation path per engine:
	// v3 republishStatic commits a new generation (flows/DNS miss until re-learn).
	// v2 bumps flow generation only.
	if s.engineV3 {
		if parent := s.parent.backendInstance(); parent != nil {
			if err := s.RefreshV3Static(parent); err != nil {
				s.parent.logger.Debug("eBPF v3 static republish after interface update: ", err)
			}
		} else if s.v3 != nil {
			if err := s.v3.InvalidateGeneration(); err != nil {
				s.parent.logger.Debug("eBPF v3 generation invalidate: ", err)
			}
		} else if s.backend != nil {
			_ = s.backend.InvalidateFlowDirect()
		}
	} else if s.flowVerdict && s.backend != nil {
		if err := s.backend.InvalidateFlowDirect(); err != nil {
			s.parent.logger.Debug("invalidate shared-network direct flow verdicts: ", err)
		}
	}
	if s.tc != nil {
		s.tc.Wake()
	}
}

// v3KernelSink adapts SharedDataplane to the lifecycle DataplaneSink surface.
type v3KernelSink struct {
	dp ECommon.SharedDataplane
}

func (s v3KernelSink) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.PublishStaticDirect(prefixes, generation, bank)
}
func (s v3KernelSink) PublishMACPolicies(entries []ebpfabi.MACPolicyEntry) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.PublishMACPolicies(entries)
}
func (s v3KernelSink) DeleteMergedStaticDirect(prefix netip.Prefix) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.DeleteMergedStaticDirect(prefix)
}
func (s v3KernelSink) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.WriteControlV3(enabled, flags, activeBank, generation, routingMark)
}
func (s v3KernelSink) Disable() error {
	if s.dp == nil {
		return nil
	}
	return s.dp.Disable()
}
func (s v3KernelSink) MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.MergeDynamicDirect(prefix, ttl)
}
func (s v3KernelSink) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.PutDirectFlow(protocol, source, destination, ttl)
}
func (s v3KernelSink) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.DeleteDirectFlow(protocol, source, destination)
}
func (s v3KernelSink) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	if s.dp == nil {
		return nil
	}
	return s.dp.PublishDNSHint(addr, direct, evidence, generation, ttl)
}
func (s v3KernelSink) InvalidateFlowDirect() error {
	if s.dp == nil {
		return nil
	}
	return s.dp.InvalidateFlowDirect()
}
func (s v3KernelSink) PolicyGeneration() uint32 {
	if s.dp == nil {
		return 0
	}
	return s.dp.PolicyGeneration()
}

// shouldLearnExactFlow is true when the kernel exact-flow map is armed.
func (s *sharedNetwork) shouldLearnExactFlow() bool {
	if s == nil {
		return false
	}
	if s.flowVerdict {
		return true
	}
	// engine=v3: SetFlowDirect(true) whenever engine=v3; learn bare-DIRECT after
	// userspace proves the leaf (gated by verdict.mode=learn on the caller).
	return s.engineV3
}

// revokeExactFlow drops a learned tuple after real failure (design §9 revoke).
func (s *sharedNetwork) revokeExactFlow(protocol uint8, client, dest netip.AddrPort) {
	if s == nil || !client.IsValid() || !dest.IsValid() {
		return
	}
	// A v3 lifecycle is created before the kernel backend is prepared.  If
	// preparation fails Start falls back to v2 but deliberately keeps the
	// lifecycle for close-time cleanup.  Never use that stale control model for
	// a v2 revoke: the tuple only exists in the v2 backend in that state.
	if s.engineV3 && s.v3 != nil {
		if err := s.v3.RevokeFlow(client, dest, protocol); err != nil {
			// A failed kernel delete can leave a stale exact-flow row.  Bump the
			// dataplane generation immediately: the TC program rejects rows from
			// the previous generation, while the lifecycle keeps the failed model
			// entry until the invalidation completes.
			s.parent.logger.Error("eBPF v3 flow revoke failed; invalidating exact-flow generation: ", err)
			if invalidateErr := s.v3.InvalidateGeneration(); invalidateErr != nil {
				s.parent.logger.Error("eBPF v3 exact-flow generation invalidate failed: ", invalidateErr)
				// Last-resort safety fuse: if the generation bump itself cannot
				// reach the kernel, stop accepting exact-flow verdicts so stale
				// rows cannot continue to bypass userspace.
				if s.backend != nil {
					if disableErr := s.backend.SetFlowDirect(false); disableErr != nil {
						s.parent.logger.Error("eBPF exact-flow safety disable failed: ", disableErr)
					}
				}
			}
		}
		return
	}
	if s.backend != nil {
		_ = s.backend.DeleteDirectFlow(protocol, client, dest)
	}
}

// learnV3Flow records a bare-direct exact-flow into the unified v3 control plane.
// When sink is bound, Lifecycle.LearnFlow also writes the kernel flow map — callers
// must not double-PutDirectFlow for the same tuple.
func (s *sharedNetwork) learnV3Flow(protocol uint8, client, dest netip.AddrPort) {
	if s == nil || !client.IsValid() || !dest.IsValid() {
		return
	}
	// See revokeExactFlow: engineV3 is the authoritative dataplane selection.
	// The lifecycle may outlive a failed v3 prepare, but must not absorb learns
	// while the live backend is v2.
	if s.engineV3 && s.v3 != nil {
		if err := s.v3.LearnFlow(client, dest, protocol, true, time.Now()); err != nil {
			s.parent.logger.Debug("eBPF v3 flow learn skipped: ", err)
		}
		return
	}
	// Fallback when lifecycle missing but kernel backend present.
	if s.backend != nil {
		if err := s.backend.PutDirectFlow(protocol, client, dest, 10*time.Minute); err != nil {
			s.parent.logger.Debug("eBPF v3 flow learn (backend) skipped: ", err)
		}
	}
}

// observeV3DNS mirrors DNS/FakeIP evidence into the unified control plane.
func (s *sharedNetwork) observeV3DNS(addr netip.Addr, direct bool, evidence uint8, ttl time.Duration) {
	if s == nil || !s.engineV3 || !addr.IsValid() {
		return
	}
	if s.v3 != nil {
		if err := s.v3.ObserveDNS(addr, direct, evidence, ttl, time.Now()); err != nil && s.parent != nil && s.parent.logger != nil {
			// DNS hints are advisory: a sink failure must not reject the DNS
			// response, but it must remain visible for diagnosing a degraded
			// kernel fast path.  Previously this error was silently discarded.
			s.parent.logger.Debug("eBPF v3 DNS hint publish skipped: ", err)
		}
		return
	}
	if s.backend != nil {
		if err := s.backend.PublishDNSHint(addr, direct, evidence, 0, ttl); err != nil && s.parent != nil && s.parent.logger != nil {
			s.parent.logger.Debug("eBPF DNS hint publish skipped: ", err)
		}
	}
}

// promoteV3Direct installs a destination /32|/128 for first-packet kernel DIRECT:
// DNS strong hint + active-bank static merge (no generation bump).
func (s *sharedNetwork) promoteV3Direct(addr netip.Addr, ttl time.Duration) {
	if s == nil {
		return
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// Serialize promotion with Close, full static-bank publication, and expiry
	// GC. The map and the live kernel bank must never disagree about whether a
	// prefix is still revocable.
	s.closeAccess.RLock()
	defer s.closeAccess.RUnlock()
	if !s.engineV3 || s.backend == nil || s.v3 == nil || !addr.IsValid() {
		return
	}
	s.v3PromoteAccess.Lock()
	defer s.v3PromoteAccess.Unlock()
	addr = addr.Unmap()
	bits := 32
	if !addr.Is4() {
		bits = 128
	}
	prefix := netip.PrefixFrom(addr, bits).Masked()
	// Evidence strong: dns_prefill / route already proved stable DIRECT.
	s.observeV3DNS(addr, true, 2 /* DNSEvidenceStrong */, ttl)
	var err error
	err = s.v3.MergeDynamicDirect(prefix, ttl)
	if err != nil {
		if s.parent != nil && s.parent.logger != nil {
			s.parent.logger.Debug("eBPF v3 merge static direct: ", err)
		}
		return
	}
	if s.v3Promoted == nil {
		s.v3Promoted = make(map[netip.Addr]time.Time)
	}
	s.v3Promoted[addr] = time.Now().Add(ttl)
}

// revokeV3Promotion removes a previously promoted /32|/128 when later DNS
// evidence marks the same address as proxy-routed (shared-IP generalisation
// guard: the kernel static entry must not outlive its promoting domain's
// policy). Only learn-promoted prefixes are revocable; snapshot-published
// bypass rules are never touched.
func (s *sharedNetwork) revokeV3Promotion(addr netip.Addr) {
	if s == nil {
		return
	}
	s.closeAccess.RLock()
	defer s.closeAccess.RUnlock()
	if !s.engineV3 || s.v3 == nil || !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	s.v3PromoteAccess.Lock()
	defer s.v3PromoteAccess.Unlock()
	_, tracked := s.v3Promoted[addr]
	if tracked {
		bits := 32
		if !addr.Is4() {
			bits = 128
		}
		prefix := netip.PrefixFrom(addr.Unmap(), bits).Masked()
		if err := s.v3.RevokeMergedStaticDirect(prefix); err != nil {
			if s.parent != nil && s.parent.logger != nil {
				s.parent.logger.Debug("eBPF v3 revoke promoted direct: ", err)
			}
			return
		}
		delete(s.v3Promoted, addr)
	}
	if !tracked {
		return
	}
	if s.parent != nil && s.parent.logger != nil {
		s.parent.logger.Info("eBPF v3 revoked promoted direct (shared-IP conflict): ", addr.String())
	}
}

// gcV3Promoted removes expired learned prefixes from both the in-process
// expiry table and the active v3 policy bank. Failures are retained for a
// later retry instead of silently losing the bookkeeping while leaving a
// stale kernel DIRECT entry installed.
func (s *sharedNetwork) gcV3Promoted(now time.Time) int {
	if s == nil {
		return 0
	}
	s.closeAccess.RLock()
	defer s.closeAccess.RUnlock()
	if !s.engineV3 || s.v3 == nil {
		return 0
	}
	s.v3PromoteAccess.Lock()
	defer s.v3PromoteAccess.Unlock()
	if len(s.v3Promoted) == 0 {
		return 0
	}
	removed := 0
	for addr, expiresAt := range s.v3Promoted {
		if now.Before(expiresAt) {
			continue
		}
		bits := 32
		if !addr.Is4() {
			bits = 128
		}
		prefix := netip.PrefixFrom(addr.Unmap(), bits).Masked()
		if err := s.v3.RevokeMergedStaticDirect(prefix); err != nil {
			if s.parent != nil && s.parent.logger != nil {
				s.parent.logger.Debug("eBPF v3 expired promotion revoke: ", err)
			}
			continue
		}
		delete(s.v3Promoted, addr)
		removed++
	}
	return removed
}

// publishV3StaticFromParent publishes the full static DIRECT snapshot:
// bypass_rule_set (+ promotions) ∪ pure-IP route→DIRECT sinks (design §5/§7).
// Always commits a new generation — even an empty snapshot — so stale entries miss.
func (s *sharedNetwork) publishV3StaticFromParent(parent *ECommon.Backend) error {
	if s == nil || s.backend == nil {
		return nil
	}
	s.closeAccess.RLock()
	defer s.closeAccess.RUnlock()
	s.v3PromoteAccess.Lock()
	defer s.v3PromoteAccess.Unlock()
	var routeRouter adapter.Router
	if r, ok := s.parent.router.(adapter.Router); ok {
		routeRouter = r
	}
	outbounds := service.FromContext[adapter.OutboundManager](s.parent.ctx)
	prefixes := collectV3StaticPrefixes(parent, routeRouter, outbounds)
	if s.engineV3 && s.v3 != nil {
		// Publish through Lifecycle so the in-process policy banks and the live
		// kernel inactive bank are committed as one control-plane operation.
		// Directly calling the backend here used to leave the memory model empty
		// while only its generation was updated.
		if err := s.v3.PublishStaticDirect(prefixes); err != nil {
			return err
		}
		// MAC identity policies ride the same refresh cadence so provider
		// reloads cannot leave a stale device verdict in v3_source_mac.
		if err := s.publishV3MACPolicies(routeRouter); err != nil {
			return err
		}
	} else if err := s.backend.PublishStaticDirect(prefixes, 0, 0); err != nil {
		return err
	}
	s.staticDirect = prefixes
	// The full snapshot rebuild wiped every learn-promoted merge.
	s.v3Promoted = nil
	s.parent.logger.Info("eBPF v3 static policy published: prefixes=", len(prefixes))
	return nil
}

// publishV3MACPolicies sinks MAC-only route rules into the kernel source
// identity map. Silent no-op unless policy_offload.mac_source_policy is on;
// only DIRECT and reject-method=drop rules are sinkable (see
// rule.CollectSourceMACPolicies) — everything else stays in userspace.
func (s *sharedNetwork) publishV3MACPolicies(routeRouter adapter.Router) error {
	var rules []adapter.Rule
	if routeRouter != nil {
		rules = routeRouter.Rules()
	}
	collected := R.CollectSourceMACPolicies(rules)
	entries := make([]ebpfabi.MACPolicyEntry, 0, len(collected))
	for _, policy := range collected {
		var key ebpfabi.MACKey
		copy(key.Addr[:], policy.MAC)
		value := ebpfabi.MACPolicyValue{
			Verdict:    uint8(policy.Verdict),
			Confidence: ebpfabi.ConfidenceAuthoritative,
		}
		if policy.Verdict == R.SourceMACOffloadBlock {
			value.ReasonCode = uint16(ebpfabi.ReasonStaticBlock)
		} else {
			value.ReasonCode = uint16(ebpfabi.ReasonStaticDirect)
		}
		entries = append(entries, ebpfabi.MACPolicyEntry{Key: key, Value: value})
	}
	return s.v3.PublishMACSourcePolicies(entries)
}

// probeXDP reports whether the installed kernel/driver supports native or
// skb XDP on the shared-network interfaces when the user explicitly enabled
// the experimental xdp block. It never installs a dataplane and never affects
// forwarding: the AF_XDP host adapter is still pending, so TC stays the live
// path. The result is logged so deployments on uncertain hardware (virtual
// NICs, older drivers) get an authoritative answer instead of silent failure.
func (s *sharedNetwork) probeXDP(parentBackend *ECommon.Backend) {
	if s == nil || s.parent == nil || !s.parent.sharedOptions.XDP.Enabled {
		return
	}
	for _, iface := range s.interfaces {
		nativeOK, skbOK, err := ECommon.XDPModeSupport(iface)
		switch {
		case err != nil:
			s.parent.logger.Warn("eBPF XDP capability probe failed on ", iface, ": ", err)
		case nativeOK:
			s.parent.logger.Info("eBPF XDP capability on ", iface, ": native supported (skb=", skbOK, "); AF_XDP host adapter pending, TC dataplane unchanged")
		case skbOK:
			s.parent.logger.Info("eBPF XDP capability on ", iface, ": skb mode only; AF_XDP host adapter pending, TC dataplane unchanged")
		default:
			s.parent.logger.Warn("eBPF XDP not supported by kernel/driver on ", iface, "; continuing with TC dataplane")
		}
	}
}

// RefreshV3Static republishes bypass prefixes after rule-set reload.
func (s *sharedNetwork) RefreshV3Static(parent *ECommon.Backend) error {
	if s == nil || !s.engineV3 {
		return nil
	}
	return s.publishV3StaticFromParent(parent)
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	s.v3PromoteAccess.Lock()
	s.v3Promoted = nil
	s.v3PromoteAccess.Unlock()
	s.udpNat.Purge()
	s.dnsMux.Close()
	s.closeTransparentWriters()
	if s.v3 != nil {
		_ = s.v3.Close()
		s.v3 = nil
	}
	var tcErr error
	if s.tc != nil {
		tcErr = s.tc.Close()
		// A failed detach must not prevent the remaining routes, maps, sockets,
		// and listeners from being released.  Keep the manager only when it
		// still owns attachments so a later Close can retry those detachments.
		if s.tc.IsClosed() {
			s.tc = nil
		}
	}
	var routeErr error
	if s.policyRoute != nil {
		routeErr = s.policyRoute.Close()
		if routeErr == nil {
			s.policyRoute = nil
		}
	}
	var backendErr error
	if s.backend != nil {
		backendErr = s.backend.Close()
		if s.backend.IsClosed() {
			s.backend = nil
		}
	}
	return E.Errors(tcErr, routeErr, backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	listeners := []*listener.Listener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	var closeErr error
	for _, current := range listeners {
		if current == nil {
			continue
		}
		closeErr = E.Errors(closeErr, common.Close(current))
	}
	return closeErr
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.closeAccess.Lock()
	defer s.closeAccess.Unlock()
	return s.tc == nil && s.policyRoute == nil && s.backend == nil &&
		s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *sharedNetwork) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if s.backend == nil {
		conn.Close()
		return
	}
	client := M.SocksaddrFromNet(conn.RemoteAddr()).AddrPort()
	redirect := M.SocksaddrFromNet(conn.LocalAddr()).AddrPort()
	original, err := s.backend.TakeOriginal(ECommon.ProtocolTCP, client, redirect)
	if err != nil {
		s.parent.logger.ErrorContext(ctx, "lookup shared-network TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = s.parent.Tag()
	metadata.InboundType = s.parent.Type()
	metadata.InboundInterface = sharedNetworkIngressInterface(original.IngressIfIndex)
	metadata.Source = M.SocksaddrFromNetIP(client)
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	// Debug: production gateways log multi-k connections/s at Info otherwise.
	s.parent.logger.DebugContext(ctx, "shared-network inbound connection to ", metadata.Destination)
	if dest := metadata.Destination.Addr; dest.IsValid() {
		s.parent.bypassMiss.ObserveTCP(s.parent, dest)
	}
	s.parent.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if s.backend == nil {
		return
	}
	client := source.AddrPort()
	var redirect netip.AddrPort
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		var err error
		redirect, err = redir.GetOriginalDestinationFromOOB(oob)
		if err != nil {
			s.udpWarnings.packetInfo.warnError(s.parent.logger, "read shared-network UDP original destination: ", err)
			return
		}
	} else {
		redirectAddress, err := redirectAddressFromOOB(oob)
		if err != nil {
			s.udpWarnings.packetInfo.warnError(s.parent.logger, "read shared-network UDP token address: ", err)
			return
		}
		redirect = netip.AddrPortFrom(redirectAddress, s.listenPort)
	}
	original, err := s.backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
	if err != nil {
		s.udpWarnings.originalDestination.warnError(s.parent.logger, "lookup shared-network UDP original destination: ", err)
		return
	}
	released := s.udpClients.setBinding(client, original.Destination, redirect.Addr(), false)
	s.deleteUDPRedirects(client, released)
	if original.Destination.Port() == 53 {
		s.dnsMux.NewPacket(buffer.Bytes(), source, M.SocksaddrFromNetIP(original.Destination), original.IngressIfIndex)
		return
	}
	s.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.IngressIfIndex)
}

func (s *sharedNetwork) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     s.parent.Tag(),
		InboundType: s.parent.Type(),
		Source:      source,
		Destination: destination,
	}
	if interfaceName, loaded := ctx.Value(sharedNetworkIngressInterfaceKey{}).(string); loaded {
		metadata.InboundInterface = interfaceName
	}
	//nolint:staticcheck
	metadata.InboundDetour = s.parent.listenOptions.Detour
	// Packet connections include short-lived DNS/QUIC flows and can be created
	// thousands of times per second on a gateway.  Logging every flow at info
	// level causes allocation pressure and can grow the log by hundreds of MiB.
	// Keep the diagnostic available without enabling it in normal operation.
	s.parent.logger.DebugContext(ctx, "shared-network inbound packet connection to ", destination)
	s.parent.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (s *sharedNetwork) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(s.parent.ctx)
	if ifIndex, loaded := userData.(uint32); loaded {
		ctx = context.WithValue(ctx, sharedNetworkIngressInterfaceKey{}, sharedNetworkIngressInterface(ifIndex))
	}
	client := source.AddrPort()
	if s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		writer := &sharedPacketWriter{shared: s, client: client}
		return true, ctx, writer, func(error) { writer.closeTransparent() }
	}
	clientState := s.udpClients.retain(client)
	writer := &sharedPacketWriter{
		shared:      s,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		common.Close(common.PtrOrNil(writer.conn))
		s.deleteUDPRedirects(client, s.udpClients.delete(client, clientState))
	}
}

func (s *sharedNetwork) deleteUDPRedirects(client netip.AddrPort, redirects []netip.Addr) {
	if s.backend == nil || s.dataPlane == sharedNetworkDataPlaneSocketAssign {
		return
	}
	for _, address := range redirects {
		redirect := netip.AddrPortFrom(address, s.listenPort)
		if err := s.backend.DeleteRedirect(ECommon.ProtocolUDP, client, redirect); err != nil {
			s.udpWarnings.cleanup.warnValueError(s.parent.logger, "delete shared-network UDP redirect mapping for ", redirect, ": ", err)
		}
	}
}

type sharedPacketWriter struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
	conn        *net.UDPConn
	bound       M.Socksaddr
	transparent *transparentWriterEntry
}

type transparentWriterEntry struct {
	conn transparentPacketConn
	refs int
}

type transparentPacketConn interface {
	WriteToUDPAddrPort(buffer []byte, destination netip.AddrPort) (int, error)
	Close() error
}

func (w *sharedPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if w.shared.dataPlane == sharedNetworkDataPlaneSocketAssign {
		return w.writeTransparent(buffer, destination)
	}
	if w.clientState == nil {
		return E.New("missing shared-network UDP client state for ", destination)
	}
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing shared-network UDP token for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		if w.shared.udp4 == nil {
			return E.New("shared-network IPv4 UDP listener is unavailable")
		}
		udpConn = w.shared.udp4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		if w.shared.udp6 == nil {
			return E.New("shared-network IPv6 UDP listener is unavailable")
		}
		udpConn = w.shared.udp6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func (w *sharedPacketWriter) writeTransparent(buffer *buf.Buffer, destination M.Socksaddr) error {
	if w.transparent == nil || w.bound != destination {
		w.closeTransparent()
		entry, err := w.shared.retainTransparentWriter(destination)
		if err != nil {
			return err
		}
		w.transparent = entry
		w.bound = destination
	}
	udpConn := w.transparent.conn
	_, err := udpConn.WriteToUDPAddrPort(buffer.Bytes(), w.client)
	if err != nil && isTransparentSocketFatal(err) {
		// Only tear down the shared socket when the descriptor itself is no
		// longer usable.  Per-packet/transient failures such as ENOBUFS must not
		// invalidate the socket for every client sharing this source address.
		w.shared.invalidateTransparentWriter(destination.AddrPort(), w.transparent)
		w.transparent = nil
		w.bound = M.Socksaddr{}
	}
	return err
}

func isTransparentSocketFatal(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, unix.EBADF) || errors.Is(err, unix.ENOTSOCK)
}

func (s *sharedNetwork) retainTransparentWriter(destination M.Socksaddr) (*transparentWriterEntry, error) {
	key := destination.AddrPort()
	s.transparentAccess.Lock()
	defer s.transparentAccess.Unlock()
	if current := s.transparentWriters[key]; current != nil {
		current.refs++
		return current, nil
	}
	current := s.udp4
	if destination.Addr.Is6() {
		current = s.udp6
	}
	if current == nil {
		return nil, E.New("shared-network transparent UDP listener is unavailable")
	}
	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	listenConfig.Control = control.Append(listenConfig.Control, redir.TProxyWriteBack())
	packetConn, err := current.ListenPacket(listenConfig, s.parent.ctx, "udp", destination.String())
	if err != nil {
		return nil, err
	}
	entry := &transparentWriterEntry{conn: packetConn.(*net.UDPConn), refs: 1}
	if s.transparentWriters == nil {
		s.transparentWriters = make(map[netip.AddrPort]*transparentWriterEntry)
	}
	s.transparentWriters[key] = entry
	return entry, nil
}

func (w *sharedPacketWriter) closeTransparent() {
	if w.transparent == nil {
		return
	}
	w.shared.releaseTransparentWriter(w.bound.AddrPort(), w.transparent)
	w.transparent = nil
	w.bound = M.Socksaddr{}
}

func (s *sharedNetwork) releaseTransparentWriter(key netip.AddrPort, writer *transparentWriterEntry) {
	s.transparentAccess.Lock()
	if s.transparentWriters[key] == writer {
		writer.refs--
		if writer.refs == 0 {
			delete(s.transparentWriters, key)
			_ = writer.conn.Close()
		}
	}
	s.transparentAccess.Unlock()
}

func (s *sharedNetwork) invalidateTransparentWriter(key netip.AddrPort, writer *transparentWriterEntry) {
	s.transparentAccess.Lock()
	if s.transparentWriters[key] == writer {
		delete(s.transparentWriters, key)
		_ = writer.conn.Close()
	}
	s.transparentAccess.Unlock()
}

func (s *sharedNetwork) closeTransparentWriters() {
	s.transparentAccess.Lock()
	for key, writer := range s.transparentWriters {
		_ = writer.conn.Close()
		delete(s.transparentWriters, key)
	}
	s.transparentAccess.Unlock()
}

type sharedTCManager struct {
	backend      ECommon.SharedDataplane
	logger       interfaceLogger
	interfaces   []string
	priority     uint16
	enableIPv4   bool
	attachEgress bool
	access       sync.Mutex
	attachments  map[string]*sharedTCAttachment
	enabled      bool
	cancel       context.CancelFunc
	done         chan struct{}
	wake         chan struct{}
}

type interfaceLogger interface {
	Info(args ...any)
	Warn(args ...any)
}

type sharedTCAttachment struct {
	interfaceName        string
	ifindex              int
	ingress              *netlink.BpfFilter
	egress               *netlink.BpfFilter
	restoreRouteLocalnet bool
}

func (m *sharedTCManager) Start() error {
	if err := m.reconcile(); err != nil {
		return E.Errors(err, m.closeAttachments())
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.wake = make(chan struct{}, 1)
	go m.loop(ctx)
	return nil
}

func (m *sharedTCManager) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(sharedNetworkRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		if err := m.reconcile(); err != nil {
			m.logger.Warn("refresh eBPF shared-network interfaces: ", err)
		}
	}
}

func (m *sharedTCManager) Wake() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sharedTCManager) reconcile() error {
	hostAddresses, err := sharedHostAddresses()
	if err != nil {
		return err
	}
	if err = m.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	desired := make(map[string]netlink.Link, len(m.interfaces))
	for _, interfaceName := range m.interfaces {
		link, linkErr := netlink.LinkByName(interfaceName)
		if isSharedNetworkLinkNotFound(linkErr) {
			continue
		}
		if linkErr != nil {
			return E.Cause(linkErr, "find shared-network interface ", interfaceName)
		}
		if linkErr = validateSharedNetworkLink(link); linkErr != nil {
			return linkErr
		}
		desired[interfaceName] = link
	}
	m.access.Lock()
	defer m.access.Unlock()
	for interfaceName, attachment := range m.attachments {
		link, loaded := desired[interfaceName]
		if loaded && link.Attrs().Index == attachment.ifindex {
			continue
		}
		if err = m.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach stale shared-network interface ", interfaceName)
		}
		if err = m.backend.DeleteInterfaceMAC(uint32(attachment.ifindex)); err != nil {
			return E.Cause(err, "delete stale shared-network interface MAC ", interfaceName)
		}
		delete(m.attachments, interfaceName)
		m.logger.Info("eBPF shared-network detached from ", interfaceName)
	}
	for interfaceName, link := range desired {
		if _, loaded := m.attachments[interfaceName]; loaded {
			continue
		}
		if err = m.backend.UpdateInterfaceMAC(uint32(link.Attrs().Index), link.Attrs().HardwareAddr); err != nil {
			return E.Cause(err, "register shared-network interface MAC ", interfaceName)
		}
		attachment, attachErr := attachSharedTC(link, m.backend, m.enableIPv4, m.attachEgress, m.priority)
		if attachErr != nil {
			_ = m.backend.DeleteInterfaceMAC(uint32(link.Attrs().Index))
			return E.Cause(attachErr, "attach eBPF shared-network to ", interfaceName)
		}
		m.attachments[interfaceName] = attachment
		m.logger.Info("eBPF shared-network attached to ", interfaceName, " (ifindex=", link.Attrs().Index, ")")
	}
	return m.updateEnabledLocked(len(m.attachments) > 0)
}

func isSharedNetworkLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func validateSharedNetworkLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return E.New("invalid shared-network interface")
	}
	if len(link.Attrs().HardwareAddr) != 6 {
		return E.New("shared-network interface ", link.Attrs().Name, " is not Ethernet-like")
	}
	return nil
}

func (m *sharedTCManager) updateEnabledLocked(enabled bool) error {
	if m.enabled == enabled {
		return nil
	}
	var err error
	if enabled {
		err = m.backend.Enable()
	} else {
		err = m.backend.Disable()
	}
	if err == nil {
		m.enabled = enabled
	}
	return err
}

func (m *sharedTCManager) detachLocked(attachment *sharedTCAttachment) error {
	detachErr := E.Errors(
		detachSharedTCFilter(attachment.ingress),
		detachSharedTCFilter(attachment.egress),
	)
	if detachErr != nil {
		return detachErr
	}
	if attachment.restoreRouteLocalnet {
		return restoreSharedRouteLocalnet(attachment.interfaceName)
	}
	return nil
}

func (m *sharedTCManager) InterfaceString() string {
	m.access.Lock()
	defer m.access.Unlock()
	names := make([]string, 0, len(m.attachments))
	for name := range m.attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "waiting for " + strings.Join(m.interfaces, ", ")
	}
	return strings.Join(names, ", ")
}

func (m *sharedTCManager) Close() error {
	if m == nil {
		return nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	return m.closeAttachments()
}

func (m *sharedTCManager) IsClosed() bool {
	if m == nil {
		return true
	}
	m.access.Lock()
	defer m.access.Unlock()
	return m.cancel == nil && len(m.attachments) == 0 && !m.enabled
}

func (m *sharedTCManager) closeAttachments() error {
	m.access.Lock()
	defer m.access.Unlock()
	var closeErr error
	if err := m.updateEnabledLocked(false); err != nil {
		closeErr = err
	}
	for name, attachment := range m.attachments {
		if err := m.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "detach shared-network interface ", name))
			continue
		}
		if err := m.backend.DeleteInterfaceMAC(uint32(attachment.ifindex)); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "delete shared-network interface MAC ", name))
		}
		delete(m.attachments, name)
	}
	return closeErr
}

func attachSharedTC(link netlink.Link, backend ECommon.SharedDataplane, enableIPv4 bool, attachEgress bool, priority uint16) (*sharedTCAttachment, error) {
	if priority == 0 {
		priority = sharedNetworkTCPriorityDefault
	}
	restoreRouteLocalnet := false
	if enableIPv4 && attachEgress {
		var err error
		restoreRouteLocalnet, err = enableSharedRouteLocalnet(link.Attrs().Name)
		if err != nil {
			return nil, err
		}
	}
	if err := ensureClsact(link); err != nil {
		if restoreRouteLocalnet {
			_ = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, err
	}
	var egress *netlink.BpfFilter
	var err error
	if attachEgress {
		egress, err = attachSharedTCFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.EgressProgramFD(),
			"sb_share_out",
			sharedEgressFilterHandle,
			priority,
		)
		if err != nil {
			if restoreRouteLocalnet {
				_ = restoreSharedRouteLocalnet(link.Attrs().Name)
			}
			return nil, err
		}
	} else if err = removeOwnedSharedTCFilter(
		link,
		netlink.HANDLE_MIN_EGRESS,
		"sb_share_out",
		sharedEgressFilterHandle,
		priority,
	); err != nil {
		return nil, E.Cause(err, "remove stale shared-network egress filter")
	}
	ingress, err := attachSharedTCFilter(
		link,
		netlink.HANDLE_MIN_INGRESS,
		backend.IngressProgramFD(),
		"sb_share_in",
		sharedIngressFilterHandle,
		priority,
	)
	if err != nil {
		var routeErr error
		if restoreRouteLocalnet {
			routeErr = restoreSharedRouteLocalnet(link.Attrs().Name)
		}
		return nil, E.Errors(err, detachSharedTCFilter(egress), routeErr)
	}
	return &sharedTCAttachment{
		interfaceName:        link.Attrs().Name,
		ifindex:              link.Attrs().Index,
		ingress:              ingress,
		egress:               egress,
		restoreRouteLocalnet: restoreRouteLocalnet,
	}, nil
}

func sharedRouteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRouteLocalnet(interfaceName string) (bool, error) {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) == "1" {
		return false, nil
	}
	if strings.TrimSpace(string(value)) != "0" {
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
	if err = os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return false, E.Cause(err, "enable route_localnet for ", interfaceName)
	}
	return true, nil
}

func restoreSharedRouteLocalnet(interfaceName string) error {
	path := sharedRouteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}

func attachSharedTCFilter(link netlink.Link, parent uint32, programFD int, programName string, handle uint16, priority uint16) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("shared-network eBPF program is unavailable")
	}
	if priority == 0 {
		priority = sharedNetworkTCPriorityDefault
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if existing.Attrs().Handle != filterHandle || existing.Attrs().Priority != priority {
				return nil, E.New("TC filter ownership conflict on ", link.Attrs().Name, " for ", programName)
			}
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func removeOwnedSharedTCFilter(link netlink.Link, parent uint32, programName string, handle uint16, priority uint16) error {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if existing.Attrs().Handle != filterHandle || existing.Attrs().Priority != priority {
				return E.New("TC filter ownership conflict on ", link.Attrs().Name, " for ", programName)
			}
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	return nil
}

func detachSharedTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func ensureClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func sharedHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, E.Cause(err, "list interfaces for shared-network host bypass")
	}
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		interfaceAddresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, E.Cause(addressErr, "list addresses for interface ", networkInterface.Name)
		}
		for _, interfaceAddress := range interfaceAddresses {
			prefix, parseErr := netip.ParsePrefix(interfaceAddress.String())
			if parseErr == nil {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}
	return addresses, nil
}
