//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_shared_network_prepare(
	const uint8_t *object,
	size_t object_size,
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	int dns_direct_ipv4_map_fd,
	int dns_direct_ipv6_map_fd,
	bool data_plane_v2,
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_prepare(
		object,
		object_size,
		bypass_ipv4_map_fd,
		bypass_ipv6_map_fd,
		dns_direct_ipv4_map_fd,
		dns_direct_ipv6_map_fd,
		data_plane_v2,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_shared_network_close(
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_shared_network_purge_token_flow(
	struct sb_ebpf_shared_network_runtime *runtime,
	const struct sb_shared_original_key *match,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_purge_token_flow(runtime, match);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	ebpfabi "github.com/sagernet/sing-box/common/ebpf/v3"
	"golang.org/x/sys/unix"
)

const SharedNetworkMapCapacity = 16384

const (
	sharedStatIngressRedirects uint32 = iota
	sharedStatIngressBypass
	sharedStatIngressDrops
	sharedStatEgressRestores
	sharedStatEgressReverseMisses
	sharedStatTokenFailures
	sharedStatRewriteFailures
	sharedStatSocketAssignments
	sharedStatSocketAssignFailures
	sharedStatFlowUpdateFailures
	sharedStatFallbackOpen
	sharedStatEstablishedBypass
	sharedStatParseFailures
	sharedStatPolicyBypass
	sharedStatListenerMisses
	sharedStatCount
)

//go:embed native/shared_network.bpf.o
var sharedNetworkV1Object []byte

//go:embed native/shared_network_v2.bpf.o
var sharedNetworkV2Object []byte

type sharedNetworkControl struct {
	Enabled        uint32
	Flags          uint32
	BridgePort     uint16
	Reserved       uint16
	IPv4Prefix     [4]byte
	IPv4PrefixBits uint8
	IPv6PrefixBits uint8
	Reserved2      [2]byte
	IPv6Prefix     [16]byte
	RoutingMark    uint32
	FlowGeneration uint32
}

type sharedNetworkFlowKey struct {
	Family       uint8
	Protocol     uint8
	ClientPort   uint16
	OriginalPort uint16
	Reserved     uint16
	ClientAddr   [16]byte
	OriginalAddr [16]byte
}

type sharedNetworkFlowValue struct {
	Generation uint32
	Reserved   uint32
	ExpiresNs  uint64
}

type sharedNetworkRedirectKey struct {
	Family       uint8
	Protocol     uint8
	RedirectPort uint16
	RedirectAddr [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type sharedNetworkInterfaceMAC struct {
	Addr     [6]byte
	Reserved [2]byte
}

const (
	sharedNetworkFlagIPv4 = 1 << iota
	sharedNetworkFlagIPv6
	sharedNetworkFlagTCP
	sharedNetworkFlagUDP
	sharedNetworkFlagDNSHijack
	sharedNetworkFlagDropUDP443
	sharedNetworkFlagSocketAssign
	sharedNetworkFlagFlowDirect
)

type SharedNetworkBackend struct {
	access sync.RWMutex
	// mapAccess serializes userspace updates to the shared maps while access
	// keeps the native runtime alive.  In particular, it makes a flow update
	// and a paired delete/consume operation atomic with respect to each other
	// without holding the lifecycle writer lock on every packet.
	mapAccess       sync.RWMutex
	runtime         *C.struct_sb_ebpf_shared_network_runtime
	control         sharedNetworkControl
	hostIPv4        []netip.Prefix
	hostIPv6        []netip.Prefix
	originalDstLost atomic.Uint64
	dataPlaneV2     bool
	v2InterfaceMAC  map[uint32]sharedNetworkInterfaceMAC
}

func PrepareSharedNetwork(
	parent *Backend,
	bridgePort uint16,
	enableTCP bool,
	enableUDP bool,
	redirectIPv4 netip.Prefix,
	redirectIPv6 netip.Prefix,
	dropUDP443 bool,
	socketAssign bool,
	routingMark uint32,
) (*SharedNetworkBackend, error) {
	if parent == nil {
		return nil, osErrClosed
	}
	if bridgePort == 0 {
		return nil, E.New("missing shared-network listener port")
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing shared-network redirect address")
	}
	sharedNetworkObject := sharedNetworkV1Object
	if socketAssign {
		sharedNetworkObject = sharedNetworkV2Object
	}
	if len(sharedNetworkObject) == 0 {
		return nil, E.New("missing embedded shared-network eBPF object")
	}

	runtimeState := (*C.struct_sb_ebpf_shared_network_runtime)(C.calloc(
		1,
		C.size_t(C.sizeof_struct_sb_ebpf_shared_network_runtime),
	))
	if runtimeState == nil {
		return nil, E.New("allocate shared-network token runtime")
	}
	parent.access.RLock()
	if parent.runtime == nil {
		parent.access.RUnlock()
		C.free(unsafe.Pointer(runtimeState))
		return nil, osErrClosed
	}
	hijackDNS := parent.hijackDNS
	dnsDirect4 := parent.dnsDirectIPv4CIDRMap
	dnsDirect6 := parent.dnsDirectIPv6CIDRMap
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkObject[0])),
		C.size_t(len(sharedNetworkObject)),
		C.int(parent.bypassIPv4CIDRMap),
		C.int(parent.bypassIPv6CIDRMap),
		C.int(dnsDirect4),
		C.int(dnsDirect6),
		C.bool(socketAssign),
		runtimeState,
		&savedErrno,
	)
	parent.access.RUnlock()
	if result != 0 {
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFOperationError(
			"prepare shared-network programs",
			syscall.Errno(savedErrno),
		)
	}

	backend := &SharedNetworkBackend{runtime: runtimeState, dataPlaneV2: socketAssign, v2InterfaceMAC: make(map[uint32]sharedNetworkInterfaceMAC)}
	backend.control.BridgePort = bridgePort
	if enableTCP {
		backend.control.Flags |= sharedNetworkFlagTCP
	}
	if enableUDP {
		backend.control.Flags |= sharedNetworkFlagUDP
	}
	if hijackDNS {
		backend.control.Flags |= sharedNetworkFlagDNSHijack
	}
	if dropUDP443 {
		backend.control.Flags |= sharedNetworkFlagDropUDP443
	}
	if socketAssign {
		if routingMark == 0 {
			_ = backend.Close()
			return nil, E.New("missing shared-network socket-assignment routing mark")
		}
		backend.control.Flags |= sharedNetworkFlagSocketAssign
		backend.control.RoutingMark = routingMark
	}
	if redirectIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv4
		backend.control.IPv4Prefix = redirectIPv4.Addr().As4()
		backend.control.IPv4PrefixBits = uint8(redirectIPv4.Bits())
	}
	if redirectIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv6
		backend.control.IPv6Prefix = redirectIPv6.Addr().As16()
		backend.control.IPv6PrefixBits = uint8(redirectIPv6.Bits())
	}
	if err := backend.updateControl(false); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "initialize shared-network control")
	}
	return backend, nil
}

func (b *SharedNetworkBackend) RegisterListenerSocket(key uint32, fd int) error {
	if b == nil || key >= 4 || fd < 0 {
		return E.New("invalid shared-network listener socket")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	value := uint64(fd)
	return updateMapWithFlags(
		int(b.runtime.listener_socket_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
		0,
	)
}

// SetFlowDirect enables the dae-style exact-flow direct fast path. It is kept
// off unless the caller explicitly selects socket_assign, because token mode
// cannot guarantee that a direct flow preserves the original routing tuple.
func (b *SharedNetworkBackend) SetFlowDirect(enabled bool) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if b.control.FlowGeneration == 0 {
		b.control.FlowGeneration = 1
	}
	if enabled {
		b.control.Flags |= 1 << 7
	} else {
		b.control.Flags &^= 1 << 7
	}
	return b.updateControl(b.control.Enabled != 0)
}

func makeSharedNetworkFlowKey(protocol uint8, source, destination netip.AddrPort) (sharedNetworkFlowKey, error) {
	if !source.IsValid() || !destination.IsValid() || source.Port() == 0 || destination.Port() == 0 {
		return sharedNetworkFlowKey{}, E.New("invalid shared-network direct flow tuple")
	}
	var key sharedNetworkFlowKey
	key.Protocol = protocol
	key.ClientPort = source.Port()
	key.OriginalPort = destination.Port()
	if err := putAddress(&key.Family, &key.ClientAddr, source.Addr()); err != nil {
		return sharedNetworkFlowKey{}, E.Cause(err, "invalid shared-network flow source")
	}
	var family uint8
	if err := putAddress(&family, &key.OriginalAddr, destination.Addr()); err != nil {
		return sharedNetworkFlowKey{}, E.Cause(err, "invalid shared-network flow destination")
	}
	if family != key.Family {
		return sharedNetworkFlowKey{}, E.New("shared-network flow tuple families do not match")
	}
	return key, nil
}

// PutDirectFlow publishes one exact source/destination flow after userspace
// routing has proven the outbound is truly direct. The deadline uses the same
// CLOCK_MONOTONIC base as bpf_ktime_get_ns.
func (b *SharedNetworkBackend) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = 45 * time.Second
	}
	key, err := makeSharedNetworkFlowKey(protocol, source, destination)
	if err != nil {
		return err
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil || b.control.Flags&(1<<7) == 0 {
		return osErrClosed
	}
	value := sharedNetworkFlowValue{Generation: b.control.FlowGeneration, ExpiresNs: expires}
	if err = updateMap(int(b.runtime.flow_direct_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "update shared-network direct flow map")
	}
	return nil
}

// InvalidateFlowDirect advances the policy generation. Stale entries remain
// bounded in the kernel map and are ignored/deleted lazily by TC.
func (b *SharedNetworkBackend) InvalidateFlowDirect() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	b.control.FlowGeneration++
	if b.control.FlowGeneration == 0 {
		b.control.FlowGeneration = 1
	}
	return b.updateControl(b.control.Enabled != 0)
}

func (b *SharedNetworkBackend) updateControl(enabled bool) error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	control := b.control
	control.Enabled = 0
	if enabled {
		control.Enabled = 1
	}
	key := uint32(0)
	if err := updateMap(
		int(b.runtime.control_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&control),
	); err != nil {
		return err
	}
	b.control.Enabled = control.Enabled
	return nil
}

func (b *SharedNetworkBackend) Enable() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.updateControl(true)
}

func (b *SharedNetworkBackend) UpdateInterfaceMAC(ifIndex uint32, hardwareAddress []byte) error {
	if b == nil || len(hardwareAddress) != 6 {
		return E.New("invalid shared-network interface MAC")
	}
	var value sharedNetworkInterfaceMAC
	copy(value.Addr[:], hardwareAddress)
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if b.dataPlaneV2 {
		if err := updateMap(int(b.runtime.interface_mac_map_fd), unsafe.Pointer(&value), unsafe.Pointer(&ifIndex)); err != nil {
			return err
		}
		b.v2InterfaceMAC[ifIndex] = value
		return nil
	}
	return updateMap(int(b.runtime.interface_mac_map_fd), unsafe.Pointer(&ifIndex), unsafe.Pointer(&value))
}

func (b *SharedNetworkBackend) DeleteInterfaceMAC(ifIndex uint32) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if b.dataPlaneV2 {
		value, loaded := b.v2InterfaceMAC[ifIndex]
		if !loaded {
			return nil
		}
		err := deleteMap(int(b.runtime.interface_mac_map_fd), unsafe.Pointer(&value))
		if errors.Is(err, syscall.ENOENT) {
			err = nil
		}
		if err == nil {
			delete(b.v2InterfaceMAC, ifIndex)
		}
		return err
	}
	err := deleteMap(int(b.runtime.interface_mac_map_fd), unsafe.Pointer(&ifIndex))
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func (b *SharedNetworkBackend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	return b.updateControl(false)
}

func (b *SharedNetworkBackend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.ingress_prog_fd)
}

func (b *SharedNetworkBackend) EgressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.egress_prog_fd)
}

func (b *SharedNetworkBackend) RuntimeStats() (SharedNetworkRuntimeStats, error) {
	if b == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	var values [sharedStatCount]uint64
	for key := uint32(0); key < sharedStatCount; key++ {
		if err := lookupMap(
			int(b.runtime.stats_map_fd),
			unsafe.Pointer(&key),
			unsafe.Pointer(&values[key]),
		); err != nil {
			return SharedNetworkRuntimeStats{}, err
		}
	}
	return SharedNetworkRuntimeStats{
		IngressRedirects:     values[sharedStatIngressRedirects],
		IngressBypass:        values[sharedStatIngressBypass],
		IngressDrops:         values[sharedStatIngressDrops],
		EgressRestores:       values[sharedStatEgressRestores],
		EgressReverseMisses:  values[sharedStatEgressReverseMisses],
		TokenFailures:        values[sharedStatTokenFailures],
		RewriteFailures:      values[sharedStatRewriteFailures],
		SocketAssignments:    values[sharedStatSocketAssignments],
		SocketAssignFailures: values[sharedStatSocketAssignFailures],
		FlowUpdateFailures:   values[sharedStatFlowUpdateFailures],
		FallbackOpen:         values[sharedStatFallbackOpen],
		EstablishedBypass:    values[sharedStatEstablishedBypass],
		ParseFailures:        values[sharedStatParseFailures],
		PolicyBypass:         values[sharedStatPolicyBypass],
		ListenerMisses:       values[sharedStatListenerMisses],
		OriginalDstLost:      b.originalDstLost.Load(),
	}, nil
}

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, false)
}

// TakeOriginal returns and consumes an original-destination entry.  TCP only
// needs the tuple while accepting a connection, whereas UDP may deliver many
// datagrams for the same flow through the shared listener and must use
// LookupOriginal for the whole flow lifetime.
func (b *SharedNetworkBackend) TakeOriginal(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, true)
}

func (b *SharedNetworkBackend) lookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, osErrClosed
	}
	key, err := makeSharedNetworkRedirectKey(protocol, client, redirect)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if deleteAfterLookup {
		b.mapAccess.Lock()
		defer b.mapAccess.Unlock()
	} else {
		b.mapAccess.RLock()
		defer b.mapAccess.RUnlock()
	}
	if b.runtime == nil {
		return OriginalDestination{}, osErrClosed
	}
	var original originalDestination
	if err = lookupMap(
		int(b.runtime.redirect_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&original),
	); err != nil {
		b.originalDstLost.Add(1)
		return OriginalDestination{}, E.Cause(err, "lookup shared-network original destination")
	}
	if deleteAfterLookup {
		if err = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key)); err != nil && !errors.Is(err, unix.ENOENT) {
			return OriginalDestination{}, E.Cause(err, "delete consumed shared-network original destination")
		}
	}
	address, err := originalDestinationAddress(original)
	if err != nil {
		return OriginalDestination{}, err
	}
	return OriginalDestination{
		Destination:    netip.AddrPortFrom(address, original.Port),
		IngressIfIndex: uint32(original.SocketCookie),
	}, nil
}

func makeSharedNetworkRedirectKey(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) (sharedNetworkRedirectKey, error) {
	var key sharedNetworkRedirectKey
	key.Protocol = protocol
	key.RedirectPort = redirect.Port()
	key.ClientPort = client.Port()
	if err := putAddress(&key.Family, &key.RedirectAddr, redirect.Addr()); err != nil {
		return sharedNetworkRedirectKey{}, E.Cause(err, "invalid shared-network redirect address")
	}
	var clientFamily uint8
	if err := putAddress(&clientFamily, &key.ClientAddr, client.Addr()); err != nil {
		return sharedNetworkRedirectKey{}, E.Cause(err, "invalid shared-network client address")
	}
	if clientFamily != key.Family {
		return sharedNetworkRedirectKey{}, E.New("shared-network client and redirect address families do not match")
	}
	return key, nil
}

// DeleteMergedStaticDirect is v3-only; the v2/token data plane has no
// revocable merged static surface.
func (b *SharedNetworkBackend) DeleteMergedStaticDirect(prefix netip.Prefix) error {
	if len(prefix.Addr().As4()) == 0 {
		return E.New("invalid prefix")
	}
	return E.New("DeleteMergedStaticDirect requires engine=v3")
}

// MergeDynamicDirect is v3-only; returning an explicit error prevents a
// legacy engine from silently dropping a learned DIRECT promotion.
func (b *SharedNetworkBackend) MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error {
	if !prefix.IsValid() || ttl <= 0 {
		return E.New("invalid dynamic direct promotion")
	}
	return E.New("MergeDynamicDirect requires engine=v3")
}

// PublishMACPolicies is v2-specific: the source-MAC identity policy is a v3
// feature and the token data plane never consumes it, so this surface only
// rejects explicitly instead of silently ignoring a misconfigured engine.
func (b *SharedNetworkBackend) PublishMACPolicies(entries []ebpfabi.MACPolicyEntry) error {
	if len(entries) == 0 {
		return nil
	}
	return E.New("source-MAC policy requires engine=v3")
}

func originalDestinationAddress(original originalDestination) (netip.Addr, error) {
	switch original.Family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(original.Addr[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(original.Addr), nil
	default:
		return netip.Addr{}, E.New("invalid original destination family: ", original.Family)
	}
}

func (b *SharedNetworkBackend) DeleteRedirect(
	protocol uint8,
	client netip.AddrPort,
	redirect netip.AddrPort,
) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeSharedNetworkRedirectKey(protocol, client, redirect)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	err = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key))
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	// Token mode also published original_to_token / token_to_original rows.
	// Leaving them behind let a reply to a stale token address rewrite to a
	// dead original until LRU pressure evicted the row, so purge the token
	// state for this flow tuple as part of the delete. socket_assign builds
	// never publish token rows and the helper is a no-op there.
	if !b.dataPlaneV2 {
		var match C.struct_sb_shared_original_key
		match.ifindex = 0
		match.family = C.uint8_t(key.Family)
		match.protocol = C.uint8_t(key.Protocol)
		match.client_port = C.uint16_t(key.ClientPort)
		match.original_port = C.uint16_t(key.RedirectPort)
		match.reserved = 0
		for i := range key.ClientAddr {
			match.client_addr[i] = C.__u8(key.ClientAddr[i])
		}
		for i := range key.RedirectAddr {
			match.original_addr[i] = C.__u8(key.RedirectAddr[i])
		}
		var savedErrno C.int
		if purgeErr := C.singbox_ebpf_shared_network_purge_token_flow(b.runtime, &match, &savedErrno); purgeErr != 0 {
			return E.Cause(syscall.Errno(savedErrno), "purge token flow rows")
		}
	}
	return nil
}

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return osErrClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if len(ipv4) > 256 || len(ipv6) > 256 {
		return E.New("shared-network host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if !slices.Equal(b.hostIPv6, ipv6) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv6_map_fd),
			b.hostIPv6,
			ipv6,
		); err != nil {
			return E.Cause(err, "update shared-network IPv6 host map")
		}
	}
	if !slices.Equal(b.hostIPv4, ipv4) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv4_map_fd),
			b.hostIPv4,
			ipv4,
		); err != nil {
			if !slices.Equal(b.hostIPv6, ipv6) {
				_ = replaceBypassCIDRPolicyMap(
					int(b.runtime.host_ipv6_map_fd),
					ipv6,
					b.hostIPv6,
				)
			}
			return E.Cause(err, "update shared-network IPv4 host map")
		}
	}
	b.hostIPv4 = ipv4
	b.hostIPv6 = ipv6
	return nil
}

func compileSharedHostPrefixes(addresses []netip.Addr) ([]netip.Prefix, []netip.Prefix) {
	ipv4Set := make(map[netip.Prefix]struct{})
	ipv6Set := make(map[netip.Prefix]struct{})
	for _, address := range addresses {
		address = address.Unmap()
		switch {
		case address.Is4():
			ipv4Set[netip.PrefixFrom(address, 32)] = struct{}{}
		case address.Is6():
			ipv6Set[netip.PrefixFrom(address, 128)] = struct{}{}
		}
	}
	ipv4 := make([]netip.Prefix, 0, len(ipv4Set))
	for prefix := range ipv4Set {
		ipv4 = append(ipv4, prefix)
	}
	ipv6 := make([]netip.Prefix, 0, len(ipv6Set))
	for prefix := range ipv6Set {
		ipv6 = append(ipv6, prefix)
	}
	slices.SortFunc(ipv4, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	slices.SortFunc(ipv6, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	return ipv4, ipv6
}

func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	_ = b.updateControl(false)
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_close(b.runtime, &savedErrno)
	if b.runtime.control_map_fd < 0 &&
		b.runtime.ingress_prog_fd < 0 &&
		b.runtime.egress_prog_fd < 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.hostIPv4 = nil
		b.hostIPv6 = nil
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close shared-network runtime")
	}
	return nil
}

func (b *SharedNetworkBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
