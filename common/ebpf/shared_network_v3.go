//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native -I${SRCDIR}/v3/kern
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_v3_prepare(
	const uint8_t *object,
	size_t object_size,
	uint32_t policy_lpm,
	uint32_t flow_entries,
	uint32_t dns_hints,
	struct sb_ebpf_v3_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_v3_prepare(object, object_size, policy_lpm, flow_entries, dns_hints, runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_v3_close(struct sb_ebpf_v3_runtime *runtime, int *saved_errno) {
	int result = sb_ebpf_v3_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
)

//go:embed v3/kern/tc.bpf.o
var sharedNetworkV3Object []byte

// V3Backend is the engine=v3 TC dataplane and the sole kernel policy sink.
// All static/flow/DNS verdicts that affect TC must be written here.
type V3Backend struct {
	access sync.RWMutex
	// mapAccess protects userspace map mutations and preserves atomicity of
	// paired forward/reverse flow entries and one-shot redirect consumption.
	// access remains the lifecycle lock, so close cannot race a syscall.
	mapAccess sync.RWMutex
	runtime   *C.struct_sb_ebpf_v3_runtime
	control   v3Control
	hostIPv4  []netip.Prefix
	hostIPv6  []netip.Prefix
	// statsPossibleCPUs is the kernel's possible-CPU count, not the current
	// online count. PERCPU map values are laid out for every possible CPU.
	statsPossibleCPUs int
	// statsAccess protects the reusable read buffer below. RuntimeStats and
	// V3Stats may be called concurrently while b.access is only an outer
	// lifecycle lock, so sharing the buffer without a second lock would race.
	statsAccess  sync.Mutex
	statsScratch []v3StatsValue
	// lastStatic is kept per bank.  A single snapshot is insufficient because
	// banks alternate: A→B→C would otherwise try to delete B from bank A and
	// leave A's stale prefixes live when bank A becomes active again.
	lastStatic [2][]netip.Prefix
	// Dynamic DIRECT ledgers mirror the two kernel LPM maps. Each family has an
	// independent capacity budget and must be accounted for separately.
	dynamicDirects4 map[netip.Prefix]uint64
	dynamicDirects6 map[netip.Prefix]uint64
	originalDstLost atomic.Uint64
	flowEnabled     bool
}

type v3Control struct {
	ABIVersion       uint32
	Enabled          uint32
	Flags            uint32
	ActiveBank       uint32
	PolicyGeneration uint32
	RoutingMark      uint32
	Reserved0        uint16
	Reserved1        uint16
	Reserved2        uint32
}

const v3StatsCount = 32

// v3StatsValue mirrors sb_v3_stats_value. One value is allocated per possible
// CPU by the kernel PERCPU_ARRAY, so userspace must aggregate all slots.
type v3StatsValue [v3StatsCount]uint64

type v3PolicyValue struct {
	Verdict       uint8
	Source        uint8
	Confidence    uint8
	Reserved0     uint8
	ReasonCode    uint16
	MatchProtocol uint16
	MatchDPortMin uint16
	MatchDPortMax uint16
	PolicyID      uint32
	Generation    uint32
}

type v3DynamicDirectValue struct {
	Verdict       uint8
	Source        uint8
	Confidence    uint8
	Reserved0     uint8
	ReasonCode    uint16
	MatchProtocol uint16
	MatchDPortMin uint16
	MatchDPortMax uint16
	PolicyID      uint32
	Generation    uint32
	ExpiresNs     uint64
}

type v3FlowKey struct {
	Family    uint8
	Protocol  uint8
	Direction uint8
	Reserved0 uint8
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

type v3FlowValue struct {
	Verdict    uint8
	Source     uint8
	Confidence uint8
	Reserved0  uint8
	ReasonCode uint16
	Reserved1  uint16
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
}

type v3DNSKey struct {
	Family    uint8
	Reserved0 uint8
	Reserved1 uint16
	Addr      [16]byte
}

type v3DNSValue struct {
	DirectRefs uint32
	ProxyRefs  uint32
	PolicyID   uint32
	Generation uint32
	ExpiresNs  uint64
	LastSeenNs uint64
	Evidence   uint8
	Reserved0  uint8
	Reserved1  uint16
	Reserved2  uint32
}

type v3DNSObservationKey struct {
	QnameHash uint64
	Family    uint8
	Reserved0 uint8
	Reserved1 uint16
	Addr      [16]byte
}

type v3DNSObservationValue struct {
	Qname      [ebpfv3.DNSObservationNameMax]byte
	TTLSeconds uint32
	Reserved0  uint32
}

type v3RedirectKey struct {
	Family     uint8
	Protocol   uint8
	Reserved0  uint16
	ClientPort uint16
	DestPort   uint16
	ClientAddr [16]byte
	DestAddr   [16]byte
}

type v3RedirectValue struct {
	Family    uint8
	Protocol  uint8
	DestPort  uint16
	IfIndex   uint32
	DestAddr  [16]byte
	SourceMAC [6]byte
	Reserved  [2]byte
}

type v3LPM4 struct {
	PrefixLen uint32
	Addr      [4]byte
}

type v3LPM6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

type v3MACKey struct {
	Addr     [6]byte
	Reserved [2]byte
	Ifindex  uint32
}

type v3MACPolicyValue struct {
	Verdict    uint8
	Source     uint8
	Confidence uint8
	Reserved0  uint8
	ReasonCode uint16
	Reserved1  uint16
	PolicyID   uint32
	Generation uint32
}

const (
	v3FlagIPv4         = 1 << 0
	v3FlagIPv6         = 1 << 1
	v3FlagTCP          = 1 << 2
	v3FlagUDP          = 1 << 3
	v3FlagDNSHijack    = 1 << 4
	v3FlagDropUDP443   = 1 << 5
	v3FlagSocketAssign = 1 << 6
	v3FlagStaticPolicy = 1 << 7
	v3FlagExactFlow    = 1 << 8
	v3FlagDNSHint      = 1 << 9
	v3FlagFakeIP       = 1 << 10
	v3FlagMACSource    = 1 << 11
	v3FlagFailureProxy = 1 << 12
	v3FlagDNSSniff     = 1 << 13
)

const (
	v3VerdictDirect = 1
	v3SourceStatic  = 1
	v3SourceFlow    = 2
	v3SourceDNSWeak = 3
	v3SourceFakeIP  = 4
)

// PrepareSharedNetworkV3 loads the independent v3 TC object.
func PrepareSharedNetworkV3(
	enableTCP bool,
	enableUDP bool,
	enableIPv4 bool,
	enableIPv6 bool,
	hijackDNS bool,
	dropUDP443 bool,
	routingMark uint32,
	policyOffloadStatic bool,
	policyOffloadFlow bool,
	policyOffloadDNS bool,
	policyOffloadFakeIP bool,
	flowMaxEntries uint32,
) (*V3Backend, error) {
	if len(sharedNetworkV3Object) == 0 {
		return nil, E.New("missing embedded eBPF v3 object (run make -C common/ebpf generate on Linux)")
	}
	if routingMark == 0 {
		return nil, E.New("missing shared-network socket-assignment routing mark")
	}
	statsCPUs, cpuErr := possibleCPUCount()
	if cpuErr != nil || statsCPUs < 1 {
		if cpuErr == nil {
			cpuErr = E.New("possible CPU count must be >= 1")
		}
		return nil, E.Cause(cpuErr, "detect possible CPUs for eBPF v3 stats")
	}
	// Match inbound Prepare: large LPM/LRU maps need unlocked RLIMIT_MEMLOCK.
	memlockErr := raiseMemlockLimit()
	runtimeState := (*C.struct_sb_ebpf_v3_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_sb_ebpf_v3_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF v3 runtime")
	}
	var savedErrno C.int
	result := C.singbox_ebpf_v3_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkV3Object[0])),
		C.size_t(len(sharedNetworkV3Object)),
		C.uint32_t(16384),
		C.uint32_t(flowMaxEntries),
		C.uint32_t(ebpfv3.DefaultDynamicDirect),
		runtimeState,
		&savedErrno,
	)
	if result != 0 {
		C.free(unsafe.Pointer(runtimeState))
		prepareErr := eBPFOperationError("prepare eBPF v3 programs", syscall.Errno(savedErrno))
		if memlockErr != nil && (syscall.Errno(savedErrno) == unix.ENOMEM || syscall.Errno(savedErrno) == unix.EPERM || syscall.Errno(savedErrno) == unix.EACCES) {
			prepareErr = E.Cause(prepareErr, "memlock limit could not be removed: ", memlockErr)
		}
		return nil, prepareErr
	}
	_ = memlockErr
	b := &V3Backend{
		runtime:           runtimeState,
		flowEnabled:       policyOffloadFlow,
		statsPossibleCPUs: statsCPUs,
		statsScratch:      make([]v3StatsValue, statsCPUs),
		dynamicDirects4:   make(map[netip.Prefix]uint64),
		dynamicDirects6:   make(map[netip.Prefix]uint64),
	}
	// Must match SB_V3_ABI_VERSION in v3/kern/abi.h. The version covers the
	// PERCPU stats vector and the DNS observation map contract.
	b.control.ABIVersion = ebpfv3.ABIVersion
	b.control.PolicyGeneration = 1
	b.control.ActiveBank = 0
	b.control.RoutingMark = routingMark
	b.control.Flags = v3FlagSocketAssign | v3FlagFailureProxy
	if enableIPv4 {
		b.control.Flags |= v3FlagIPv4
	}
	if enableIPv6 {
		b.control.Flags |= v3FlagIPv6
	}
	if enableTCP {
		b.control.Flags |= v3FlagTCP
	}
	if enableUDP {
		b.control.Flags |= v3FlagUDP
	}
	if hijackDNS {
		b.control.Flags |= v3FlagDNSHijack
	}
	if dropUDP443 {
		b.control.Flags |= v3FlagDropUDP443
	}
	if policyOffloadStatic {
		b.control.Flags |= v3FlagStaticPolicy
	}
	if policyOffloadFlow {
		b.control.Flags |= v3FlagExactFlow
	}
	if policyOffloadDNS {
		b.control.Flags |= v3FlagDNSHint
		b.control.Flags |= v3FlagDNSSniff
	}
	if policyOffloadFakeIP {
		b.control.Flags |= v3FlagFakeIP
	}
	if err := b.writeControl(false); err != nil {
		_ = b.Close()
		return nil, E.Cause(err, "seed eBPF v3 control")
	}
	return b, nil
}

func (b *V3Backend) writeControl(enabled bool) error {
	if b == nil || b.runtime == nil {
		return osErrClosed
	}
	ctrl := b.control
	ctrl.Enabled = 0
	if enabled {
		ctrl.Enabled = 1
	}
	key := uint32(0)
	if err := updateMap(int(b.runtime.control_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&ctrl)); err != nil {
		return err
	}
	b.control.Enabled = ctrl.Enabled
	return nil
}

func (b *V3Backend) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	previous := b.control
	if generation == 0 {
		generation = 1
	}
	b.control.Flags = flags
	b.control.ActiveBank = activeBank & 1
	b.control.PolicyGeneration = generation
	if routingMark != 0 {
		b.control.RoutingMark = routingMark
	}
	if err := b.writeControl(enabled); err != nil {
		b.control = previous
		return err
	}
	return nil
}

func (b *V3Backend) RegisterListenerSocket(key uint32, fd int) error {
	if b == nil || key >= 4 || fd < 0 {
		return E.New("invalid v3 listener socket")
	}
	b.access.RLock()
	defer b.access.RUnlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	value := uint64(fd)
	return updateMapWithFlags(int(b.runtime.listener_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
}

func (b *V3Backend) SetFlowDirect(enabled bool) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	previousEnabled := b.flowEnabled
	previousFlags := b.control.Flags
	if enabled {
		b.control.Flags |= v3FlagExactFlow
	} else {
		b.control.Flags &^= v3FlagExactFlow
	}
	if err := b.writeControl(b.control.Enabled != 0); err != nil {
		b.flowEnabled = previousEnabled
		b.control.Flags = previousFlags
		return err
	}
	b.flowEnabled = enabled
	return nil
}

func (b *V3Backend) PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	fwd, rev, err := makeV3FlowPair(protocol, source, destination)
	if err != nil {
		return err
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	// Pair publication may need to advance the generation if the reverse
	// update and its forward rollback both fail, so take the exclusive lock.
	b.access.Lock()
	defer b.access.Unlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil || !b.flowEnabled {
		return osErrClosed
	}
	value := v3FlowValue{
		Verdict:    v3VerdictDirect,
		Source:     v3SourceFlow,
		Confidence: 2,
		ReasonCode: 2, // flow_direct
		Generation: b.control.PolicyGeneration,
		ExpiresNs:  expires,
	}
	if err = updateMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&fwd), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "update v3 flow forward")
	}
	if err = updateMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&rev), unsafe.Pointer(&value)); err != nil {
		// Never leave a one-sided pair.  A reverse miss would make return
		// traffic take a different path until the TTL expires.
		cleanupErr := deleteMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&fwd))
		if cleanupErr != nil && !errors.Is(cleanupErr, unix.ENOENT) {
			invalidateErr := b.invalidateFlowGenerationLocked()
			return errors.Join(E.Cause(err, "update v3 flow reverse"), E.Cause(cleanupErr, "rollback v3 flow forward"), invalidateErr)
		}
		return E.Cause(err, "update v3 flow reverse")
	}
	return nil
}

func (b *V3Backend) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	fwd, rev, err := makeV3FlowPair(protocol, source, destination)
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
	var firstErr error
	if err := deleteMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&fwd)); err != nil && !errors.Is(err, unix.ENOENT) {
		firstErr = E.Cause(err, "delete v3 flow forward")
	}
	if err := deleteMap(int(b.runtime.flow_map_fd), unsafe.Pointer(&rev)); err != nil && !errors.Is(err, unix.ENOENT) {
		if firstErr == nil {
			firstErr = E.Cause(err, "delete v3 flow reverse")
		} else {
			firstErr = errors.Join(firstErr, E.Cause(err, "delete v3 flow reverse"))
		}
	}
	return firstErr
}

// makeV3FlowPair builds forward + reverse keys both with direction=0.
// TC looks up direction=0 only; reverse is the on-wire swapped 5-tuple.
func makeV3FlowPair(protocol uint8, source, destination netip.AddrPort) (v3FlowKey, v3FlowKey, error) {
	var fwd, rev v3FlowKey
	fwd.Protocol = protocol
	fwd.Direction = 0
	fwd.SPort = source.Port()
	fwd.DPort = destination.Port()
	if err := putAddress(&fwd.Family, &fwd.SAddr, source.Addr()); err != nil {
		return fwd, rev, err
	}
	var fam uint8
	if err := putAddress(&fam, &fwd.DAddr, destination.Addr()); err != nil {
		return fwd, rev, err
	}
	if fam != fwd.Family {
		return fwd, rev, E.New("v3 flow family mismatch")
	}
	rev.Family = fwd.Family
	rev.Protocol = protocol
	rev.Direction = 0
	rev.SPort = destination.Port()
	rev.DPort = source.Port()
	rev.SAddr = fwd.DAddr
	rev.DAddr = fwd.SAddr
	return fwd, rev, nil
}

func (b *V3Backend) InvalidateFlowDirect() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.invalidateFlowGenerationLocked()
}

func (b *V3Backend) invalidateFlowGenerationLocked() error {
	if b == nil {
		return osErrClosed
	}
	if b.runtime == nil {
		return osErrClosed
	}
	b.control.PolicyGeneration++
	if b.control.PolicyGeneration == 0 {
		b.control.PolicyGeneration = 1
	}
	// The reload generation is already carried in the control record.  Do not
	// perform a userspace read-modify-write on the PERCPU stats map: it would
	// overwrite the per-CPU counter for one CPU and reintroduce contention.
	return b.writeControl(b.control.Enabled != 0)
}

func (b *V3Backend) PolicyGeneration() uint32 {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.control.PolicyGeneration
}

// readStatsLocked aggregates the PERCPU reason counters with one map lookup.
// The caller must hold b.access.RLock or b.access.Lock.
func (b *V3Backend) readStatsLocked() (v3StatsValue, error) {
	if b == nil || b.runtime == nil || b.statsPossibleCPUs < 1 {
		return v3StatsValue{}, osErrClosed
	}
	b.statsAccess.Lock()
	defer b.statsAccess.Unlock()
	if len(b.statsScratch) != b.statsPossibleCPUs {
		b.statsScratch = make([]v3StatsValue, b.statsPossibleCPUs)
	}
	key := uint32(0)
	if err := lookupMap(int(b.runtime.stats_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&b.statsScratch[0])); err != nil {
		return v3StatsValue{}, err
	}
	var stats v3StatsValue
	for _, value := range b.statsScratch {
		for index, count := range value {
			stats[index] += count
		}
	}
	return stats, nil
}

// V3Stats reads and aggregates the kernel reason counters.
func (b *V3Backend) V3Stats() (stats []uint64, generation uint32, activeBank uint32) {
	if b == nil {
		return nil, 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil, 0, 0
	}
	raw, err := b.readStatsLocked()
	if err != nil {
		return nil, b.control.PolicyGeneration, b.control.ActiveBank & 1
	}
	stats = append([]uint64(nil), raw[:]...)
	return stats, b.control.PolicyGeneration, b.control.ActiveBank & 1
}

func (b *V3Backend) Enable() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.writeControl(true)
}

func (b *V3Backend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	return b.writeControl(false)
}

func (b *V3Backend) UpdateInterfaceMAC(ifIndex uint32, hardwareAddress []byte) error {
	// v3 source MAC policy is optional; interface MAC table not required for socket_assign.
	_ = ifIndex
	_ = hardwareAddress
	return nil
}

func (b *V3Backend) DeleteInterfaceMAC(ifIndex uint32) error {
	_ = ifIndex
	return nil
}

func (b *V3Backend) IngressProgramFD() int {
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

func (b *V3Backend) EgressProgramFD() int {
	return -1
}

func (b *V3Backend) RuntimeStats() (SharedNetworkRuntimeStats, error) {
	if b == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return SharedNetworkRuntimeStats{}, osErrClosed
	}
	raw, err := b.readStatsLocked()
	if err != nil {
		return SharedNetworkRuntimeStats{}, err
	}
	return v3SharedRuntimeStats(raw[:], b.originalDstLost.Load()), nil
}

// v3SharedRuntimeStats maps V3's packet counters onto the legacy shared
// dataplane stats contract. A policy/map miss is a normal proxy handoff, not
// an open fallback; only failures while preparing/assigning that handoff are
// counted as fallback-open. Keep this pure so the mapping stays unit-tested.
func v3SharedRuntimeStats(raw []uint64, originalDstLost uint64) SharedNetworkRuntimeStats {
	read := func(idx uint32) uint64 {
		if int(idx) >= len(raw) {
			return 0
		}
		return raw[idx]
	}
	staticDirect := read(0)
	flowDirect := read(1)
	fakeIPDirect := read(2)
	dnsHintDirect := read(3)
	parseFail := read(7)
	socketOK := read(8)
	socketFail := read(9)
	mapCapacityReject := read(12)
	security := read(13)
	return SharedNetworkRuntimeStats{
		IngressRedirects:     socketOK,
		IngressBypass:        staticDirect + flowDirect + fakeIPDirect + dnsHintDirect + security,
		IngressDrops:         read(10),
		SocketAssignments:    socketOK,
		SocketAssignFailures: socketFail,
		FlowUpdateFailures:   mapCapacityReject,
		ParseFailures:        parseFail,
		PolicyBypass:         staticDirect + flowDirect + fakeIPDirect + dnsHintDirect,
		FallbackOpen:         socketFail + mapCapacityReject,
		EstablishedBypass:    read(14),
		OriginalDstLost:      originalDstLost,
	}
}

func (b *V3Backend) LookupOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, false)
}

func (b *V3Backend) TakeOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, client, redirect, true)
}

func (b *V3Backend) lookupOriginal(protocol uint8, client, redirect netip.AddrPort, del bool) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, osErrClosed
	}
	key, err := makeV3RedirectKey(protocol, client, redirect)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if del {
		b.mapAccess.Lock()
		defer b.mapAccess.Unlock()
	} else {
		b.mapAccess.RLock()
		defer b.mapAccess.RUnlock()
	}
	if b.runtime == nil {
		return OriginalDestination{}, osErrClosed
	}
	var value v3RedirectValue
	if err = lookupMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		b.originalDstLost.Add(1)
		return OriginalDestination{}, E.Cause(err, "lookup v3 original destination")
	}
	if del {
		if err = deleteMap(int(b.runtime.redirect_map_fd), unsafe.Pointer(&key)); err != nil && !errors.Is(err, unix.ENOENT) {
			return OriginalDestination{}, E.Cause(err, "delete consumed v3 original destination")
		}
	}
	addr, err := addrFromFamily(value.Family, value.DestAddr)
	if err != nil {
		return OriginalDestination{}, err
	}
	return OriginalDestination{
		Destination:    netip.AddrPortFrom(addr, value.DestPort),
		IngressIfIndex: value.IfIndex,
	}, nil
}

func makeV3RedirectKey(protocol uint8, client, dest netip.AddrPort) (v3RedirectKey, error) {
	var key v3RedirectKey
	key.Protocol = protocol
	key.ClientPort = client.Port()
	key.DestPort = dest.Port()
	if err := putAddress(&key.Family, &key.ClientAddr, client.Addr()); err != nil {
		return key, err
	}
	var fam uint8
	if err := putAddress(&fam, &key.DestAddr, dest.Addr()); err != nil {
		return key, err
	}
	if fam != key.Family {
		return key, E.New("v3 redirect family mismatch")
	}
	return key, nil
}

func addrFromFamily(family uint8, raw [16]byte) (netip.Addr, error) {
	switch family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(raw), nil
	default:
		return netip.Addr{}, E.New("invalid family")
	}
}

func (b *V3Backend) DeleteRedirect(protocol uint8, client, redirect netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeV3RedirectKey(protocol, client, redirect)
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
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (b *V3Backend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return osErrClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if err := validateV3HostPrefixes(ipv4, ipv6); err != nil {
		return err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if err := replaceBypassCIDRPolicyMap(int(b.runtime.host6_map_fd), b.hostIPv6, ipv6); err != nil {
		return E.Cause(err, "update v3 host6")
	}
	if err := replaceBypassCIDRPolicyMap(int(b.runtime.host4_map_fd), b.hostIPv4, ipv4); err != nil {
		rollbackErr := replaceBypassCIDRPolicyMap(int(b.runtime.host6_map_fd), ipv6, b.hostIPv6)
		if rollbackErr != nil {
			return errors.Join(E.Cause(err, "update v3 host4"), E.Cause(rollbackErr, "rollback v3 host6"))
		}
		return E.Cause(err, "update v3 host4")
	}
	b.hostIPv4, b.hostIPv6 = ipv4, ipv6
	return nil
}

const v3HostMapCapacity = 1024

// v3PolicyMapCapacity mirrors SB_V3_DEFAULT_POLICY_LPM in the native
// constructor. Each address family has its own LPM map with this limit.
const v3PolicyMapCapacity = 16384

func validateV3HostPrefixes(ipv4, ipv6 []netip.Prefix) error {
	if len(ipv4) > v3HostMapCapacity || len(ipv6) > v3HostMapCapacity {
		return E.New("v3 host address policy exceeds eBPF map capacity")
	}
	return nil
}

func validateV3PolicyPrefixes(prefixes []netip.Prefix) error {
	var ipv4, ipv6 int
	for _, prefix := range prefixes {
		addr := prefix.Addr().Unmap()
		if addr.Is4() {
			ipv4++
		} else if addr.Is6() {
			ipv6++
		}
	}
	if ipv4 > v3PolicyMapCapacity || ipv6 > v3PolicyMapCapacity {
		return E.New("v3 static policy exceeds eBPF LPM map capacity")
	}
	return nil
}

// PublishStaticDirect writes DIRECT prefixes into the inactive bank and commits
// with a new policy_generation (design §7.1 double-buffer).
// Removed prefixes from the previous snapshot are deleted from the inactive bank
// before commit so LPM capacity does not grow without bound across reloads.
func (b *V3Backend) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if generation == 0 {
		generation = b.control.PolicyGeneration + 1
		if generation == 0 {
			generation = 1
		}
	}
	inactive := uint32(1 - (b.control.ActiveBank & 1))
	if bank <= 1 {
		// bank arg is advisory; always fill the true inactive bank.
		_ = bank
	}
	fd4 := int(b.runtime.policy4_bank0_fd)
	fd6 := int(b.runtime.policy6_bank0_fd)
	if inactive == 1 {
		fd4 = int(b.runtime.policy4_bank1_fd)
		fd6 = int(b.runtime.policy6_bank1_fd)
	}

	next := normalizePrefixSnapshot(prefixes)
	nextSet := make(map[netip.Prefix]struct{}, len(next))
	for _, p := range next {
		nextSet[p] = struct{}{}
	}
	if err := validateV3PolicyPrefixes(next); err != nil {
		return err
	}
	// Keep a copy so every failure path can restore both the in-process
	// transaction state and the inactive BPF bank. The inactive bank is
	// unreachable until writeControl succeeds, but leaving partially written
	// generations there would consume LPM capacity and make later retries fail.
	previousControl := b.control
	previousStatic := append([]netip.Prefix(nil), b.lastStatic[inactive]...)
	// Drop keys present in this bank's previous snapshot but not in the new one.
	for _, old := range b.lastStatic[inactive] {
		if _, keep := nextSet[old]; keep {
			continue
		}
		if err := deleteV3PolicyPrefix(fd4, fd6, old); err != nil {
			rollbackErr := rollbackV3StaticBank(fd4, fd6, previousStatic, nil, previousControl.PolicyGeneration)
			if rollbackErr != nil {
				return errors.Join(E.Cause(err, "remove stale v3 static prefix"), E.Cause(rollbackErr, "rollback v3 static prefix"))
			}
			return E.Cause(err, "remove stale v3 static prefix")
		}
	}
	written := make([]netip.Prefix, 0, len(next))
	for _, prefix := range next {
		if err := writeV3PolicyPrefix(fd4, fd6, prefix, generation); err != nil {
			cleanupErr := rollbackV3StaticBank(fd4, fd6, previousStatic, written, previousControl.PolicyGeneration)
			b.lastStatic[inactive] = previousStatic
			if cleanupErr != nil {
				return errors.Join(err, E.Cause(cleanupErr, "rollback v3 static prefix"))
			}
			return err
		}
		written = append(written, prefix)
	}
	b.control.ActiveBank = inactive
	b.control.PolicyGeneration = generation
	if err := b.writeControl(b.control.Enabled != 0); err != nil {
		b.control = previousControl
		b.lastStatic[inactive] = previousStatic
		rollbackErr := rollbackV3StaticBank(fd4, fd6, previousStatic, written, previousControl.PolicyGeneration)
		restoreControlErr := b.writeControl(previousControl.Enabled != 0)
		if rollbackErr != nil || restoreControlErr != nil {
			return errors.Join(E.Cause(err, "commit v3 static policy"),
				wrapOptionalEBPFError(rollbackErr, "rollback v3 static prefix"),
				wrapOptionalEBPFError(restoreControlErr, "restore v3 control"))
		}
		return E.Cause(err, "commit v3 static policy")
	}
	b.lastStatic[inactive] = next
	// A generation commit invalidates all learned rows.  Remove the now-stale
	// dynamic entries as well so an idle process cannot retain them until the
	// map reaches capacity.  This is deliberately after the atomic policy flip:
	// a failed static transaction never destroys valid runtime learning.
	if err := b.clearDynamicDirectLocked(); err != nil {
		return E.Cause(err, "clear stale v3 dynamic direct entries")
	}
	return nil
}

// rollbackV3StaticBank restores the last committed snapshot after an
// inactive-bank write or control-map commit fails.  Rewriting the full prior
// snapshot is intentional: stale-key deletion may have succeeded before the
// failure, and a partial write may have replaced a prefix with a new
// generation.  The helper only removes entries introduced by this attempt;
// entries from an older failed attempt are not enumerable without an extra
// syscall and remain unreachable by generation checks.
func rollbackV3StaticBank(fd4, fd6 int, previous, written []netip.Prefix, generation uint32) error {
	previousSet := make(map[netip.Prefix]struct{}, len(previous))
	for _, prefix := range previous {
		previousSet[prefix] = struct{}{}
	}
	var rollbackErr error
	for _, prefix := range written {
		if _, keep := previousSet[prefix]; keep {
			continue
		}
		if err := deleteV3PolicyPrefix(fd4, fd6, prefix); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	for _, prefix := range previous {
		if err := writeV3PolicyPrefix(fd4, fd6, prefix, generation); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	return rollbackErr
}

func wrapOptionalEBPFError(err error, context string) error {
	if err == nil {
		return nil
	}
	return E.Cause(err, context)
}

// MergeDynamicDirect writes one learned DIRECT prefix to the separate expiring
// map. Static policy banks remain immutable snapshots between publishes.
func (b *V3Backend) MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	var err error
	prefix, err = ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return E.Cause(err, "invalid dynamic direct prefix")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	entries, err := b.dynamicEntriesForPrefix(prefix)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now, err := monotonicExpireNs(0)
	if err != nil {
		return err
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	if err := b.purgeExpiredDynamicDirectLocked(now); err != nil {
		return E.Cause(err, "reclaim expired v3 dynamic direct entries")
	}
	if existing, ok := entries[prefix]; ok && existing > now {
		if err := writeV3DynamicDirect(int(b.runtime.dynamic_direct4_fd), int(b.runtime.dynamic_direct6_fd), prefix,
			b.control.PolicyGeneration, expires); err != nil {
			return err
		}
		entries[prefix] = expires
		return nil
	}
	if len(entries) >= ebpfv3.DefaultDynamicDirect {
		return E.New("v3 dynamic direct map capacity reached")
	}
	if err := writeV3DynamicDirect(int(b.runtime.dynamic_direct4_fd), int(b.runtime.dynamic_direct6_fd), prefix,
		b.control.PolicyGeneration, expires); err != nil {
		return err
	}
	entries[prefix] = expires
	return nil
}

func (b *V3Backend) dynamicEntriesForPrefix(prefix netip.Prefix) (map[netip.Prefix]uint64, error) {
	if b == nil {
		return nil, osErrClosed
	}
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		if b.dynamicDirects4 == nil {
			b.dynamicDirects4 = make(map[netip.Prefix]uint64)
		}
		return b.dynamicDirects4, nil
	}
	if addr.Is6() {
		if b.dynamicDirects6 == nil {
			b.dynamicDirects6 = make(map[netip.Prefix]uint64)
		}
		return b.dynamicDirects6, nil
	}
	return nil, E.New("invalid dynamic direct prefix family")
}

// MergeStaticDirect is retained as a source-compatible wrapper for callers
// outside the v3 lifecycle. New code must provide the authoritative TTL via
// MergeDynamicDirect so the kernel expiry matches the DNS answer lifetime.
func (b *V3Backend) MergeStaticDirect(prefix netip.Prefix) error {
	return b.MergeDynamicDirect(prefix, 5*time.Minute)
}

// DeleteMergedStaticDirect is the compatibility façade for deleting one
// learn-promoted dynamic DIRECT row. Static snapshot entries are never touched.
func (b *V3Backend) DeleteMergedStaticDirect(prefix netip.Prefix) error {
	if b == nil {
		return osErrClosed
	}
	var err error
	prefix, err = ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return E.Cause(err, "invalid dynamic direct prefix")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	entries, err := b.dynamicEntriesForPrefix(prefix)
	if err != nil {
		return err
	}
	if _, revocable := entries[prefix]; !revocable {
		return nil
	}
	if err := deleteV3DynamicDirect(int(b.runtime.dynamic_direct4_fd), int(b.runtime.dynamic_direct6_fd), prefix); err != nil {
		return err
	}
	delete(entries, prefix)
	return nil
}

func normalizePrefixSnapshot(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		canonical, err := ebpfv3.CanonicalPrefix(p)
		if err != nil {
			continue
		}
		p = canonical
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func writeV3PolicyPrefix(fd4, fd6 int, prefix netip.Prefix, generation uint32) error {
	canonical, err := ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	prefix = canonical
	addr := prefix.Addr()
	value := v3PolicyValue{
		Verdict:    v3VerdictDirect,
		Source:     v3SourceStatic,
		Confidence: 2,
		ReasonCode: 1,
		Generation: generation,
	}
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		return updateMap(fd4, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		return updateMap(fd6, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	return E.New("invalid policy prefix family")
}

func deleteV3PolicyPrefix(fd4, fd6 int, prefix netip.Prefix) error {
	canonical, err := ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	prefix = canonical
	addr := prefix.Addr()
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		err := deleteMap(fd4, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		err := deleteMap(fd6, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	return nil
}

func writeV3DynamicDirect(fd4, fd6 int, prefix netip.Prefix, generation uint32, expires uint64) error {
	prefix, err := ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	value := v3DynamicDirectValue{
		Verdict:    v3VerdictDirect,
		Source:     v3SourceStatic,
		Confidence: 2,
		ReasonCode: 1,
		Generation: generation,
		ExpiresNs:  expires,
	}
	addr := prefix.Addr()
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		return updateMap(fd4, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		return updateMap(fd6, unsafe.Pointer(&key), unsafe.Pointer(&value))
	}
	return E.New("invalid dynamic direct prefix family")
}

func deleteV3DynamicDirect(fd4, fd6 int, prefix netip.Prefix) error {
	prefix, err := ebpfv3.CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	addr := prefix.Addr()
	if addr.Is4() {
		a := addr.As4()
		key := v3LPM4{PrefixLen: uint32(prefix.Bits()), Addr: a}
		err := deleteMap(fd4, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if addr.Is6() {
		key := v3LPM6{PrefixLen: uint32(prefix.Bits()), Addr: addr.As16()}
		err := deleteMap(fd6, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	return E.New("invalid dynamic direct prefix family")
}

// clearDynamicDirectLocked removes all learned rows known to this process.
// The map is generation-checked in the kernel, but explicit deletion avoids
// retaining expired rows and makes capacity independent from reload count.
func (b *V3Backend) clearDynamicDirectLocked() error {
	if b == nil || b.runtime == nil || (len(b.dynamicDirects4) == 0 && len(b.dynamicDirects6) == 0) {
		return nil
	}
	var joined error
	for _, entries := range []map[netip.Prefix]uint64{b.dynamicDirects4, b.dynamicDirects6} {
		for prefix := range entries {
			if err := deleteV3DynamicDirect(int(b.runtime.dynamic_direct4_fd), int(b.runtime.dynamic_direct6_fd), prefix); err != nil {
				joined = errors.Join(joined, err)
			}
		}
	}
	if joined == nil {
		clear(b.dynamicDirects4)
		clear(b.dynamicDirects6)
	}
	return joined
}

func (b *V3Backend) purgeExpiredDynamicDirectLocked(now uint64) error {
	if b == nil || b.runtime == nil {
		return nil
	}
	var joined error
	for _, entries := range []map[netip.Prefix]uint64{b.dynamicDirects4, b.dynamicDirects6} {
		for prefix, expires := range entries {
			if expires == 0 || expires > now {
				continue
			}
			if err := deleteV3DynamicDirect(int(b.runtime.dynamic_direct4_fd), int(b.runtime.dynamic_direct6_fd), prefix); err != nil {
				joined = errors.Join(joined, err)
				continue
			}
			delete(entries, prefix)
		}
	}
	return joined
}

// PublishMACPolicies replaces the complete source-MAC identity snapshot in
// the kernel v3_source_mac map (design §7.3). The snapshot is authoritative:
// keys absent from entries are deleted so a provider reload cannot leave a
// stale device verdict behind. Rows are tagged with the live policy
// generation so the kernel ignores them after a generation bump until the
// host republishes.
func (b *V3Backend) PublishMACPolicies(entries []ebpfv3.MACPolicyEntry) error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	mapFD := int(b.runtime.source_mac_map_fd)
	generation := b.control.PolicyGeneration
	if generation == 0 {
		generation = 1
	}
	// Enumerate live keys and values first: deleting while iterating with
	// get_next_key can skip entries, and retaining the old values lets us
	// restore the previous snapshot if a later syscall fails.
	var live []v3MACKey
	var next v3MACKey
	for {
		var start unsafe.Pointer
		if len(live) > 0 {
			prev := live[len(live)-1]
			start = unsafe.Pointer(&prev)
		}
		if err := getNextKeyMap(mapFD, start, unsafe.Pointer(&next)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				break
			}
			return E.Cause(err, "iterate v3 source mac")
		}
		live = append(live, next)
	}
	previous := make(map[v3MACKey]v3MACPolicyValue, len(live))
	for _, key := range live {
		value := v3MACPolicyValue{}
		if err := lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return E.Cause(err, "read v3 source mac snapshot")
		}
		previous[key] = value
	}
	capHint := len(entries)
	if capHint > ebpfv3.MaxSourcePolicies+1 {
		capHint = ebpfv3.MaxSourcePolicies + 1
	}
	desired := make(map[v3MACKey]v3MACPolicyValue, capHint)
	for _, entry := range entries {
		var zero ebpfv3.MACKey
		if entry.Key == zero {
			continue
		}
		value := v3MACPolicyValue{
			Verdict:    entry.Value.Verdict,
			Source:     entry.Value.Source,
			Confidence: entry.Value.Confidence,
			ReasonCode: entry.Value.ReasonCode,
			PolicyID:   entry.Value.PolicyID,
			Generation: generation,
		}
		if value.Source == 0 {
			value.Source = v3SourceStatic
		}
		desired[v3MACKey{
			Addr:     entry.Key.Addr,
			Reserved: entry.Key.Reserved,
			Ifindex:  entry.Key.Ifindex,
		}] = value
	}
	if len(desired) > ebpfv3.MaxSourcePolicies {
		return E.New("mac source policy exceeds map capacity")
	}
	restore := func() error {
		var restoreErr error
		// Remove keys that did not exist in the previous snapshot and restore
		// every previous value. ENOENT is harmless during rollback because the
		// target state is already absent.
		for key := range desired {
			if _, existed := previous[key]; existed {
				continue
			}
			entry := key
			if err := deleteMap(mapFD, unsafe.Pointer(&entry)); err != nil && !errors.Is(err, unix.ENOENT) {
				restoreErr = errors.Join(restoreErr, E.Cause(err, "rollback new v3 source mac"))
			}
		}
		for key, value := range previous {
			entry := key
			old := value
			if err := updateMap(mapFD, unsafe.Pointer(&entry), unsafe.Pointer(&old)); err != nil {
				restoreErr = errors.Join(restoreErr, E.Cause(err, "restore v3 source mac"))
			}
		}
		return restoreErr
	}
	for key, value := range desired {
		entry := key
		if err := updateMap(mapFD, unsafe.Pointer(&entry), unsafe.Pointer(&value)); err != nil {
			return errors.Join(E.Cause(err, "publish v3 source mac"), restore())
		}
	}
	for old := range previous {
		if _, ok := desired[old]; ok {
			continue
		}
		stale := old
		if err := deleteMap(mapFD, unsafe.Pointer(&stale)); err != nil && !errors.Is(err, unix.ENOENT) {
			return errors.Join(E.Cause(err, "delete stale v3 source mac"), restore())
		}
	}
	return nil
}

func (b *V3Backend) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	if b == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	var key v3DNSKey
	a := addr.Unmap()
	if a.Is4() {
		key.Family = addressFamilyIPv4
		v4 := a.As4()
		copy(key.Addr[:4], v4[:])
	} else if a.Is6() {
		key.Family = addressFamilyIPv6
		key.Addr = a.As16()
	} else {
		return E.New("invalid dns hint address")
	}
	expires, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	now, err := monotonicExpireNs(0)
	if err != nil {
		return err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	if generation == 0 {
		generation = b.control.PolicyGeneration
		if generation == 0 {
			generation = 1
		}
	}
	var cur v3DNSValue
	if err := lookupMap(int(b.runtime.dns_hint_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&cur)); err != nil && !errors.Is(err, unix.ENOENT) {
		return E.Cause(err, "lookup v3 dns hint")
	}
	// Expired hints must start a fresh evidence epoch.  Carrying an old
	// proxy/direct ref across TTL turns transient CDN address reuse into a
	// permanent conflict and prevents the direct fast path from recovering.
	if cur.Generation != generation || (cur.ExpiresNs != 0 && cur.ExpiresNs <= now) {
		cur = v3DNSValue{Generation: generation, Evidence: evidence}
	}
	if direct {
		if cur.DirectRefs != ^uint32(0) {
			cur.DirectRefs++
		}
	} else {
		if cur.ProxyRefs != ^uint32(0) {
			cur.ProxyRefs++
		}
	}
	// Conflict isolation (design §8.2): both refs → weak, never DIRECT in TC.
	if cur.ProxyRefs > 0 && cur.DirectRefs > 0 {
		cur.Evidence = 3 // weak
	} else if evidence > cur.Evidence {
		cur.Evidence = evidence
	}
	cur.ExpiresNs = expires
	cur.LastSeenNs = now
	cur.Generation = generation
	return updateMap(int(b.runtime.dns_hint_map_fd), unsafe.Pointer(&key), unsafe.Pointer(&cur))
}

// DrainDNSObservations consumes a bounded batch from the optional v3 kernel
// DNS-response observation map.  The map is advisory: a disappearing entry or
// malformed name is dropped, never turned into a routing decision.  We first
// snapshot keys and only then delete them because deleting during
// BPF_MAP_GET_NEXT_KEY iteration can skip the next entry on LRU maps.
func (b *V3Backend) DrainDNSObservations(max int) ([]ebpfv3.DNSObservation, error) {
	if b == nil {
		return nil, osErrClosed
	}
	if max <= 0 || max > ebpfv3.MaxDNSObservations {
		max = 128
	}
	b.access.RLock()
	defer b.access.RUnlock()
	b.mapAccess.Lock()
	defer b.mapAccess.Unlock()
	if b.runtime == nil || b.runtime.dns_observe_map_fd < 0 {
		return nil, osErrClosed
	}
	mapFD := int(b.runtime.dns_observe_map_fd)
	keys := make([]v3DNSObservationKey, 0, max)
	var previous v3DNSObservationKey
	havePrevious := false
	for len(keys) < max {
		var next v3DNSObservationKey
		var keyPtr unsafe.Pointer
		if havePrevious {
			keyCopy := previous
			keyPtr = unsafe.Pointer(&keyCopy)
		}
		if err := getNextKeyMap(mapFD, keyPtr, unsafe.Pointer(&next)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				break
			}
			return nil, E.Cause(err, "iterate v3 dns observations")
		}
		keys = append(keys, next)
		previous = next
		havePrevious = true
	}
	observations := make([]ebpfv3.DNSObservation, 0, len(keys))
	for _, key := range keys {
		var value v3DNSObservationValue
		err := lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value))
		// Always consume the row.  A malformed producer must not pin the same
		// bad value in the LRU map and repeatedly waste the drainer budget.
		_ = deleteMap(mapFD, unsafe.Pointer(&key))
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return observations, E.Cause(err, "read v3 dns observation")
		}
		name := string(value.Qname[:])
		if nul := strings.IndexByte(name, 0); nul >= 0 {
			name = name[:nul]
		}
		name = normalizeDNSObservationName(name)
		if name == "" {
			continue
		}
		addr, addrErr := addrFromFamily(key.Family, key.Addr)
		if addrErr != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
			continue
		}
		observations = append(observations, ebpfv3.DNSObservation{Name: name, Address: addr, TTLSeconds: value.TTLSeconds})
	}
	return observations, nil
}

func normalizeDNSObservationName(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if len(name) == 0 || len(name) > 253 {
		return ""
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
		for index, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || (r == '-' && index > 0 && index < len(label)-1) {
				continue
			}
			return ""
		}
	}
	return name
}

func (b *V3Backend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	_ = b.writeControl(false)
	var savedErrno C.int
	result := C.singbox_ebpf_v3_close(b.runtime, &savedErrno)
	C.free(unsafe.Pointer(b.runtime))
	b.runtime = nil
	if result != 0 {
		return eBPFOperationError("close eBPF v3 runtime", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *V3Backend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}

// No-op stubs so SharedNetworkBackend (v2) satisfies SharedDataplane.
func (b *SharedNetworkBackend) PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error {
	return nil
}
func (b *SharedNetworkBackend) PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error {
	return nil
}
func (b *SharedNetworkBackend) DrainDNSObservations(int) ([]ebpfv3.DNSObservation, error) {
	return nil, nil
}
func (b *SharedNetworkBackend) WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error {
	return nil
}
func (b *SharedNetworkBackend) PolicyGeneration() uint32 { return 0 }
func (b *SharedNetworkBackend) V3Stats() ([]uint64, uint32, uint32) {
	return nil, 0, 0
}
func (b *SharedNetworkBackend) DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeSharedNetworkFlowKey(protocol, source, destination)
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
	if err := deleteMap(int(b.runtime.flow_direct_map_fd), unsafe.Pointer(&key)); err != nil && !errors.Is(err, syscall.ENOENT) {
		return E.Cause(err, "delete shared-network direct flow")
	}
	return nil
}
