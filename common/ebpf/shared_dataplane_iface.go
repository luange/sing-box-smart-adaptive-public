package ebpf

import (
	"net/netip"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
)

// SharedDataplane is the TC shared-network backend surface used by protocol/ebpf.
// v2 and v3 both implement this so engine selection stays outside TC attach code.
// The interface lives in a build-tag-neutral file so the non-cgo stub and the
// cgo backend are held to the exact same method set.
//
// Control-plane contract (design §3/§7): every learn/publish/invalidate path that
// affects packet verdicts must go through this interface — never a parallel
// in-memory model that is not synced to kernel maps.
// SharedNetworkRuntimeStats mirrors the cgroup-connect/runtime telemetry
// counters shared by v1/v2/v3 backends and their stubs.
type SharedNetworkRuntimeStats struct {
	IngressRedirects     uint64
	IngressBypass        uint64
	IngressDrops         uint64
	EgressRestores       uint64
	EgressReverseMisses  uint64
	TokenFailures        uint64
	RewriteFailures      uint64
	SocketAssignments    uint64
	SocketAssignFailures uint64
	FlowUpdateFailures   uint64
	FallbackOpen         uint64
	EstablishedBypass    uint64
	ParseFailures        uint64
	PolicyBypass         uint64
	ListenerMisses       uint64
	OriginalDstLost      uint64
}

type SharedDataplane interface {
	RegisterListenerSocket(key uint32, fd int) error
	SetFlowDirect(enabled bool) error
	PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error
	DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error
	InvalidateFlowDirect() error
	Enable() error
	Disable() error
	UpdateInterfaceMAC(ifIndex uint32, hardwareAddress []byte) error
	DeleteInterfaceMAC(ifIndex uint32) error
	IngressProgramFD() int
	EgressProgramFD() int
	RuntimeStats() (SharedNetworkRuntimeStats, error)
	LookupOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error)
	TakeOriginal(protocol uint8, client, redirect netip.AddrPort) (OriginalDestination, error)
	DeleteRedirect(protocol uint8, client, redirect netip.AddrPort) error
	UpdateHostAddresses(addresses []netip.Addr) error
	// V3 policy surface (no-op on v2).
	// PublishStaticDirect replaces the inactive bank and commits (full snapshot).
	PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error
	// MergeDynamicDirect writes one expiring learned DIRECT prefix to the
	// independent dynamic map without mutating the static policy snapshot.
	MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error
	PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error
	// DrainDNSObservations removes a bounded batch of plaintext DNS answers
	// captured by the v3 TC sniffer. Each row carries the first A/AAAA answer
	// and its RR TTL; v2 returns an empty batch. Domain policy evaluation and
	// any DIRECT promotion remain in userspace.
	DrainDNSObservations(max int) ([]ebpfv3.DNSObservation, error)
	// PublishMACPolicies replaces the source-MAC identity snapshot (v3 only).
	PublishMACPolicies(entries []ebpfv3.MACPolicyEntry) error
	// DeleteMergedStaticDirect revokes one promote-sourced DIRECT prefix (v3 only).
	DeleteMergedStaticDirect(prefix netip.Prefix) error
	WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error
	PolicyGeneration() uint32
	// V3Stats returns raw reason counters (index = SB_V3_STAT_*), generation, active bank.
	// v2 returns nil,0,0.
	V3Stats() (stats []uint64, generation uint32, activeBank uint32)
	Close() error
	IsClosed() bool
}

// PublishMACPolicies lives on the v3 ABI types; the interface needs the import.
var _ = ebpfv3.MACPolicyEntry{}
