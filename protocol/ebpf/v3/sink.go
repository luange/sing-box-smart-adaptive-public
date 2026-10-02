package v3

import (
	"net/netip"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
)

// DataplaneSink is the single kernel-facing publish surface for engine=v3.
// Lifecycle dual-writes MemoryBackend (tests/audit) and this sink (live TC maps).
// Implementations: common/ebpf.V3Backend via sharedNetwork.backend.
type DataplaneSink interface {
	PublishStaticDirect(prefixes []netip.Prefix, generation uint32, bank uint32) error
	MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error
	PutDirectFlow(protocol uint8, source, destination netip.AddrPort, ttl time.Duration) error
	DeleteDirectFlow(protocol uint8, source, destination netip.AddrPort) error
	PublishDNSHint(addr netip.Addr, direct bool, evidence uint8, generation uint32, ttl time.Duration) error
	PublishMACPolicies(entries []ebpfv3.MACPolicyEntry) error
	// DeleteMergedStaticDirect revokes one promote-sourced DIRECT prefix.
	DeleteMergedStaticDirect(prefix netip.Prefix) error
	// WriteControlV3 pushes control flags/mark/generation into the live kernel
	// control map without touching policy banks (hot reconfig surface).
	WriteControlV3(enabled bool, flags uint32, activeBank, generation, routingMark uint32) error
	InvalidateFlowDirect() error
	// Disable is the last-resort fail-closed fuse. It detaches the v3
	// dataplane's control enable bit when a narrower recovery cannot be trusted.
	Disable() error
	PolicyGeneration() uint32
}
