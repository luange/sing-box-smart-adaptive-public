//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// PrepareSharedNetworkV3 is the non-cgo placeholder: the v3 TC dataplane
// requires cgo to load the kernel object. The stub keeps the with_ebpf&&!cgo
// build compilable so package wiring is exercised on every platform; runtime
// callers receive an explicit configuration error instead of a compile break.
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
	return nil, E.New("eBPF v3 dataplane requires a cgo build")
}

// V3Backend mirrors the cgo type so the shared interface conformance vars and
// any typed references compile without cgo; every method reports the same
// "requires cgo" error as the stub backend it embeds.
type V3Backend struct {
	*SharedNetworkBackend
}

var _ SharedDataplane = (*V3Backend)(nil)
