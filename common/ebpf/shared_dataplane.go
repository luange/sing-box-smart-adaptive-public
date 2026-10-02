//go:build with_ebpf && (linux || android) && cgo

package ebpf

// SharedDataplane is the TC shared-network backend surface used by protocol/ebpf.
// v2 and v3 both implement this so engine selection stays outside TC attach code.
//
// Control-plane contract (design §3/§7): every learn/publish/invalidate path that
// affects packet verdicts must go through this interface — never a parallel
// in-memory model that is not synced to kernel maps.
// Ensure compile-time conformance.
var (
	_ SharedDataplane = (*SharedNetworkBackend)(nil)
	_ SharedDataplane = (*V3Backend)(nil)
)
