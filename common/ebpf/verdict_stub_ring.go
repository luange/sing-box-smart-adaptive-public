//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"
)

// The non-cgo verdict stub records exports through the same shared ring as
// the cgo backend so TestVerdictExportRingWrap and diagnostics stay identical.
var stubVerdictRing verdictExportRing

func (v *VerdictBackend) recordExport(key outVerdictKey, value outVerdictValue, destination netip.AddrPort) {
	stubVerdictRing.recordExport(key, value, destination)
}

func (v *VerdictBackend) Export() []VerdictEntry {
	return stubVerdictRing.Export()
}
