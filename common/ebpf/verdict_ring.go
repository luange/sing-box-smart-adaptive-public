//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
)

// verdictExportRing is the pure-Go export ring shared by the cgo VerdictBackend
// and the non-cgo stub build. Both variants must expose the same recorded
// verdict surface so diagnostics and tests do not depend on link mode.
type verdictExportRing struct {
	exportAccess sync.Mutex
	// Fixed ring from the start — head is next write slot; count <= cap.
	ring  []VerdictEntry
	head  int
	count int
}

const verdictExportCap = 256

func (r *verdictExportRing) recordExport(key outVerdictKey, value outVerdictValue, destination netip.AddrPort) {
	r.exportAccess.Lock()
	defer r.exportAccess.Unlock()
	entry := VerdictEntry{
		Destination: destination,
		Family:      key.Family,
		Protocol:    key.Protocol,
		Verdict:     value.Verdict,
		Generation:  value.Generation,
		ExpireNs:    value.ExpireNs,
	}
	if r.ring == nil {
		r.ring = make([]VerdictEntry, verdictExportCap)
	}
	r.ring[r.head] = entry
	r.head = (r.head + 1) % verdictExportCap
	if r.count < verdictExportCap {
		r.count++
	}
}

func (r *verdictExportRing) Export() []VerdictEntry {
	r.exportAccess.Lock()
	defer r.exportAccess.Unlock()
	if r.count == 0 || r.ring == nil {
		return nil
	}
	out := make([]VerdictEntry, r.count)
	start := 0
	if r.count == verdictExportCap {
		start = r.head // full: head is oldest
	}
	for i := 0; i < r.count; i++ {
		out[i] = r.ring[(start+i)%verdictExportCap]
	}
	return out
}
