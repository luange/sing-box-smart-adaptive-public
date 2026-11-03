package v3

import (
	"fmt"
	"strings"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
)

// Snapshot is a reason-separated counter view (design §14).
type Snapshot struct {
	StaticDirect        uint64
	FlowDirect          uint64
	FakeIPDirect        uint64
	DNSHintDirect       uint64
	PolicyProxy         uint64
	MapMissProxy        uint64
	GenerationMissProxy uint64
	ParseFailProxy      uint64
	SocketAssignOK      uint64
	SocketAssignFail    uint64
	Blocked             uint64
	DNSHintConflict     uint64
	MapCapacityReject   uint64
	SecurityBypass      uint64
	EstablishedBypass   uint64
	Generation          uint32
	ActiveBank          uint32
}

// FromBackendStats maps PERCPU/array indices when available.
func FromBackendStats(stats []uint64, generation uint32, bank uint32) Snapshot {
	get := func(i int) uint64 {
		if i >= 0 && i < len(stats) {
			return stats[i]
		}
		return 0
	}
	return Snapshot{
		StaticDirect:        get(0),
		FlowDirect:          get(1),
		FakeIPDirect:        get(2),
		DNSHintDirect:       get(3),
		PolicyProxy:         get(4),
		MapMissProxy:        get(5),
		GenerationMissProxy: get(6),
		ParseFailProxy:      get(7),
		SocketAssignOK:      get(8),
		SocketAssignFail:    get(9),
		Blocked:             get(10),
		DNSHintConflict:     get(11),
		MapCapacityReject:   get(12),
		SecurityBypass:      get(13),
		EstablishedBypass:   get(14),
		Generation:          generation,
		ActiveBank:          bank,
	}
}

// Delta returns non-zero fields as a compact log line (no payloads/secrets).
func (s Snapshot) Delta(prev Snapshot) string {
	var b strings.Builder
	add := func(name string, cur, old uint64) {
		if cur > old {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%s=%d", name, cur-old)
		}
	}
	add("static_direct", s.StaticDirect, prev.StaticDirect)
	add("flow_direct", s.FlowDirect, prev.FlowDirect)
	add("fakeip_direct", s.FakeIPDirect, prev.FakeIPDirect)
	add("dns_hint_direct", s.DNSHintDirect, prev.DNSHintDirect)
	add("map_miss_proxy", s.MapMissProxy, prev.MapMissProxy)
	add("gen_miss_proxy", s.GenerationMissProxy, prev.GenerationMissProxy)
	add("parse_fail_proxy", s.ParseFailProxy, prev.ParseFailProxy)
	add("sk_assign_ok", s.SocketAssignOK, prev.SocketAssignOK)
	add("sk_assign_fail", s.SocketAssignFail, prev.SocketAssignFail)
	add("blocked", s.Blocked, prev.Blocked)
	add("dns_conflict", s.DNSHintConflict, prev.DNSHintConflict)
	add("security_bypass", s.SecurityBypass, prev.SecurityBypass)
	add("established", s.EstablishedBypass, prev.EstablishedBypass)
	if s.Generation != prev.Generation {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "generation=%d bank=%d", s.Generation, s.ActiveBank)
	}
	if b.Len() == 0 {
		return "ebpf_v3 idle"
	}
	return "ebpf_v3 " + b.String()
}

// ReasonName is for tests/debug only.
func ReasonName(r ebpfv3.Reason) string {
	switch r {
	case ebpfv3.ReasonStaticDirect:
		return "static_direct"
	case ebpfv3.ReasonFlowDirect:
		return "flow_direct"
	case ebpfv3.ReasonMapMissProxy:
		return "map_miss_proxy"
	case ebpfv3.ReasonParseFailProxy:
		return "parse_fail_proxy"
	case ebpfv3.ReasonDNSHintConflict:
		return "dns_hint_conflict"
	default:
		return fmt.Sprintf("reason_%d", r)
	}
}
