//go:build with_ebpf && (linux || android)

package ebpf

// ABI mirrors of native/singbox_ebpf_out.h — keep Sizeof tests in lockstep.

type spliceKey struct {
	Family     uint8
	Protocol   uint8
	LocalPort  uint16
	RemotePort uint16
	Reserved   uint16
	LocalAddr  [16]byte
	RemoteAddr [16]byte
}

type spliceControl struct {
	Enabled uint32
	Flags   uint32
}

// Module A ABI size locks (constants OutVerdict* live in verdict_const.go).
const (
	outVerdictKeySize     = 24
	outVerdictValueSize   = 16
	outVerdictControlSize = 8
)

type outVerdictKey struct {
	Family   uint8
	Protocol uint8
	Port     uint16 // host order
	Addr     [16]byte
	Reserved uint32
}

type outVerdictValue struct {
	Verdict    uint8
	Reserved   [3]byte
	Generation uint32
	ExpireNs   uint64
}

type outVerdictControl struct {
	Generation uint32
	Enabled    uint32
}

const (
	spliceKeySize        = 40
	spliceControlSize    = 8
	spliceCtrlAccounting = 1 << 0
)

// Kernel splice stats ARRAY indices (native/splice.bpf.c sb_splice_stat_index).
// 0/1 are userspace-maintained pair created/released; kernel writes 2..5 only (Q10).
const (
	spliceStatPairsCreated = iota
	spliceStatPairsReleased
	spliceStatRedirects
	spliceStatRedirectFailures
	spliceStatPeerMisses
	spliceStatPassthrough
	spliceStatCount
)

// Size assertions live in outbound_abi_test.go (real compile-time via testing).
