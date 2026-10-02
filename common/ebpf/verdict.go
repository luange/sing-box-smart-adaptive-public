//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// VerdictStats are module A observability counters (userspace + kernel).
// KernelHits/Expired/GenMismatch are read from the BPF ARRAY stats map (A2).
type VerdictStats struct {
	Writes      uint64 // userspace PutDIRECT successes
	Skips       uint64 // userspace safety-gate skips
	KernelHits  uint64 // BPF: DIRECT bypass taken
	Expired     uint64 // BPF: entry present but expire_ns passed
	GenMismatch uint64 // BPF: generation != control.generation
}

// VerdictEntry is one exported flow-verdict cache row (debug / tests).
type VerdictEntry struct {
	Destination netip.AddrPort
	Family      uint8
	Protocol    uint8
	Verdict     uint8
	Generation  uint32
	ExpireNs    uint64
}

// VerdictBackend owns the flow-verdict map fds created by inbound Prepare.
// Maps are closed with the inbound Backend lifecycle.
//
// Granularity (A3/F-3): keys are destination-level {family,protocol,port,addr}
// only — not per-UID/flow. One DIRECT learn affects all local UIDs for that dest
// on the cgroup capture surface. Keep mode=off unless that model fits the deployment.
type VerdictBackend struct {
	access     sync.RWMutex
	verdictMap int
	controlMap int
	statsMap   int // BPF ARRAY: hits/expired/gen_mismatch (A2)
	generation uint32
	enabled    bool
	writes     atomic.Uint64
	skips      atomic.Uint64
	verdictExportRing
}

// NewVerdictBackend wraps map fds from inbound runtime after Prepare.
// control map must already exist; seeds generation=1, enabled=1.
// statsMapFD may be -1 (kernel counters then stay 0).
func NewVerdictBackend(verdictMapFD, controlMapFD, statsMapFD int) (*VerdictBackend, error) {
	if verdictMapFD < 0 || controlMapFD < 0 {
		return nil, E.New("verdict maps not available")
	}
	v := &VerdictBackend{
		verdictMap: verdictMapFD,
		controlMap: controlMapFD,
		statsMap:   statsMapFD,
		generation: 1,
		enabled:    true,
	}
	if err := v.writeControl(); err != nil {
		return nil, E.Cause(err, "seed verdict control map")
	}
	return v, nil
}

func (v *VerdictBackend) writeControl() error {
	if v == nil || v.controlMap < 0 {
		return osErrClosed
	}
	key := uint32(0)
	ctrl := outVerdictControl{
		Generation: v.generation,
		Enabled:    0,
	}
	if v.enabled {
		ctrl.Enabled = 1
	}
	return updateMap(v.controlMap, unsafe.Pointer(&key), unsafe.Pointer(&ctrl))
}

// PutDIRECT writes a DIRECT verdict for destination (host-order port in key).
func (v *VerdictBackend) PutDIRECT(protocol uint8, destination netip.AddrPort, ttl time.Duration) error {
	if v == nil {
		return osErrClosed
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	v.access.RLock()
	defer v.access.RUnlock()
	if v.verdictMap < 0 || !v.enabled {
		return osErrClosed
	}
	key, err := makeOutVerdictKey(protocol, destination)
	if err != nil {
		return err
	}
	expire, err := monotonicExpireNs(ttl)
	if err != nil {
		return err
	}
	value := outVerdictValue{
		Verdict:    OutVerdictDIRECT,
		Generation: v.generation,
		ExpireNs:   expire,
	}
	if err = updateMap(v.verdictMap, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "update flow verdict map")
	}
	v.writes.Add(1)
	v.recordExport(key, value, destination)
	return nil
}

// Skip records a safety-gate skip (never an error path).
func (v *VerdictBackend) Skip() {
	if v == nil {
		return
	}
	v.skips.Add(1)
}

// InvalidateAll bumps control.generation so all cached entries miss generation match.
func (v *VerdictBackend) InvalidateAll() error {
	if v == nil {
		return osErrClosed
	}
	v.access.Lock()
	defer v.access.Unlock()
	if v.controlMap < 0 {
		return osErrClosed
	}
	v.generation++
	if v.generation == 0 {
		v.generation = 1
	}
	return v.writeControl()
}

// SetEnabled toggles control.enabled (fail-open off does not close maps).
func (v *VerdictBackend) SetEnabled(enabled bool) error {
	if v == nil {
		return osErrClosed
	}
	v.access.Lock()
	defer v.access.Unlock()
	v.enabled = enabled
	return v.writeControl()
}

// Stats returns userspace writes/skips plus kernel hit counters from the BPF stats map (A2).
func (v *VerdictBackend) Stats() VerdictStats {
	if v == nil {
		return VerdictStats{}
	}
	st := VerdictStats{
		Writes: v.writes.Load(),
		Skips:  v.skips.Load(),
	}
	v.access.RLock()
	statsFD := v.statsMap
	v.access.RUnlock()
	if statsFD >= 0 {
		st.KernelHits = lookupVerdictStat(statsFD, outVerdictStatHits)
		st.Expired = lookupVerdictStat(statsFD, outVerdictStatExpired)
		st.GenMismatch = lookupVerdictStat(statsFD, outVerdictStatGenMismatch)
	}
	return st
}

func lookupVerdictStat(statsFD int, index uint32) uint64 {
	var value uint64
	if err := lookupMap(statsFD, unsafe.Pointer(&index), unsafe.Pointer(&value)); err != nil {
		return 0
	}
	return value
}

// Export returns a snapshot of recent writes (debug / tests). Not a full map dump.
// Oldest first. When full, head points at the oldest entry (next overwrite slot).
// Export returns the recorded verdict entries. Nil-receiver safe (the
// nil-safe contract test pins this).
func (v *VerdictBackend) Export() []VerdictEntry {
	if v == nil {
		return nil
	}
	return v.verdictExportRing.Export()
}

// Generation returns the current control generation.
func (v *VerdictBackend) Generation() uint32 {
	if v == nil {
		return 0
	}
	v.access.RLock()
	defer v.access.RUnlock()
	return v.generation
}

// Close detaches this wrapper (does not close map fds; inbound owns them).
// Q8: best-effort write enabled=0 to control before dropping local fds so the
// kernel stops DIRECT bypass while maps still live under inbound Backend.
func (v *VerdictBackend) Close() {
	if v == nil {
		return
	}
	v.access.Lock()
	defer v.access.Unlock()
	if v.controlMap >= 0 {
		v.enabled = false
		_ = v.writeControl() // best-effort; ignore error (fail-open close)
	}
	v.verdictMap = -1
	v.controlMap = -1
	v.statsMap = -1
	v.enabled = false
}

func makeOutVerdictKey(protocol uint8, destination netip.AddrPort) (outVerdictKey, error) {
	var key outVerdictKey
	key.Protocol = protocol
	key.Port = destination.Port() // host order (ABI iron law)
	if err := putAddress(&key.Family, &key.Addr, destination.Addr()); err != nil {
		return outVerdictKey{}, E.Cause(err, "invalid verdict destination")
	}
	return key, nil
}

// monotonicExpireNs returns bpf_ktime_get_ns()-comparable deadline.
// A1/F-2: never fall back to wall clock (would make expire_ns never fire).
// On failure return err so PutDIRECT aborts the write (fail-open = no permanent bypass).
func monotonicExpireNs(ttl time.Duration) (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	now := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	return now + uint64(ttl), nil
}
