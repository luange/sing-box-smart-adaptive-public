//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// bypassMissSampler watches userspace-admitted flows against the installed
// bypass LPM. On a PBR gateway, CN should die in TC; if a covered IP still
// arrives in userspace, either the map is stale or the classifier missed.
//
// Sampling keeps overhead near-zero under multi-Gbps proxies.
type bypassMissSampler struct {
	// every Nth TCP flow (0 = disabled, default 32)
	every uint32
	seq   atomic.Uint64

	// coveredByPolicy: dest matches bypass LPM but still hit userspace (kernel miss)
	kernelMiss atomic.Uint64
	// notInPolicy: dest not in bypass LPM (expected for proxy; sample for ops top-N)
	userspace atomic.Uint64
	// gapHeal: DIRECT-eligible IPs missing from static LPM that we promoted
	gapHeal atomic.Uint64
	// last log rate limit
	lastKernelLog atomic.Int64
	lastGapLog    atomic.Int64
}

func newBypassMissSampler() *bypassMissSampler {
	return &bypassMissSampler{every: 32}
}

func (s *bypassMissSampler) Snapshot() (kernelMiss, userspace, gapHeal uint64) {
	if s == nil {
		return 0, 0, 0
	}
	return s.kernelMiss.Load(), s.userspace.Load(), s.gapHeal.Load()
}

// ObserveTCP samples one destination from a userspace-admitted TCP flow.
func (s *bypassMissSampler) ObserveTCP(i *Inbound, dest netip.Addr) {
	if s == nil || i == nil || !dest.IsValid() || s.every == 0 {
		return
	}
	n := s.seq.Add(1)
	if n%uint64(s.every) != 0 {
		return
	}
	dest = dest.Unmap()
	if dest.IsPrivate() || dest.IsLoopback() || dest.IsUnspecified() || dest.IsLinkLocalUnicast() {
		return
	}
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	if backend.BypassContains(dest) {
		s.kernelMiss.Add(1)
		// Rate-limit warns: at most one per 30s.
		now := time.Now().Unix()
		prev := s.lastKernelLog.Load()
		if now-prev >= 30 && s.lastKernelLog.CompareAndSwap(prev, now) {
			i.logger.Warn("eBPF bypass miss (policy covers dest but flow hit userspace): ", dest.String(),
				" kernel_miss_total=", s.kernelMiss.Load())
		}
		return
	}
	s.userspace.Add(1)
	// If route would choose DIRECT for this IP, static LPM/geoip is incomplete —
	// self-heal with a temporary /32 promote so subsequent packets skip userspace.
	// The promote is identity-blind (no client/source in the sampler ABI), so it
	// must respect the same mac_source_policy boundary as the DNS prefill path:
	// a source-sensitive policy makes any global /32 DIRECT hint unsafe.
	if i.dnsPrefillIdentitySafe() && i.dnsPrefillRouter != nil && i.dnsPrefillOutbounds != nil {
		if dnsPrefillIsStableDirect(i.dnsPrefillRouter, i.dnsPrefillOutbounds, i.Tag(), "", dest) {
			if i.promoteLearnedBypass(dest, i.directPromoteTTL()) {
				s.gapHeal.Add(1)
				now := time.Now().Unix()
				prev := s.lastGapLog.Load()
				if now-prev >= 30 && s.lastGapLog.CompareAndSwap(prev, now) {
					i.logger.Info("eBPF bypass gap self-heal promote ", dest.String(),
						" gap_heal_total=", s.gapHeal.Load())
				}
			}
		}
	}
}
