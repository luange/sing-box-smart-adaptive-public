//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// skip reasons for safety gates (tests + debug).
const (
	verdictSkipNone = iota
	verdictSkipPort53
	verdictSkipSniff
	verdictSkipNonDirect
	verdictSkipProcessUser
	verdictSkipNoDest
	verdictSkipDisabled
	verdictSkipAddrMismatch // Q4: metadata dest ≠ established peer (DNS/rewrite)
)

// verdictLearnOptions is a pure-data view used by safety gates and tests.
type verdictLearnOptions struct {
	mode           string
	ttl            time.Duration
	allowWithSniff bool
	promoteBypass  bool
}

func verdictLearnOptionsFrom(opts option.EBPFVerdictOptions) verdictLearnOptions {
	ttl := time.Duration(opts.TTL)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	mode := opts.Mode
	if mode == "" {
		mode = "off"
	}
	promote := true
	if opts.PromoteBypass != nil {
		promote = *opts.PromoteBypass
	}
	if mode != "learn" {
		promote = false
	}
	return verdictLearnOptions{
		mode:           mode,
		ttl:            ttl,
		allowWithSniff: opts.AllowWithSniff,
		promoteBypass:  promote,
	}
}

// evaluateVerdictLearn runs safety gates without writing maps.
// Returns (ok, skipReason). ok means a DIRECT write is allowed.
func evaluateVerdictLearn(
	opts verdictLearnOptions,
	outboundDialer N.Dialer,
	metadata adapter.InboundContext,
	destination netip.AddrPort,
) (bool, int) {
	if opts.mode == "" || opts.mode == "off" {
		return false, verdictSkipDisabled
	}
	if !destination.IsValid() || !destination.Addr().IsValid() {
		return false, verdictSkipNoDest
	}
	// (a) port 53 never
	if destination.Port() == 53 {
		return false, verdictSkipPort53
	}
	// Q3: explicit route verdict gate (fail-closed on Unknown / non-IP-only).
	// Domain/process/user classes never learn DIRECT (F-4). allow_with_sniff does
	// NOT relax those classes and cannot manufacture missing scope evidence.
	if !verdictRouteInputsOK(metadata) {
		return false, verdictSkipSniff
	}
	// For an explicit DestinationIP scope, sniff metadata is orthogonal to the
	// route key and must not block learning. Legacy callers without scope have
	// already failed closed above.
	// (d) process/user based selection if detectable
	if verdictUsedProcessOrUser(metadata) {
		return false, verdictSkipProcessUser
	}
	// (c) must be empty DirectDialer (or type direct with IsEmpty)
	if !verdictIsEmptyDirect(outboundDialer) {
		return false, verdictSkipNonDirect
	}
	return true, verdictSkipNone
}

// verdictRouteInputsOK: only an explicitly destination-IP scoped verdict may
// become a global /32. Unknown scope is fail-closed, including legacy callers
// that leave MatchInputs at zero: absence of evidence is not proof that the
// decision was destination-only.
func verdictRouteInputsOK(metadata adapter.InboundContext) bool {
	if metadata.VerdictScope == adapter.RouteVerdictScopeDestinationIP {
		return true
	}
	return false
}

func verdictUsedSniff(metadata adapter.InboundContext) bool {
	// Domain/Protocol/Client/SniffHost set from sniff and destination was not pure IP-only path.
	if metadata.Protocol != "" || metadata.Client != "" || metadata.SniffHost != "" {
		return true
	}
	if metadata.Domain != "" && !metadata.Destination.IsIP() {
		return true
	}
	// Sniff filled Domain while original destination was domain-form.
	if metadata.Domain != "" && metadata.SniffHost != "" {
		return true
	}
	return false
}

func verdictUsedProcessOrUser(metadata adapter.InboundContext) bool {
	if metadata.User != "" {
		return true
	}
	if metadata.ProcessInfo != nil {
		return true
	}
	return false
}

func verdictIsEmptyDirect(outboundDialer N.Dialer) bool {
	if outboundDialer == nil {
		return false
	}
	// Plan §4.4 gate 2: direct semantic = DirectDialer, no detour/proxy rewrite.
	// Stock `{"type":"direct"}` often has IsEmpty()==false because DialerOptions
	// defaults (e.g. UDPFragmentDefault) fail DeepEqual against the empty probe —
	// still true direct. Accept TypeDirect + DirectDialer; keep IsEmpty as fast path.
	if outbound, ok := outboundDialer.(adapter.Outbound); ok {
		switch outbound.Type() {
		case C.TypeDirect, C.TypeEBPF:
			// type ebpf is direct-class (routable offload target).
			if _, ok := outboundDialer.(dialer.DirectDialer); ok {
				return true
			}
			return false
		}
	}
	if directDialer, ok := outboundDialer.(dialer.DirectDialer); ok {
		return directDialer.IsEmpty()
	}
	return false
}

// resolveLearnDestination picks the key for verdict/promote (Q4/N5, perf 2026-08-04).
// Prefer metadata.Destination (IP) — that is what TC/shared_network sees on LAN clients.
// Peer (dial result) must not be a *different host* (proxy leaf); multi-A / port
// variance is accepted so DIRECT learn actually triggers in production.
func resolveLearnDestination(metadata adapter.InboundContext, remoteAddr netip.AddrPort) (netip.AddrPort, int) {
	var preferred netip.AddrPort
	if metadata.Destination.IsValid() && metadata.Destination.IsIP() {
		preferred = metadata.Destination.AddrPort()
	} else if len(metadata.DestinationAddresses) > 0 {
		addr := metadata.DestinationAddresses[0]
		port := metadata.Destination.Port
		if port == 0 && remoteAddr.IsValid() {
			port = remoteAddr.Port()
		}
		if addr.IsValid() && port != 0 {
			preferred = netip.AddrPortFrom(addr, port)
		}
	}
	peerOK := remoteAddr.IsValid() && remoteAddr.Addr().IsValid() &&
		!remoteAddr.Addr().IsUnspecified() && remoteAddr.Port() != 0
	if !preferred.IsValid() || !preferred.Addr().IsValid() || preferred.Port() == 0 {
		// No metadata-side IP: peer-only key misses TC/client lookup — refuse.
		return netip.AddrPort{}, verdictSkipNoDest
	}
	if !peerOK {
		return preferred, verdictSkipNone
	}
	pa, ra := preferred.Addr().Unmap(), remoteAddr.Addr().Unmap()
	if pa == ra {
		// Port may differ (rewrite); keep client-visible dest port.
		return netip.AddrPortFrom(pa, preferred.Port()), verdictSkipNone
	}
	// Happy-Eyeballs / multi-A: dialed peer is another address for same name.
	for _, a := range metadata.DestinationAddresses {
		if a.IsValid() && a.Unmap() == ra {
			return preferred, verdictSkipNone
		}
	}
	// Different host (typically proxy server) — caller should have gated non-direct first.
	return netip.AddrPort{}, verdictSkipAddrMismatch
}

// verdictInboundEligible: native eBPF inbound, or shared-network transparent
// flows that still surface as mixed. Socks/tun/other stay out (A4).
// Must match Inbound.ebpfLearnEligible — single gate for CM + coordinator.
func verdictInboundEligible(inboundType string) bool {
	return inboundType == C.TypeEBPF || inboundType == C.TypeMixed
}

// MaybeLearnTCP is the ConnectionManager hook after successful dial.
// Fail-open: never returns an error that aborts the connection.
// A4/F-3: only eBPF / shared-network mixed may write the cgroup verdict map.
func (c *outboundCoordinator) MaybeLearnTCP(
	ctx context.Context,
	outboundDialer N.Dialer,
	metadata adapter.InboundContext,
	remote netip.AddrPort,
) {
	if c == nil {
		return
	}
	// A4: reject socks/tun/etc. Mixed is allowed for shared-network socket_assign
	// (Inbound.ebpfLearnEligible already filtered hub members with shared off).
	if !verdictInboundEligible(metadata.InboundType) {
		return
	}
	c.learnInvoked.Add(1)
	// Perf: gate non-direct BEFORE resolve/backend. Count for ops (atomic).
	if !verdictIsEmptyDirect(outboundDialer) {
		c.noteSkipReason(verdictSkipNonDirect)
		return
	}
	c.access.RLock()
	backend := c.verdict
	opts := c.verdictLearn
	closed := c.closed
	c.access.RUnlock()
	if backend == nil || closed {
		return
	}
	// W3: mode enum is off|learn only ("dns" rejected at normalize).
	if opts.mode != "learn" {
		return
	}
	dest, resolveReason := resolveLearnDestination(metadata, remote)
	if resolveReason != verdictSkipNone || !dest.IsValid() {
		backend.Skip()
		c.noteSkipReason(resolveReason)
		c.debug("eBPF verdict learn skip: reason=", resolveReason, " dest=", dest.String())
		return
	}
	// Q3: keep legacy sniff gate (AND with future MatchInputs); process/user/port53 remain.
	ok, reason := evaluateVerdictLearn(opts, outboundDialer, metadata, dest)
	if !ok {
		backend.Skip()
		c.noteSkipReason(reason)
		c.debug("eBPF verdict learn skip: reason=", reason, " dest=", dest.String())
		return
	}
	if err := backend.PutDIRECT(ECommon.ProtocolTCP, dest, opts.ttl); err != nil {
		c.warn("eBPF verdict learn write failed (ignored): ", err)
		return
	}
	// Info-level so lab evidence (F-5) is visible at default log.level=info.
	if c.logger != nil {
		c.logger.Info("eBPF verdict learn wrote DIRECT: ", dest.String(), " ttl=", opts.ttl)
	}
	// Always promote TC on gateway learn success. promote_bypass=false only
	// disables optional connect4-era behavior in docs; TC LPM is the real
	// shared_network hit path and must stay armed for DIRECT leaves.
	c.promoteLearnedBypass(dest.Addr(), opts.ttl)
}

// MaybeLearnUDP mirrors the TCP learner for the local cgroup capture surface.
// The shared-network exact-flow map is published by Inbound.MaybeLearnUDP;
// keeping this destination-level learner here preserves existing cgroup
// verdict behavior without sharing state between the two capture surfaces.
func (c *outboundCoordinator) MaybeLearnUDP(
	ctx context.Context,
	outboundDialer N.Dialer,
	metadata adapter.InboundContext,
	remote netip.AddrPort,
) {
	if c == nil {
		return
	}
	if !verdictInboundEligible(metadata.InboundType) {
		return
	}
	c.learnInvoked.Add(1)
	if !verdictIsEmptyDirect(outboundDialer) {
		c.noteSkipReason(verdictSkipNonDirect)
		return
	}
	c.access.RLock()
	backend := c.verdict
	opts := c.verdictLearn
	closed := c.closed
	c.access.RUnlock()
	if backend == nil || opts.mode != "learn" || closed {
		return
	}
	dest, resolveReason := resolveLearnDestination(metadata, remote)
	if resolveReason != verdictSkipNone || !dest.IsValid() || dest.Port() == 53 {
		backend.Skip()
		if resolveReason != verdictSkipNone {
			c.noteSkipReason(resolveReason)
		} else if dest.Port() == 53 {
			c.noteSkipReason(verdictSkipPort53)
		}
		return
	}
	ok, reason := evaluateVerdictLearn(opts, outboundDialer, metadata, dest)
	if !ok {
		backend.Skip()
		c.noteSkipReason(reason)
		return
	}
	if err := backend.PutDIRECT(ECommon.ProtocolUDP, dest, opts.ttl); err != nil {
		c.warn("eBPF UDP verdict learn write failed (ignored): ", err)
		return
	}
	c.promoteLearnedBypass(dest.Addr(), opts.ttl)
}

func (c *outboundCoordinator) debug(args ...any) {
	if c == nil || c.logger == nil {
		return
	}
	c.logger.Debug(args...)
}

func (c *outboundCoordinator) warn(args ...any) {
	if c == nil || c.logger == nil {
		return
	}
	c.logger.Warn(args...)
}
