//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// outboundCoordinator owns module B (splice) and A (verdict) lifecycle under the ebpf inbound.
// Not a routable outbound type.
type outboundCoordinator struct {
	logger interface {
		Info(args ...any)
		Warn(args ...any)
		Debug(args ...any)
	}
	spliceOpts  option.EBPFSpliceOptions
	verdictOpts option.EBPFVerdictOptions

	access       sync.RWMutex
	closed       bool // Q1: Close marks closed; keep pointer, entries become no-op
	splice       *ECommon.SpliceBackend
	verdict      *ECommon.VerdictBackend
	verdictLearn verdictLearnOptions
	idleTimeout  time.Duration
	halfClose    string
	// allowOutbound is the normalized whitelist (default: direct only). E4 / B-5.
	allowOutbound map[string]struct{}
	// lastInvalidate is wall time of last successful InvalidateAll (observability).
	lastInvalidate time.Time
	// Bypass fingerprint: only commit after successful InvalidateAll (N1/N7).
	lastBypassFingerprint string
	fingerprintSeeded     bool
	// clampWarnings from normalize (N3); logged once at Start.
	clampWarnings []string
	// promoteToBypass installs learned DIRECT IPs into TC bypass (gateway hit-rate).
	// Set by inbound after construction; nil = no-op.
	promoteToBypass func(addr netip.Addr, ttl time.Duration)
	clearPromoted   func()
	// skipReason counts for learn gates (index = verdictSkip* const). Atomic for
	// hot non_direct path under smart/proxy traffic without taking access lock.
	skipReason   [8]atomic.Uint64
	learnInvoked atomic.Uint64
	// splice skip tallies (high-cardinality path → Debug log + periodic Info)
	spliceSkipBareTCP uint64
	spliceSkipType    uint64
	spliceSkipRecvq   uint64
	spliceActive      uint64
	// Q5: backend-level single epoll + idle sweeper (nil → per-pair fallback).
	spliceWatch *spliceWatcher
}

func newOutboundCoordinator(
	logger interface {
		Info(args ...any)
		Warn(args ...any)
		Debug(args ...any)
	},
	opts option.EBPFOutboundOffloadOptions,
	defaultIdle time.Duration,
) *outboundCoordinator {
	idle := time.Duration(opts.Splice.IdleTimeout)
	if idle <= 0 {
		idle = 2 * defaultIdle
		if idle <= 0 {
			idle = 10 * time.Minute
		}
	}
	half := opts.Splice.HalfClose
	if half == "" {
		half = "close"
	}
	allow := make(map[string]struct{})
	if len(opts.Splice.AllowOutboundTypes) == 0 {
		// Default whitelist: types whose *upstream official* dial already finishes
		// framing before ConnectionManager copy (no protocol-side patches).
		// - direct / type:ebpf: bare dial
		// - socks / http CONNECT (no TLS to proxy): handshake done, remaining bare TCP
		// AEAD/TLS leaves (ss/trojan/vless/vmess/…) stay out — do not list them unless
		// you know the dial returns post-transform bare TCP (rare). Opaque gate still
		// blocks peeling under tls.Conn.
		allow[C.TypeDirect] = struct{}{}
		allow[C.TypeEBPF] = struct{}{}
		allow[C.TypeSOCKS] = struct{}{}
		allow[C.TypeHTTP] = struct{}{}
	} else {
		for _, t := range opts.Splice.AllowOutboundTypes {
			if t != "" {
				allow[t] = struct{}{}
			}
		}
	}
	return &outboundCoordinator{
		logger:        logger,
		spliceOpts:    opts.Splice,
		verdictOpts:   opts.Verdict,
		verdictLearn:  verdictLearnOptionsFrom(opts.Verdict),
		idleTimeout:   idle,
		halfClose:     half,
		allowOutbound: allow,
	}
}

// spliceOutboundOK checks dialer type against allow_outbound_types (E4).
// Groups (selector/smart/urltest) are unwrapped one level when possible so a
// selector pointing at socks/direct can splice; encrypted leaves still fail the
// type check (and the opaque-conn gate even if whitelisted by mistake).
func (c *outboundCoordinator) spliceOutboundOK(dialer N.Dialer) bool {
	if c == nil {
		return false
	}
	outbound, ok := dialer.(adapter.Outbound)
	if !ok {
		// Plain dialer (tests) — still requires bare TCP at call site.
		return true
	}
	for depth := 0; depth < 8 && outbound != nil; depth++ {
		if _, allowed := c.allowOutbound[outbound.Type()]; allowed {
			return true
		}
		// selector: fixed Selected(); other groups lack a stable Selected() API
		// without metadata — stop after one unwrap attempt.
		if sg, ok := outbound.(adapter.SelectorGroup); ok {
			if next := sg.Selected(); next != nil && next != outbound {
				outbound = next
				continue
			}
		}
		break
	}
	return false
}

func (c *outboundCoordinator) enabled() bool {
	if c == nil {
		return false
	}
	c.access.RLock()
	defer c.access.RUnlock()
	return !c.closed && c.spliceOpts.Enabled
}

func (c *outboundCoordinator) verdictEnabled() bool {
	if c == nil {
		return false
	}
	c.access.RLock()
	defer c.access.RUnlock()
	return !c.closed && c.verdictLearn.mode != "" && c.verdictLearn.mode != "off"
}

func (c *outboundCoordinator) isClosed() bool {
	if c == nil {
		return true
	}
	c.access.RLock()
	defer c.access.RUnlock()
	return c.closed
}

// StartSplice attaches module B (fail-open).
func (c *outboundCoordinator) Start() error {
	if c == nil {
		return nil
	}
	if err := c.startSplice(); err != nil {
		return err
	}
	// Verdict maps are owned by inbound Backend; StartVerdict is called separately
	// once Backend.Prepare has completed (see startOutboundOffload).
	return nil
}

func (c *outboundCoordinator) startSplice() error {
	if c == nil || !c.spliceOpts.Enabled {
		return nil
	}
	// W4: half_close=passthrough is a splice kill-switch, not true half-close
	// forwarding. Do not attach SOCKMAP at all (avoids white-cost pair rejects).
	if c.halfClose == "passthrough" {
		c.logger.Info("eBPF splice disabled: half_close=passthrough (true half-close forwarding not implemented)")
		return nil
	}
	maxPairs := c.spliceOpts.MaxPairs
	if maxPairs == 0 {
		maxPairs = 65536
	}
	// Residual-window review §4.3: Activate↔FIONREAD race needs byte-idle
	// watchdog; force accounting on when splice is enabled (override false).
	accounting := true
	if c.spliceOpts.Accounting != nil && !*c.spliceOpts.Accounting {
		c.logger.Warn("eBPF splice accounting=false ignored while splice enabled (byte-idle watchdog required)")
	}
	backend, err := ECommon.PrepareSplice(maxPairs, accounting)
	if err != nil {
		// Fail open: do not block inbound (master §1.4 / plan Android gate).
		c.logger.Warn("eBPF outbound splice prepare failed (disabled): ", err)
		return nil
	}
	if err := backend.Attach(); err != nil {
		_ = backend.Close()
		c.logger.Warn("eBPF outbound splice attach failed (disabled): ", err)
		return nil
	}
	watcher, werr := newSpliceWatcher(c.logger, accounting, c.idleTimeout)
	if werr != nil {
		c.logger.Warn("eBPF splice backend watcher unavailable (per-pair fallback): ", werr)
	} else {
		c.logger.Info("eBPF splice backend watcher started (single epoll)")
	}
	c.access.Lock()
	c.splice = backend
	c.spliceWatch = watcher
	c.access.Unlock()
	allowList := make([]string, 0, len(c.allowOutbound))
	for t := range c.allowOutbound {
		allowList = append(allowList, t)
	}
	sort.Strings(allowList)
	c.logger.Info(
		"eBPF outbound splice attached: max_pairs=", maxPairs,
		", accounting=", accounting,
		", half_close=", c.halfClose,
		", idle_timeout=", c.idleTimeout,
		", allow_outbound_types=", strings.Join(allowList, ","),
	)
	return nil
}

// StartVerdict wires Module A against inbound-owned map fds. Fail-open on error.
func (c *outboundCoordinator) StartVerdict(inboundBackend *ECommon.Backend) error {
	if c == nil || !c.verdictEnabled() {
		return nil
	}
	if inboundBackend == nil || !inboundBackend.FlowVerdictEnabled() {
		c.logger.Warn("eBPF outbound verdict enabled in config but maps missing (disabled)")
		return nil
	}
	vMap, cMap, sMap := inboundBackend.OutVerdictMapFDs()
	backend, err := ECommon.NewVerdictBackend(vMap, cMap, sMap)
	if err != nil {
		c.logger.Warn("eBPF outbound verdict prepare failed (disabled): ", err)
		return nil
	}
	c.access.Lock()
	c.verdict = backend
	c.access.Unlock()
	c.logger.Info("eBPF outbound verdict enabled: mode=", c.verdictLearn.mode,
		", ttl=", c.verdictLearn.ttl,
		", allow_with_sniff=", c.verdictLearn.allowWithSniff,
		" (destination-level key; see docs A3/F-3)")
	return nil
}

func (c *outboundCoordinator) Close() error {
	if c == nil {
		return nil
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	splice := c.splice
	c.splice = nil
	watcher := c.spliceWatch
	c.spliceWatch = nil
	verdict := c.verdict
	c.verdict = nil
	c.access.Unlock()
	// Stop shared watcher before closing pairs/backend (unblocks EpollWait).
	if watcher != nil {
		watcher.Close()
	}
	// Q8: best-effort stop kernel bypass before releasing references; never block close.
	if verdict != nil {
		if err := verdict.InvalidateAll(); err != nil {
			c.warn("eBPF verdict InvalidateAll on close failed (generation bump): ", err)
			if err2 := verdict.SetEnabled(false); err2 != nil {
				c.warn("eBPF verdict SetEnabled(false) on close failed: ", err2)
			}
		} else {
			c.logger.Info("eBPF verdict InvalidateAll reason=close generation=", verdict.Generation())
		}
		verdict.Close()
	}
	var errs []error
	if splice != nil {
		if err := splice.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

// doInvalidate runs InvalidateAll + failure fallback. On success records lastInvalidate.
// Does not touch fingerprint (caller commits fingerprint only after true).
func (c *outboundCoordinator) doInvalidate(reason string) bool {
	if c == nil || c.isClosed() {
		return false
	}
	v := c.Verdict()
	if v == nil {
		return false
	}
	if err := v.InvalidateAll(); err != nil {
		c.warn("eBPF verdict InvalidateAll reason=", reason, " failed (will retry on next interface update): ", err)
		if err2 := v.SetEnabled(false); err2 != nil {
			c.warn("eBPF verdict SetEnabled(false) fallback ALSO failed; kernel DIRECT bypass may still be active: ", err2)
		} else {
			c.logger.Info("eBPF verdict disabled (enabled=0) after InvalidateAll failure reason=", reason)
		}
		return false
	}
	c.access.Lock()
	c.lastInvalidate = time.Now()
	c.access.Unlock()
	c.logger.Info("eBPF verdict InvalidateAll reason=", reason, " generation=", v.Generation())
	c.clearPromotedBypass()
	return true
}

// InvalidateVerdictIfNeeded bumps generation only when bypass fingerprint changed (Q2/N1).
// Fingerprint is committed only after successful InvalidateAll. First observation seeds only.
func (c *outboundCoordinator) InvalidateVerdictIfNeeded(fingerprint, reason string) bool {
	if c == nil || c.isClosed() {
		return false
	}
	c.access.Lock()
	if !c.fingerprintSeeded {
		c.lastBypassFingerprint = fingerprint
		c.fingerprintSeeded = true
		c.access.Unlock()
		return false
	}
	if c.lastBypassFingerprint == fingerprint {
		c.access.Unlock()
		return false
	}
	c.access.Unlock()

	if !c.doInvalidate(reason) {
		// Fingerprint NOT committed → next InterfaceUpdated retries (N1).
		return false
	}
	c.access.Lock()
	c.lastBypassFingerprint = fingerprint
	c.fingerprintSeeded = true
	c.access.Unlock()
	return true
}

// InvalidateVerdictNow forces InvalidateAll without fingerprint compare (N2).
func (c *outboundCoordinator) InvalidateVerdictNow(reason string) bool {
	return c.doInvalidate(reason)
}

// NoteBypassFingerprint sets fingerprint baseline without invalidate (N2 after forced invalidate).
func (c *outboundCoordinator) NoteBypassFingerprint(fingerprint string) {
	if c == nil {
		return
	}
	c.access.Lock()
	c.lastBypassFingerprint = fingerprint
	c.fingerprintSeeded = true
	c.access.Unlock()
}

func (c *outboundCoordinator) Verdict() *ECommon.VerdictBackend {
	if c == nil {
		return nil
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if c.closed {
		return nil
	}
	return c.verdict
}

func (c *outboundCoordinator) Splice() *ECommon.SpliceBackend {
	if c == nil {
		return nil
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if c.closed {
		return nil
	}
	return c.splice
}

func (c *outboundCoordinator) SpliceWatcher() *spliceWatcher {
	if c == nil {
		return nil
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if c.closed {
		return nil
	}
	return c.spliceWatch
}
func (c *outboundCoordinator) IdleTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.idleTimeout
}

func (c *outboundCoordinator) HalfClose() string {
	if c == nil {
		return "close"
	}
	return c.halfClose
}

// Capacity clamps (N3). 0 means "use default" and must not be raised to min.
const (
	outboundOffloadMaxPairsCap   = 262144
	outboundOffloadMaxEntriesCap = 262144
	outboundOffloadMinCapacity   = 16
)

func normalizeOutboundOffloadOptions(options option.EBPFOutboundOffloadOptions) (option.EBPFOutboundOffloadOptions, []string, error) {
	// Defaults: everything off. Field names locked by master §7 / plan §6.
	var warnings []string
	if options.Verdict.Mode == "" {
		options.Verdict.Mode = "off"
	}
	switch options.Verdict.Mode {
	case "off", "learn":
	case "dns":
		// W3 scheme A: enum value never shipped on lab configs; reject with migration hint.
		return options, nil, E.New("outbound_offload.verdict.mode \"dns\" was never implemented (no router dry-run); use \"learn\" or \"off\"")
	default:
		return options, nil, E.New("outbound_offload.verdict.mode must be off or learn")
	}
	if options.Splice.HalfClose == "" {
		options.Splice.HalfClose = "close"
	}
	switch options.Splice.HalfClose {
	case "close", "passthrough":
		// passthrough keeps the enum value for forward-compat; runtime treats it as
		// "do not attach splice" until true half-close forwarding exists (W4).
	default:
		return options, nil, E.New("outbound_offload.splice.half_close must be close or passthrough")
	}
	// N3/Q11: capacity always clamp+Warn — never new startup errors for existing fields.
	// MaxPairs == 0 means default (65536 at startSplice); must not be rewritten to 16.
	if options.Splice.MaxPairs != 0 {
		if options.Splice.MaxPairs < outboundOffloadMinCapacity {
			warnings = append(warnings,
				"outbound_offload.splice.max_pairs raised to "+itoaU32(outboundOffloadMinCapacity))
			options.Splice.MaxPairs = outboundOffloadMinCapacity
		} else if options.Splice.MaxPairs > outboundOffloadMaxPairsCap {
			warnings = append(warnings,
				"outbound_offload.splice.max_pairs clamped to "+itoaU32(outboundOffloadMaxPairsCap))
			options.Splice.MaxPairs = outboundOffloadMaxPairsCap
		}
	}
	if options.Verdict.MaxEntries != 0 {
		if options.Verdict.MaxEntries < outboundOffloadMinCapacity {
			warnings = append(warnings,
				"outbound_offload.verdict.max_entries raised to "+itoaU32(outboundOffloadMinCapacity))
			options.Verdict.MaxEntries = outboundOffloadMinCapacity
		} else if options.Verdict.MaxEntries > outboundOffloadMaxEntriesCap {
			warnings = append(warnings,
				"outbound_offload.verdict.max_entries clamped to "+itoaU32(outboundOffloadMaxEntriesCap))
			options.Verdict.MaxEntries = outboundOffloadMaxEntriesCap
		}
	}
	if options.Verdict.AllowWithSniff {
		// Q3 P4: field kept (B-4) but no longer opens domain/protocol learn paths.
		// MatchInputs gate is authoritative. Keep accepting the field so existing
		// configurations remain readable, but make its no-op semantics explicit.
		warnings = append(warnings,
			"outbound_offload.verdict.allow_with_sniff is deprecated: it no longer relaxes domain/protocol/process learn gates (Q3); prefer IP-only rules + MatchInputs")
	}
	if options.Verdict.TTL < 0 {
		return options, warnings, E.New("outbound_offload.verdict.ttl must be >= 0")
	}
	if options.Splice.IdleTimeout < 0 {
		return options, warnings, E.New("outbound_offload.splice.idle_timeout must be >= 0")
	}
	// E4: empty allow list → default ["direct"] at coordinator construction.
	for _, t := range options.Splice.AllowOutboundTypes {
		switch t {
		case "":
			return options, warnings, E.New("outbound_offload.splice.allow_outbound_types entry must not be empty")
		}
	}
	return options, warnings, nil
}

func itoaU32(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// SetPromoteHooks wires TC bypass promotion (call from inbound Start path).
func (c *outboundCoordinator) SetPromoteHooks(promote func(netip.Addr, time.Duration), clear func()) {
	if c == nil {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	c.promoteToBypass = promote
	c.clearPromoted = clear
}

func (c *outboundCoordinator) promoteLearnedBypass(addr netip.Addr, ttl time.Duration) {
	if c == nil || !addr.IsValid() {
		return
	}
	c.access.RLock()
	fn := c.promoteToBypass
	c.access.RUnlock()
	if fn == nil {
		return
	}
	fn(addr.Unmap(), ttl)
}

func (c *outboundCoordinator) clearPromotedBypass() {
	if c == nil {
		return
	}
	c.access.RLock()
	fn := c.clearPromoted
	c.access.RUnlock()
	if fn != nil {
		fn()
	}
}

func (c *outboundCoordinator) noteSkipReason(reason int) {
	if c == nil || reason < 0 || reason >= len(c.skipReason) {
		return
	}
	c.skipReason[reason].Add(1)
}

func (c *outboundCoordinator) SkipReasonSnapshot() [8]uint64 {
	var out [8]uint64
	if c == nil {
		return out
	}
	for i := range c.skipReason {
		out[i] = c.skipReason[i].Load()
	}
	return out
}

func (c *outboundCoordinator) LearnInvoked() uint64 {
	if c == nil {
		return 0
	}
	return c.learnInvoked.Load()
}

func (c *outboundCoordinator) noteSpliceSkipBareTCP() {
	if c == nil {
		return
	}
	c.access.Lock()
	c.spliceSkipBareTCP++
	c.access.Unlock()
}

func (c *outboundCoordinator) noteSpliceSkipType() {
	if c == nil {
		return
	}
	c.access.Lock()
	c.spliceSkipType++
	c.access.Unlock()
}

func (c *outboundCoordinator) noteSpliceSkipRecvq() {
	if c == nil {
		return
	}
	c.access.Lock()
	c.spliceSkipRecvq++
	c.access.Unlock()
}

func (c *outboundCoordinator) noteSpliceActive() {
	if c == nil {
		return
	}
	c.access.Lock()
	c.spliceActive++
	c.access.Unlock()
}

func (c *outboundCoordinator) SpliceSkipSnapshot() (bare, typ, recvq, active uint64) {
	if c == nil {
		return
	}
	c.access.RLock()
	defer c.access.RUnlock()
	return c.spliceSkipBareTCP, c.spliceSkipType, c.spliceSkipRecvq, c.spliceActive
}
