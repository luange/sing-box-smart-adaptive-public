package v3

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	ebpfv3 "github.com/sagernet/sing-box/common/ebpf/v3"
	"github.com/sagernet/sing-box/option"
)

// Lifecycle owns v3 control-plane state for one ebpf inbound.
// MemoryBackend is the pure model (tests + audit). BindSink attaches the live
// kernel dataplane so learn/publish/DNS never diverge from TC maps.
type Lifecycle struct {
	mu sync.Mutex

	options option.EBPFSharedNetworkOptions
	backend *ebpfv3.MemoryBackend
	sink    DataplaneSink

	flowTTL        time.Duration
	macQuarantined bool
	// dataplaneQuarantined is a process-lifetime safety fuse. It is set only
	// after the narrow MAC and generation recovery paths both fail; ordinary
	// control refreshes must never resurrect a dataplane in that state.
	dataplaneQuarantined bool
}

// NewLifecycle constructs control-plane state. Does not attach TC.
func NewLifecycle(options option.EBPFSharedNetworkOptions, flowTTL time.Duration) (*Lifecycle, error) {
	normalized, err := NormalizeSharedNetwork(options)
	if err != nil {
		return nil, err
	}
	if !IsV3(normalized) {
		return nil, fmt.Errorf("lifecycle requires engine=v3")
	}
	if flowTTL <= 0 {
		flowTTL = 10 * time.Minute
	}
	return &Lifecycle{
		options: normalized,
		backend: ebpfv3.NewMemoryBackend(),
		flowTTL: flowTTL,
	}, nil
}

// BindSink attaches the live kernel publisher. Call once after V3Backend prepare.
func (l *Lifecycle) BindSink(sink DataplaneSink) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = sink
}

// BackendSnapshot is the read-only lifecycle status exposed to diagnostics.
// Mutable map state remains private to Lifecycle so callers cannot bypass its
// transaction mutex or hold the MemoryBackend compile reservation themselves.
type BackendSnapshot struct {
	Control        ebpfv3.Control
	ActiveBank     uint32
	Generation     uint32
	FlowCount      int
	MACPolicyCount int
}

// Backend returns a point-in-time status snapshot, never the mutable model.
func (l *Lifecycle) Backend() BackendSnapshot {
	if l == nil {
		return BackendSnapshot{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backend == nil {
		return BackendSnapshot{}
	}
	snapshot := BackendSnapshot{
		Control:        l.backend.Control,
		FlowCount:      len(l.backend.Flows),
		MACPolicyCount: len(l.backend.MACPolicies),
	}
	if l.backend.Publisher != nil {
		snapshot.ActiveBank, snapshot.Generation = l.backend.Publisher.Snapshot()
	}
	return snapshot
}

// SyncPolicyGeneration keeps the audit model aligned with a generation that
// was committed by the live kernel publisher. LearnFlow, ObserveDNS, reload
// and Close all share this lock.
func (l *Lifecycle) SyncPolicyGeneration(generation uint32) {
	if l == nil || generation == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncPolicyGenerationLocked(generation)
}

func (l *Lifecycle) syncPolicyGenerationLocked(generation uint32) {
	if l == nil || generation == 0 {
		return
	}
	if l.backend != nil {
		if current := l.backend.Control.PolicyGeneration; current != 0 && generation < current {
			return
		}
		l.backend.Control.PolicyGeneration = generation
		l.backend.Publisher.SyncGeneration(generation)
		l.backend.InvalidateGeneration(generation)
	}
}

// Options returns normalized shared_network options.
func (l *Lifecycle) Options() option.EBPFSharedNetworkOptions {
	if l == nil {
		return option.EBPFSharedNetworkOptions{}
	}
	return l.options
}

// ControlFlags builds kernel control flags from options.
func ControlFlags(options option.EBPFSharedNetworkOptions, enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack bool, routingMark uint32) uint32 {
	var flags uint32
	if enableIPv4 {
		flags |= ebpfv3.FlagIPv4
	}
	if enableIPv6 {
		flags |= ebpfv3.FlagIPv6
	}
	if enableTCP {
		flags |= ebpfv3.FlagTCP
	}
	if enableUDP {
		flags |= ebpfv3.FlagUDP
	}
	if dnsHijack {
		flags |= ebpfv3.FlagDNSHijack
	}
	if options.DropUDP443 != nil && *options.DropUDP443 {
		flags |= ebpfv3.FlagDropUDP443
	}
	if options.DataPlane == "" || options.DataPlane == "socket_assign" {
		flags |= ebpfv3.FlagSocketAssign
	}
	flags |= ebpfv3.FlagFailureProxy
	po := options.PolicyOffload
	if po.Enabled {
		if po.StaticRules {
			flags |= ebpfv3.FlagStaticPolicy
		}
		if po.ExactFlowLearning {
			flags |= ebpfv3.FlagExactFlow
		}
		switch po.DNSIPHint {
		case "safe", "strong":
			flags |= ebpfv3.FlagDNSHint
			// Capture hard-coded plaintext DNS replies as advisory observations;
			// userspace still evaluates the complete domain rule set.
			flags |= ebpfv3.FlagDNSSniff
		}
		if po.FakeIP {
			flags |= ebpfv3.FlagFakeIP
		}
		if po.MACSourcePolicy {
			flags |= ebpfv3.FlagMACSource
		}
	}
	_ = routingMark
	return flags
}

// ApplyControlFlags refreshes backend control flag bits without flipping
// generation. When a kernel sink is bound, the same flags are pushed into the
// live control map (WriteControlV3) so a reconfig cannot leave the kernel
// running a stale feature mask while the memory model moved on.
func (l *Lifecycle) ApplyControlFlags(enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack bool, routingMark uint32) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	flags := ControlFlags(l.options, enableIPv4, enableIPv6, enableTCP, enableUDP, dnsHijack, routingMark)
	// A failed snapshot publication leaves the one-map kernel state unknown.
	// Keep MAC lookup disabled until a complete replacement succeeds; this is
	// local to the MAC subsystem and does not retire healthy flow/DNS state.
	if l.macQuarantined {
		flags &^= ebpfv3.FlagMACSource
	}
	enabled := l.backend.Control.Enabled != 0 && !l.dataplaneQuarantined
	if l.sink != nil {
		bank, generation := l.backend.Publisher.Snapshot()
		// The kernel control map is authoritative.  Do not advance the model
		// until the live feature mask has been committed successfully.
		if err := l.sink.WriteControlV3(enabled, flags, bank, generation, routingMark); err != nil {
			return err
		}
	}
	l.backend.Control.Flags = flags
	l.backend.Control.RoutingMark = routingMark
	l.backend.Control.ABIVersion = ebpfv3.ABIVersion
	if enabled {
		l.backend.Control.Enabled = 1
	} else {
		l.backend.Control.Enabled = 0
	}
	return nil
}

// PublishStaticRules compiles and double-buffers static DIRECT rules.  The v3
// dataplane intentionally has one direct fast-path sink; proxy/block/group
// rules remain userspace decisions and are reported as rejected instead of
// being counted as accepted while silently disappearing at the kernel boundary.
func (l *Lifecycle) PublishStaticRules(inputs []ebpfv3.CompileInput) (accepted int, rejected int, err error) {
	if l == nil || l.backend == nil {
		return 0, 0, fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.StaticRules {
		return 0, len(inputs), nil
	}
	compiled, rej, err := ebpfv3.CompileStatic(inputs, l.backend.Control.PolicyGeneration)
	if err != nil {
		return 0, 0, err
	}
	direct := make([]ebpfv3.CompiledPolicy, 0, len(compiled))
	for _, policy := range compiled {
		// DataplaneSink.PublishStaticDirect intentionally accepts only a
		// destination prefix.  Publishing a protocol/port-scoped rule through
		// that surface would silently broaden it to all traffic for the prefix;
		// keep such rules in userspace instead of changing their semantics.
		if policy.Value.Verdict == uint8(ebpfv3.VerdictDirect) &&
			policy.Value.MatchProtocol == 0 &&
			policy.Value.MatchDPortMin == 0 && policy.Value.MatchDPortMax == 0 {
			direct = append(direct, policy)
		} else {
			rej = append(rej, ebpfv3.CompileInput{Destination: policy.Prefix, Verdict: ebpfv3.Verdict(policy.Value.Verdict), Kind: ebpfv3.RuleKindNeedsControl, PolicyID: policy.Value.PolicyID})
		}
	}
	directPrefixes := make([]netip.Prefix, 0, len(direct))
	for _, c := range direct {
		directPrefixes = append(directPrefixes, c.Prefix)
	}
	// Stage and validate the model before touching the kernel. The reservation
	// prevents another model compile from racing this transaction; after the
	// sink succeeds, CommitPreparedStatic has no fallible path left.
	prepared, err := l.backend.PrepareStatic(direct)
	if err != nil {
		return 0, 0, err
	}
	if l.sink != nil {
		if err := l.sink.PublishStaticDirect(directPrefixes, 0, 0); err != nil {
			l.backend.AbortPreparedStatic(prepared)
			return len(direct), len(rej), err
		}
	}
	l.backend.CommitPreparedStatic(prepared)
	return len(direct), len(rej), nil
}

// PublishMACSourcePolicies replaces the complete MAC-source identity
// snapshot in both control-plane representations. It is a no-op unless
// policy_offload.mac_source_policy is enabled, so the kernel flag and the
// publication surface stay consistent. Kernel publication happens first
// (the fail-closed side), then the memory model is committed.
func (l *Lifecycle) PublishMACSourcePolicies(entries []ebpfv3.MACPolicyEntry) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.MACSourcePolicy {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	wasQuarantined := l.macQuarantined
	capHint := len(entries)
	if capHint > ebpfv3.MaxSourcePolicies+1 {
		capHint = ebpfv3.MaxSourcePolicies + 1
	}
	unique := make(map[ebpfv3.MACKey]struct{}, capHint)
	for _, entry := range entries {
		var zero ebpfv3.MACKey
		if entry.Key != zero {
			unique[entry.Key] = struct{}{}
		}
	}
	if len(unique) > ebpfv3.MaxSourcePolicies {
		return fmt.Errorf("mac source policy exceeds map capacity")
	}
	if l.sink != nil {
		if err := l.sink.PublishMACPolicies(entries); err != nil {
			return l.recoverMACPublishFailureLocked(err)
		}
	}
	if err := l.backend.PublishMACPolicies(entries); err != nil {
		// This is expected to be unreachable after the preflight above, but
		// keep the kernel/model transaction fail-closed if model validation is
		// extended in the future.
		return l.recoverMACPublishFailureLocked(err)
	}
	if wasQuarantined {
		// The snapshot is now complete and authoritative again. Re-enable the
		// MAC lookup in the same lifecycle transaction instead of waiting for a
		// later, unrelated control refresh to turn the feature back on.
		flags := l.backend.Control.Flags | ebpfv3.FlagMACSource
		if l.sink != nil {
			bank, generation := l.backend.Publisher.Snapshot()
			if err := l.sink.WriteControlV3(l.backend.Control.Enabled != 0, flags, bank, generation, l.backend.Control.RoutingMark); err != nil {
				// The snapshot itself is valid, but its activation is not. Keep the
				// local quarantine so subsequent refreshes cannot re-enable it
				// until another complete control commit succeeds.
				l.macQuarantined = true
				return err
			}
		}
		l.backend.Control.Flags = flags
	}
	l.macQuarantined = false
	return nil
}

// recoverMACPublishFailureLocked retires an uncertain one-map MAC snapshot.
// A partial kernel update must never remain live. First disable only the MAC
// lookup: this is sufficient to make an uncertain one-map snapshot inert and
// avoids invalidating unrelated static/flow/DNS rows. If that narrow control
// write fails, escalate to the shared generation fuse; if even that fails,
// disable the entire dataplane.
func (l *Lifecycle) recoverMACPublishFailureLocked(cause error) error {
	if l == nil {
		return cause
	}
	l.macQuarantined = true
	disableErr := l.disableMACSourceLocked()
	if disableErr == nil {
		return cause
	}
	if l.sink == nil {
		return errors.Join(cause, disableErr)
	}
	invalidateErr := l.invalidateGenerationLocked()
	if invalidateErr == nil {
		return errors.Join(cause, disableErr)
	}
	// The final fuse is fail-closed even when its syscall reports an error: the
	// kernel state is no longer trustworthy, so later refreshes must not issue
	// an enable write until a new lifecycle/backend is constructed.
	l.dataplaneQuarantined = true
	if l.backend != nil {
		// Reflect the terminal fail-closed state even if the detach syscall
		// itself reports an error. The quarantine bit prevents any later
		// control refresh from attempting to resurrect the dataplane.
		l.backend.Control.Enabled = 0
	}
	wholeErr := l.sink.Disable()
	return errors.Join(cause, disableErr, invalidateErr, wholeErr)
}

func (l *Lifecycle) disableMACSourceLocked() error {
	if l == nil || l.backend == nil {
		return nil
	}
	flags := l.backend.Control.Flags &^ ebpfv3.FlagMACSource
	if l.sink != nil {
		bank, generation := l.backend.Publisher.Snapshot()
		enabled := l.backend.Control.Enabled != 0
		if err := l.sink.WriteControlV3(enabled, flags, bank, generation, l.backend.Control.RoutingMark); err != nil {
			return err
		}
	}
	l.backend.Control.Flags = flags
	return nil
}

// PublishStaticDirect replaces the complete DIRECT prefix snapshot in both
// control-plane representations.  The protocol/ebpf parent already resolved
// these prefixes from its route and rule-set state, so there is no CompileInput
// to validate here.  Kernel publication happens first (the fail-closed side),
// then the memory model is committed with the same bank-flip semantics for
// tests, diagnostics, and later generation invalidation.
func (l *Lifecycle) PublishStaticDirect(prefixes []netip.Prefix) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	normalized := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	policies := make([]ebpfv3.CompiledPolicy, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			continue
		}
		if _, loaded := seen[prefix]; loaded {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
		policies = append(policies, ebpfv3.CompiledPolicy{
			Prefix: prefix,
			Value: ebpfv3.PolicyValue{
				Verdict:    uint8(ebpfv3.VerdictDirect),
				Source:     uint8(ebpfv3.SourceStatic),
				Confidence: ebpfv3.ConfidenceStrong,
				ReasonCode: uint16(ebpfv3.ReasonStaticDirect),
			},
		})
	}
	prepared, err := l.backend.PrepareStatic(policies)
	if err != nil {
		return err
	}
	if l.sink != nil {
		if err := l.sink.PublishStaticDirect(normalized, 0, 0); err != nil {
			l.backend.AbortPreparedStatic(prepared)
			return err
		}
	}
	l.backend.CommitPreparedStatic(prepared)
	return nil
}

// MergeDynamicDirect publishes one learned DIRECT prefix to the expiring
// dynamic map while keeping the kernel sink and in-process model in lockstep.
func (l *Lifecycle) MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled {
		return nil
	}
	canonical, err := l.backend.ValidateDynamicDirect(prefix)
	if err != nil {
		return err
	}
	if l.sink != nil {
		if err := l.sink.MergeDynamicDirect(canonical, ttl); err != nil {
			return err
		}
	}
	if err := l.backend.MergeDynamicDirect(canonical, ttl); err != nil {
		// ValidateDynamicDirect makes this path unreachable for ordinary model
		// errors. Keep a fail-closed recovery for future capacity/semantic
		// changes: invalidate the generation so a successful kernel write cannot
		// remain active without a matching model entry.
		if l.sink != nil {
			if invalidateErr := l.invalidateGenerationLocked(); invalidateErr != nil {
				return errors.Join(err, invalidateErr)
			}
		}
		return err
	}
	return nil
}

// MergeStaticDirect is retained for source compatibility with older control
// callers. It uses the same dynamic implementation with the historical
// default TTL; new callers should use MergeDynamicDirect.
func (l *Lifecycle) MergeStaticDirect(prefix netip.Prefix) error {
	return l.MergeDynamicDirect(prefix, 5*time.Minute)
}

// RevokeMergedStaticDirect removes one learned/promoted DIRECT prefix from
// both representations. Used when later DNS evidence turns a previously
// stable-direct IP into a conflict (shared-IP generalisation guard).
// Kernel sink first (fail-closed), then the memory model.
func (l *Lifecycle) RevokeMergedStaticDirect(prefix netip.Prefix) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sink != nil {
		if err := l.sink.DeleteMergedStaticDirect(prefix); err != nil {
			return err
		}
	}
	return l.backend.DeleteMergedStaticDirect(prefix)
}

// LearnFlow publishes exact-flow verdict after userspace bare-direct route.
func (l *Lifecycle) LearnFlow(client, dest netip.AddrPort, protocol uint8, bareDirect bool, now time.Time) error {
	if l == nil || l.backend == nil {
		return fmt.Errorf("nil lifecycle")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.options.PolicyOffload.Enabled || !l.options.PolicyOffload.ExactFlowLearning {
		return nil
	}
	if !bareDirect {
		return nil
	}
	request := ebpfv3.FlowPublishRequest{
		Client:           client,
		Destination:      dest,
		Protocol:         protocol,
		Verdict:          ebpfv3.VerdictDirect,
		LeafIsBareDirect: true,
		TTL:              l.flowTTL,
	}
	// Complete all semantic validation before touching the kernel. The memory
	// publication below is then limited to capacity bookkeeping, so a later
	// model-side validation error cannot leave a one-sided kernel verdict.
	if _, err := ebpfv3.BuildFlowPair(request, l.backend.Control.PolicyGeneration, 1); err != nil {
		return err
	}
	if l.sink != nil {
		if err := l.sink.PutDirectFlow(protocol, client, dest, l.flowTTL); err != nil {
			return err
		}
	}
	if err := l.backend.PublishFlow(request, uint64(now.UnixNano())); err != nil {
		return err
	}
	return nil
}

// RevokeFlow clears a learned flow after real failure.
func (l *Lifecycle) RevokeFlow(client, dest netip.AddrPort, protocol uint8) error {
	if l == nil || l.backend == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Validate before touching the kernel. MemoryBackend.RevokeFlow performs
	// the same validation, but doing it up front prevents a future model-side
	// validation change from creating a kernel/model split after a successful
	// kernel delete.
	if _, err := ebpfv3.BuildFlowPair(ebpfv3.FlowPublishRequest{
		Client: client, Destination: dest, Protocol: protocol,
		Verdict: ebpfv3.VerdictProxy,
	}, l.backend.Control.PolicyGeneration, 1); err != nil {
		return err
	}
	if l.sink != nil {
		// The kernel is the authoritative dataplane.  Remove it first so a
		// failed kernel operation cannot be hidden by a model-only revoke.
		// Keeping the model entry on failure preserves diagnostics and lets the
		// caller invalidate the generation as a fail-closed fallback.
		if err := l.sink.DeleteDirectFlow(protocol, client, dest); err != nil {
			return err
		}
	}
	return l.backend.RevokeFlow(client, dest, protocol)
}

// ObserveDNS records DNS/FakeIP evidence with conflict isolation and mirrors
// into the kernel DNS hint map when a sink is bound.
func (l *Lifecycle) ObserveDNS(addr netip.Addr, direct bool, evidence uint8, ttl time.Duration, now time.Time) error {
	if l == nil || l.backend == nil || l.backend.DNS == nil {
		return nil
	}
	if !l.options.PolicyOffload.Enabled {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	family := uint8(ebpfv3.AFInet)
	var raw [16]byte
	a := addr.Unmap()
	if a.Is4() {
		v4 := a.As4()
		copy(raw[:4], v4[:])
	} else if a.Is6() {
		family = ebpfv3.AFInet6
		raw = a.As16()
	} else {
		return nil
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := ebpfv3.DNSIPKey{Family: family, Addr: raw}
	expire := uint64(now.Add(ttl).UnixNano())
	if l.sink != nil {
		if err := l.sink.PublishDNSHint(addr, direct, evidence, 0, ttl); err != nil {
			return err
		}
	}
	l.backend.DNS.Observe(key, direct, evidence, 0, l.backend.Control.PolicyGeneration, expire, uint64(now.UnixNano()))
	return nil
}

// InvalidateGeneration bumps policy generation on memory + kernel sinks so
// stale exact-flow / DNS hints miss until re-learned (interface/route reload).
func (l *Lifecycle) InvalidateGeneration() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.invalidateGenerationLocked()
}

func (l *Lifecycle) invalidateGenerationLocked() error {
	if l == nil || l.backend == nil {
		return nil
	}
	if l.sink != nil {
		// The kernel controls whether stale verdicts are accepted. Commit its
		// generation first; only then advance the in-process model to the exact
		// generation reported by the sink.
		if err := l.sink.InvalidateFlowDirect(); err != nil {
			return err
		}
		generation := l.sink.PolicyGeneration()
		if generation == 0 {
			return fmt.Errorf("kernel invalidation returned zero generation")
		}
		l.backend.Control.PolicyGeneration = generation
		l.backend.Publisher.SyncGeneration(generation)
		l.backend.InvalidateGeneration(generation)
		return nil
	}
	l.backend.Control.PolicyGeneration++
	if l.backend.Control.PolicyGeneration == 0 {
		l.backend.Control.PolicyGeneration = 1
	}
	l.backend.Publisher.SyncGeneration(l.backend.Control.PolicyGeneration)
	l.backend.InvalidateGeneration(l.backend.Control.PolicyGeneration)
	return nil
}

// Close releases control-plane state (kernel detach is a separate step on Linux).
func (l *Lifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backend != nil {
		l.backend.Control.Enabled = 0
	}
	return nil
}
