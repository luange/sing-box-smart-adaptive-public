package v3

import (
	"fmt"
	"net/netip"
	"time"
)

// FlowPublishRequest is produced after userspace route reaches a stable leaf.
type FlowPublishRequest struct {
	Client      netip.AddrPort
	Destination netip.AddrPort
	Protocol    uint8
	Verdict     Verdict
	// LeafIsBareDirect must be true for DIRECT — selector/smart never.
	LeafIsBareDirect bool
	PolicyID         uint32
	TTL              time.Duration
	TimeoutClass     string // "dns" | "quic" | "data" — for UDP TTL defaults
}

// FlowPair is forward + reverse keys for kernel write.
type FlowPair struct {
	Forward FlowKey
	Reverse FlowKey
	Value   FlowValue
}

// DefaultFlowTTL picks TCP/UDP TTL per design §9.
func DefaultFlowTTL(protocol uint8, class string, configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	if protocol == ProtocolTCP {
		return 10 * time.Minute
	}
	switch class {
	case "dns":
		return 30 * time.Second
	case "quic":
		return 2 * time.Minute
	default:
		return 3 * time.Minute
	}
}

// BuildFlowPair validates and builds bidirectional flow entries.
func BuildFlowPair(req FlowPublishRequest, generation uint32, expireNs uint64) (FlowPair, error) {
	if !req.Client.IsValid() || !req.Destination.IsValid() {
		return FlowPair{}, fmt.Errorf("invalid addresses")
	}
	if req.Protocol != ProtocolTCP && req.Protocol != ProtocolUDP {
		return FlowPair{}, fmt.Errorf("unsupported protocol")
	}
	if req.Verdict == VerdictDirect && !req.LeafIsBareDirect {
		return FlowPair{}, fmt.Errorf("DIRECT requires bare direct leaf")
	}
	if req.Destination.Port() == 53 && req.Verdict == VerdictDirect {
		return FlowPair{}, fmt.Errorf("port 53 must not learn DIRECT flow")
	}

	family, saddr, err := addrBytes(req.Client.Addr())
	if err != nil {
		return FlowPair{}, err
	}
	dfamily, daddr, err := addrBytes(req.Destination.Addr())
	if err != nil {
		return FlowPair{}, err
	}
	if family != dfamily {
		return FlowPair{}, fmt.Errorf("address family mismatch")
	}

	conf := ConfidenceStrong
	src := SourceExactFlow
	reason := ReasonFlowDirect
	switch req.Verdict {
	case VerdictDirect:
		reason = ReasonFlowDirect
	case VerdictProxy:
		reason = ReasonFlowProxy
		conf = ConfidenceStrong
	case VerdictBlock:
		reason = ReasonFlowBlock
	case VerdictMustControl:
		reason = ReasonMustControl
		conf = ConfidenceNone
	default:
		return FlowPair{}, fmt.Errorf("invalid verdict")
	}

	value := FlowValue{
		Verdict:    uint8(req.Verdict),
		Source:     uint8(src),
		Confidence: conf,
		ReasonCode: uint16(reason),
		PolicyID:   req.PolicyID,
		Generation: generation,
		ExpiresNs:  expireNs,
	}
	fwd := FlowKey{
		Family:    family,
		Protocol:  req.Protocol,
		Direction: 0,
		SPort:     req.Client.Port(),
		DPort:     req.Destination.Port(),
		SAddr:     saddr,
		DAddr:     daddr,
	}
	// Reverse uses direction=0 with swapped 5-tuple so TC (direction=0 only) hits.
	rev := FlowKey{
		Family:    family,
		Protocol:  req.Protocol,
		Direction: 0,
		SPort:     req.Destination.Port(),
		DPort:     req.Client.Port(),
		SAddr:     daddr,
		DAddr:     saddr,
	}
	return FlowPair{Forward: fwd, Reverse: rev, Value: value}, nil
}

func addrBytes(addr netip.Addr) (family uint8, out [16]byte, err error) {
	addr = addr.Unmap()
	if addr.Is4() {
		a := addr.As4()
		copy(out[:4], a[:])
		return AFInet, out, nil
	}
	if addr.Is6() {
		return AFInet6, addr.As16(), nil
	}
	return 0, out, fmt.Errorf("invalid addr")
}

// MemoryBackend is a test double for kernel maps (no cgo).
type MemoryBackend struct {
	Control     Control
	Policy4     [2]map[LPM4Key]PolicyValue
	Policy6     [2]map[LPM6Key]PolicyValue
	Flows       map[FlowKey]FlowValue
	DNS         *DNSHintTable
	MACPolicies map[MACKey]MACPolicyValue
	// Dynamic DIRECT rows mirror the production v4/v6 map split. Keeping two
	// ledgers is important: each kernel LPM map has its own capacity budget.
	dynamicDirects4 map[netip.Prefix]time.Time
	dynamicDirects6 map[netip.Prefix]time.Time
	Publisher       *BankPublisher
	Stats           [StatsCount]uint64
	flowLimit       int
	nextFlowPruneNs uint64
}

// PreparedStatic reserves the inactive policy bank and contains a fully
// validated snapshot ready for an infallible model commit.  Lifecycle uses
// this reservation to validate and stage the model before touching the live
// kernel, so a successful kernel publish cannot be followed by a model-side
// compile/capacity failure.
type PreparedStatic struct {
	backend  *MemoryBackend
	inactive uint32
	policy4  map[LPM4Key]PolicyValue
	policy6  map[LPM6Key]PolicyValue
}

func NewMemoryBackend() *MemoryBackend {
	b := &MemoryBackend{
		Publisher:   NewBankPublisher(),
		Flows:       make(map[FlowKey]FlowValue),
		DNS:         NewDNSHintTable(),
		MACPolicies: make(map[MACKey]MACPolicyValue),
		flowLimit:   maxMemoryFlowEntries,
	}
	b.Policy4[0] = make(map[LPM4Key]PolicyValue)
	b.Policy4[1] = make(map[LPM4Key]PolicyValue)
	b.Policy6[0] = make(map[LPM6Key]PolicyValue)
	b.Policy6[1] = make(map[LPM6Key]PolicyValue)
	b.dynamicDirects4 = make(map[netip.Prefix]time.Time)
	b.dynamicDirects6 = make(map[netip.Prefix]time.Time)
	bank, gen := b.Publisher.Snapshot()
	b.Control = Control{
		ABIVersion:       ABIVersion,
		Enabled:          1,
		Flags:            FlagIPv4 | FlagIPv6 | FlagTCP | FlagUDP | FlagSocketAssign | FlagStaticPolicy | FlagExactFlow | FlagDNSHint | FlagFakeIP | FlagFailureProxy,
		ActiveBank:       bank,
		PolicyGeneration: gen,
	}
	return b
}

// PrepareStatic validates and stages an inactive-bank snapshot. The compile
// reservation remains held until CommitPreparedStatic or AbortPreparedStatic.
func (b *MemoryBackend) PrepareStatic(policies []CompiledPolicy) (*PreparedStatic, error) {
	if b == nil || b.Publisher == nil {
		return nil, fmt.Errorf("nil memory backend")
	}
	inactive, ok := b.Publisher.BeginCompile()
	if !ok {
		return nil, fmt.Errorf("compile already in progress")
	}
	// Build off to the side, then install the complete bank in one assignment;
	// a malformed prefix must not leave a partially refreshed inactive snapshot.
	policy4 := make(map[LPM4Key]PolicyValue)
	policy6 := make(map[LPM6Key]PolicyValue)
	// generation for entries is commit generation (current+1)
	nextGen := b.Publisher.Generation() + 1
	if nextGen == 0 {
		nextGen = 1
	}
	for _, p := range policies {
		canonical, canonicalErr := CanonicalPrefix(p.Prefix)
		if canonicalErr != nil {
			b.Publisher.AbortCompile()
			return nil, canonicalErr
		}
		p.Prefix = canonical
		p.Value.Generation = nextGen
		addr := p.Prefix.Addr()
		if addr.Is4() {
			key, err := PrefixToLPM4(p.Prefix)
			if err != nil {
				b.Publisher.AbortCompile()
				return nil, err
			}
			policy4[key] = p.Value
			continue
		}
		key, err := PrefixToLPM6(p.Prefix)
		if err != nil {
			b.Publisher.AbortCompile()
			return nil, err
		}
		policy6[key] = p.Value
	}
	if len(policy4) > DefaultPolicyLPM || len(policy6) > DefaultPolicyLPM {
		b.Publisher.AbortCompile()
		return nil, fmt.Errorf("static policy exceeds eBPF LPM map capacity")
	}
	return &PreparedStatic{backend: b, inactive: inactive, policy4: policy4, policy6: policy6}, nil
}

// AbortPreparedStatic releases a staged snapshot without changing the model.
// It is required when the corresponding kernel publication fails.
func (b *MemoryBackend) AbortPreparedStatic(prepared *PreparedStatic) {
	if b == nil || prepared == nil || prepared.backend != b {
		return
	}
	b.Publisher.AbortCompile()
	prepared.backend = nil
}

// CommitPreparedStatic installs a previously validated snapshot. All
// fallible work happened in PrepareStatic; this method only performs map
// assignments and the publisher's atomic bank flip.
func (b *MemoryBackend) CommitPreparedStatic(prepared *PreparedStatic) {
	if b == nil || prepared == nil || prepared.backend != b {
		return
	}
	b.Policy4[prepared.inactive] = prepared.policy4
	b.Policy6[prepared.inactive] = prepared.policy6
	gen, bank := b.Publisher.Commit()
	b.Control.ActiveBank = bank
	b.Control.PolicyGeneration = gen
	// A generation commit invalidates all learned dynamic rows. They are
	// represented separately from the static snapshot in the memory model too.
	clear(b.dynamicDirects4)
	clear(b.dynamicDirects6)
	b.invalidateGenerationMaps(gen)
	b.Stats[25] = uint64(gen) // RELOAD_GENERATION index if aligned — best-effort
	prepared.backend = nil
}

// PublishStatic performs inactive-bank fill + atomic commit.
func (b *MemoryBackend) PublishStatic(policies []CompiledPolicy) error {
	prepared, err := b.PrepareStatic(policies)
	if err != nil {
		return err
	}
	b.CommitPreparedStatic(prepared)
	return nil
}

// MergeDynamicDirect adds one learned DIRECT prefix to the separate dynamic
// map without changing policy_generation. The TTL is checked in the same
// monotonic time domain as the kernel model.
func (b *MemoryBackend) MergeDynamicDirect(prefix netip.Prefix, ttl time.Duration) error {
	if b == nil || b.Publisher == nil {
		return fmt.Errorf("nil memory backend")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	var err error
	prefix, err = CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	entries, err := b.dynamicEntriesForPrefix(prefix)
	if err != nil {
		return err
	}
	expires := time.Now().Add(ttl)
	now := time.Now()
	for learnedPrefix, learnedExpiry := range entries {
		if !learnedExpiry.After(now) {
			delete(entries, learnedPrefix)
		}
	}
	if existing, ok := entries[prefix]; ok && existing.After(now) {
		entries[prefix] = expires
		return nil
	}
	if len(entries) >= DefaultDynamicDirect {
		return fmt.Errorf("dynamic direct policy exceeds eBPF map capacity")
	}
	entries[prefix] = expires
	return nil
}

// ValidateDynamicDirect performs all fallible model-side checks without
// mutating the model. Lifecycle uses it before publishing to the kernel so a
// capacity or family error cannot follow a successful kernel write.
func (b *MemoryBackend) ValidateDynamicDirect(prefix netip.Prefix) (netip.Prefix, error) {
	if b == nil || b.Publisher == nil {
		return netip.Prefix{}, fmt.Errorf("nil memory backend")
	}
	canonical, err := CanonicalPrefix(prefix)
	if err != nil {
		return netip.Prefix{}, err
	}
	entries, err := b.dynamicEntriesForPrefix(canonical)
	if err != nil {
		return netip.Prefix{}, err
	}
	now := time.Now()
	if existing, ok := entries[canonical]; ok && existing.After(now) {
		return canonical, nil
	}
	active := 0
	for _, expiry := range entries {
		if expiry.After(now) {
			active++
		}
	}
	if active >= DefaultDynamicDirect {
		return netip.Prefix{}, fmt.Errorf("dynamic direct policy exceeds eBPF map capacity")
	}
	return canonical, nil
}

func (b *MemoryBackend) dynamicEntriesForPrefix(prefix netip.Prefix) (map[netip.Prefix]time.Time, error) {
	if b == nil {
		return nil, fmt.Errorf("nil memory backend")
	}
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		if b.dynamicDirects4 == nil {
			b.dynamicDirects4 = make(map[netip.Prefix]time.Time)
		}
		return b.dynamicDirects4, nil
	}
	if addr.Is6() {
		if b.dynamicDirects6 == nil {
			b.dynamicDirects6 = make(map[netip.Prefix]time.Time)
		}
		return b.dynamicDirects6, nil
	}
	return nil, fmt.Errorf("invalid dynamic direct prefix family")
}

// MergeStaticDirect is kept as a source-compatible wrapper for older tests and
// integrations. New code should pass the RR TTL through MergeDynamicDirect.
func (b *MemoryBackend) MergeStaticDirect(prefix netip.Prefix) error {
	return b.MergeDynamicDirect(prefix, 5*time.Minute)
}

// PublishFlow writes bidirectional flow verdicts.
func (b *MemoryBackend) PublishFlow(req FlowPublishRequest, nowNs uint64) error {
	ttl := DefaultFlowTTL(req.Protocol, req.TimeoutClass, req.TTL)
	expire := nowNs
	if ttlNs := uint64(ttl); ttlNs > ^uint64(0)-nowNs {
		expire = ^uint64(0)
	} else {
		expire += ttlNs
	}
	pair, err := BuildFlowPair(req, b.Control.PolicyGeneration, expire)
	if err != nil {
		return err
	}
	if b.Flows == nil {
		b.Flows = make(map[FlowKey]FlowValue)
	}
	if nowNs != 0 && (b.nextFlowPruneNs == 0 || nowNs >= b.nextFlowPruneNs) {
		b.pruneExpiredFlows(nowNs)
		b.nextFlowPruneNs = nowNs + flowPruneIntervalNs
	}
	limit := b.flowLimit
	if limit <= 0 {
		limit = maxMemoryFlowEntries
	}
	missing := 0
	if _, ok := b.Flows[pair.Forward]; !ok {
		missing++
	}
	if _, ok := b.Flows[pair.Reverse]; !ok {
		missing++
	}
	for len(b.Flows)+missing > limit {
		if !b.evictOldestFlowPair() {
			break
		}
	}
	b.Flows[pair.Forward] = pair.Value
	b.Flows[pair.Reverse] = pair.Value
	return nil
}

const (
	maxMemoryFlowEntries = DefaultFlowEntries
	flowPruneIntervalNs  = 30 * 1_000_000_000
)

func (b *MemoryBackend) pruneExpiredFlows(nowNs uint64) {
	for key, value := range b.Flows {
		if value.ExpiresNs != 0 && value.ExpiresNs <= nowNs {
			delete(b.Flows, key)
		}
	}
}

func (b *MemoryBackend) evictOldestFlowPair() bool {
	var oldestKey FlowKey
	var oldest uint64
	first := true
	for key, value := range b.Flows {
		if first || value.ExpiresNs < oldest {
			oldestKey, oldest = key, value.ExpiresNs
			first = false
		}
	}
	if first {
		return false
	}
	delete(b.Flows, oldestKey)
	reverse := oldestKey
	reverse.SPort, reverse.DPort = oldestKey.DPort, oldestKey.SPort
	reverse.SAddr, reverse.DAddr = oldestKey.DAddr, oldestKey.SAddr
	delete(b.Flows, reverse)
	return true
}

func (b *MemoryBackend) invalidateGenerationMaps(generation uint32) {
	if b == nil || generation == 0 {
		return
	}
	for key, value := range b.Flows {
		if value.Generation != generation {
			delete(b.Flows, key)
		}
	}
	if b.DNS != nil {
		b.DNS.InvalidateGeneration(generation)
	}
	// The kernel tags dynamic DIRECT and source-MAC rows with the same global
	// policy generation.  Retire their model copies as well; otherwise a
	// generation bump would make the model report rows that TC must ignore.
	clear(b.dynamicDirects4)
	clear(b.dynamicDirects6)
	clear(b.MACPolicies)
	b.nextFlowPruneNs = 0
}

// InvalidateGeneration drops all generation-scoped learned evidence from the
// older policy epoch. The kernel maps use generation checks for correctness;
// the memory model removes the corresponding rows so diagnostics and tests do
// not report entries that TC will ignore.
func (b *MemoryBackend) InvalidateGeneration(generation uint32) {
	if b == nil {
		return
	}
	b.invalidateGenerationMaps(generation)
}

// RevokeFlow removes both directions after a real proxy/route failure.
func (b *MemoryBackend) RevokeFlow(client, dest netip.AddrPort, protocol uint8) error {
	pair, err := BuildFlowPair(FlowPublishRequest{
		Client:           client,
		Destination:      dest,
		Protocol:         protocol,
		Verdict:          VerdictProxy,
		LeafIsBareDirect: false,
	}, b.Control.PolicyGeneration, 1)
	if err != nil {
		return err
	}
	delete(b.Flows, pair.Forward)
	delete(b.Flows, pair.Reverse)
	return nil
}

// LookupStatic finds destination /32 or /128 style exact match in active bank
// (tests use host routes; production LPM is longest-prefix in kernel).
func (b *MemoryBackend) LookupStatic(dest netip.Addr, protocol uint8, dport uint16) *PolicyValue {
	bank := b.Control.ActiveBank
	addr := dest.Unmap()
	if addr.Is4() {
		a := addr.As4()
		key := LPM4Key{PrefixLen: 32, Addr: a}
		if v, ok := b.Policy4[bank][key]; ok && v.Generation == b.Control.PolicyGeneration {
			if v.MatchProtocol != 0 && uint8(v.MatchProtocol) != protocol {
				return nil
			}
			if v.MatchDPortMin != 0 || v.MatchDPortMax != 0 {
				if dport < v.MatchDPortMin || dport > v.MatchDPortMax {
					return nil
				}
			}
			return &v
		}
		return nil
	}
	key := LPM6Key{PrefixLen: 128, Addr: addr.As16()}
	if v, ok := b.Policy6[bank][key]; ok && v.Generation == b.Control.PolicyGeneration {
		if v.MatchProtocol != 0 && uint8(v.MatchProtocol) != protocol {
			return nil
		}
		if v.MatchDPortMin != 0 || v.MatchDPortMax != 0 {
			if dport < v.MatchDPortMin || dport > v.MatchDPortMax {
				return nil
			}
		}
		return &v
	}
	return nil
}

// LookupDynamicDirect mirrors the separate expiring dynamic LPM maps used by
// the kernel. It is kept distinct from LookupStatic so tests exercise the same
// precedence and lifetime semantics as tc.bpf.c.
func (b *MemoryBackend) LookupDynamicDirect(dest netip.Addr, protocol uint8, dport uint16) *PolicyValue {
	if b == nil || !dest.IsValid() {
		return nil
	}
	dest = dest.Unmap()
	now := time.Now()
	var (
		bestPrefix netip.Prefix
		bestExpiry time.Time
	)
	entries := b.dynamicDirects4
	if dest.Is6() {
		entries = b.dynamicDirects6
	}
	for prefix, expiry := range entries {
		if !expiry.After(now) {
			delete(entries, prefix)
			continue
		}
		if !prefix.Contains(dest) || (bestPrefix.IsValid() && prefix.Bits() <= bestPrefix.Bits()) {
			continue
		}
		bestPrefix, bestExpiry = prefix, expiry
	}
	if !bestPrefix.IsValid() || !bestExpiry.After(now) {
		return nil
	}
	return &PolicyValue{
		Verdict:    uint8(VerdictDirect),
		Source:     uint8(SourceStatic),
		Confidence: ConfidenceStrong,
		ReasonCode: uint16(ReasonDNSHintDirect),
		Generation: b.Control.PolicyGeneration,
	}
}

// LookupFlow returns active generation flow.
func (b *MemoryBackend) LookupFlow(key FlowKey) *FlowValue {
	v, ok := b.Flows[key]
	if !ok || v.Generation != b.Control.PolicyGeneration {
		return nil
	}
	return &v
}

// PublishMACPolicies replaces the complete MAC-source snapshot in the memory
// model. Rows are tagged with the current policy generation so a generation
// bump (PublishStatic / InvalidateFlowDirect) retires stale identities.
func (b *MemoryBackend) PublishMACPolicies(entries []MACPolicyEntry) error {
	if b == nil {
		return fmt.Errorf("nil memory backend")
	}
	capHint := len(entries)
	if capHint > MaxSourcePolicies+1 {
		capHint = MaxSourcePolicies + 1
	}
	snapshot := make(map[MACKey]MACPolicyValue, capHint)
	for _, entry := range entries {
		var zero MACKey
		if entry.Key == zero {
			continue
		}
		entry.Value.Generation = b.Control.PolicyGeneration
		if entry.Value.Generation == 0 {
			entry.Value.Generation = 1
		}
		if entry.Value.Source == 0 {
			entry.Value.Source = uint8(SourceStatic)
		}
		snapshot[entry.Key] = entry.Value
	}
	if len(snapshot) > MaxSourcePolicies {
		return fmt.Errorf("mac source policy exceeds map capacity")
	}
	b.MACPolicies = snapshot
	return nil
}

// DeleteMergedStaticDirect is a compatibility façade for removing one learned
// dynamic DIRECT row. Snapshot-published rules are never touched.
func (b *MemoryBackend) DeleteMergedStaticDirect(prefix netip.Prefix) error {
	if b == nil || b.Publisher == nil {
		return fmt.Errorf("nil memory backend")
	}
	var err error
	prefix, err = CanonicalPrefix(prefix)
	if err != nil {
		return err
	}
	entries := b.dynamicDirects4
	if prefix.Addr().Is6() {
		entries = b.dynamicDirects6
	}
	if _, revocable := entries[prefix]; !revocable {
		return nil
	}
	delete(entries, prefix)
	return nil
}
