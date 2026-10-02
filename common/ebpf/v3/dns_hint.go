package v3

// DNSHintTable is the userspace model of v3_dns_ip_hint conflict isolation.
type DNSHintTable struct {
	entries     map[DNSIPKey]DNSIPValue
	nextPruneNs uint64
}

// Keep the userspace model bounded to the same order of magnitude as the
// kernel hint map.  Without a bound, a long-lived gateway would retain every
// public address ever observed even after its kernel entry had expired/LRU
// evicted, defeating the memory budget of the v3 control plane.
const (
	maxDNSHintEntries      = 8192
	dnsHintPruneIntervalNs = 30 * 1_000_000_000
)

func NewDNSHintTable() *DNSHintTable {
	return &DNSHintTable{entries: make(map[DNSIPKey]DNSIPValue)}
}

// Observe records a DNS/FakeIP association. Conflicts force MUST_CONTROL semantics
// (proxy_refs and direct_refs both non-zero → kernel denies DIRECT).
func (t *DNSHintTable) Observe(key DNSIPKey, direct bool, evidence uint8, policyID, generation uint32, expiresNs, nowNs uint64) DNSIPValue {
	if t.entries == nil {
		t.entries = make(map[DNSIPKey]DNSIPValue)
	}
	if nowNs != 0 && (t.nextPruneNs == 0 || nowNs >= t.nextPruneNs) {
		t.pruneExpired(nowNs)
		t.nextPruneNs = nowNs + dnsHintPruneIntervalNs
	}
	cur, ok := t.entries[key]
	// An expired entry must not carry a previous direct/proxy classification
	// into the next DNS epoch.  Otherwise one old proxy observation permanently
	// poisons a reused CDN address until a full policy-generation bump.
	if !ok || cur.Generation != generation || (cur.ExpiresNs != 0 && nowNs != 0 && cur.ExpiresNs <= nowNs) {
		if !ok && len(t.entries) >= maxDNSHintEntries {
			t.evictOldest()
		}
		cur = DNSIPValue{
			PolicyID:   policyID,
			Generation: generation,
			Evidence:   evidence,
		}
	}
	if direct {
		if cur.DirectRefs != ^uint32(0) {
			cur.DirectRefs++
		}
	} else {
		if cur.ProxyRefs != ^uint32(0) {
			cur.ProxyRefs++
		}
	}
	// Evidence can only strengthen within the same generation when no conflict.
	if evidenceRank(evidence) > evidenceRank(cur.Evidence) && cur.ProxyRefs == 0 {
		cur.Evidence = evidence
	}
	if cur.ProxyRefs > 0 && cur.DirectRefs > 0 {
		// Conflict: keep counts, force weak so kernel path never DIRECT.
		cur.Evidence = DNSEvidenceWeak
	}
	cur.ExpiresNs = expiresNs
	cur.LastSeenNs = nowNs
	cur.PolicyID = policyID
	cur.Generation = generation
	t.entries[key] = cur
	return cur
}

func (t *DNSHintTable) pruneExpired(nowNs uint64) {
	for key, value := range t.entries {
		if value.ExpiresNs != 0 && value.ExpiresNs <= nowNs {
			delete(t.entries, key)
		}
	}
}

func (t *DNSHintTable) evictOldest() {
	var oldestKey DNSIPKey
	var oldest uint64
	first := true
	for key, value := range t.entries {
		if first || value.LastSeenNs < oldest {
			oldestKey, oldest = key, value.LastSeenNs
			first = false
		}
	}
	if !first {
		delete(t.entries, oldestKey)
	}
}

func evidenceRank(e uint8) int {
	switch e {
	case DNSEvidenceFakeIP:
		return 3
	case DNSEvidenceStrong:
		return 2
	case DNSEvidenceWeak:
		return 1
	default:
		return 0
	}
}

// Lookup returns a copy if present.
func (t *DNSHintTable) Lookup(key DNSIPKey) (DNSIPValue, bool) {
	if t == nil || t.entries == nil {
		return DNSIPValue{}, false
	}
	v, ok := t.entries[key]
	return v, ok
}

// InvalidateGeneration drops entries not matching generation (optional eager GC).
func (t *DNSHintTable) InvalidateGeneration(generation uint32) {
	if t == nil || t.entries == nil {
		return
	}
	for k, v := range t.entries {
		if v.Generation != generation {
			delete(t.entries, k)
		}
	}
	t.nextPruneNs = 0
}
