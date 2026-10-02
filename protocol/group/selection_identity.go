package group

import "github.com/sagernet/sing-box/adapter"

func snapshotOutbounds(snapshot *groupOutboundSnapshot) []adapter.Outbound {
	if snapshot == nil {
		return nil
	}
	result := make([]adapter.Outbound, 0, len(snapshot.tags))
	for _, tag := range snapshot.tags {
		if outbound := snapshot.outbounds[tag]; outbound != nil {
			result = append(result, outbound)
		}
	}
	return result
}

// selectedRecordForOutbound projects a runtime member into the small,
// credential-free identity record used by persistent group selection. Tags
// remain only as a compatibility/display fallback.
func selectedRecordForOutbound(outbound adapter.Outbound) adapter.SelectedRecord {
	if outbound == nil {
		return adapter.SelectedRecord{Version: 1}
	}
	record := adapter.SelectedRecord{Version: 1, DisplayTag: outbound.Tag()}
	if identified, ok := outbound.(adapter.OutboundWithEndpointIdentity); ok {
		record.EndpointIdentity = identified.EndpointIdentity()
	}
	if identified, ok := outbound.(adapter.OutboundWithDialIdentity); ok {
		record.DialIdentity = identified.DialIdentity()
	}
	return record
}

func outboundMatchesSelectionRecord(outbound adapter.Outbound, record adapter.SelectedRecord, identityKind byte) bool {
	if outbound == nil {
		return false
	}
	switch identityKind {
	case 'd':
		identified, ok := outbound.(adapter.OutboundWithDialIdentity)
		return ok && record.DialIdentity != "" && identified.DialIdentity() == record.DialIdentity
	case 'e':
		identified, ok := outbound.(adapter.OutboundWithEndpointIdentity)
		return ok && record.EndpointIdentity != "" && identified.EndpointIdentity() == record.EndpointIdentity
	default:
		return record.DisplayTag != "" && outbound.Tag() == record.DisplayTag
	}
}

// resolveSelectionRecord follows the persistence contract used by selector and
// manual-selection state: authenticated dial identity first, credential-free
// endpoint identity second, and the legacy display tag only as a final
// compatibility fallback. Callers that require credential-sensitive affinity
// must use resolveStickySessionRecord instead.
func resolveSelectionRecord(outbounds []adapter.Outbound, record adapter.SelectedRecord) adapter.Outbound {
	if record.DialIdentity != "" {
		for _, outbound := range outbounds {
			if outboundMatchesSelectionRecord(outbound, record, 'd') {
				return outbound
			}
		}
	}
	if record.EndpointIdentity != "" {
		var endpointMatch adapter.Outbound
		for _, outbound := range outbounds {
			if !outboundMatchesSelectionRecord(outbound, record, 'e') {
				continue
			}
			// Prefer the old display alias when several credentials share one
			// path. Otherwise snapshot order remains deterministic.
			if outbound.Tag() == record.DisplayTag {
				return outbound
			}
			if endpointMatch == nil {
				endpointMatch = outbound
			}
		}
		if endpointMatch != nil {
			return endpointMatch
		}
	}
	for _, outbound := range outbounds {
		if outboundMatchesSelectionRecord(outbound, record, 't') {
			return outbound
		}
	}
	return nil
}

// resolveStickySessionRecord resolves a runtime sticky-session record without
// silently changing authenticated members. A DialIdentity represents the
// complete data-plane credential (for example a VLESS UUID), so once it is
// present an exact match is required. Falling back to EndpointIdentity here
// would move an existing session to another credential that merely shares the
// same server/transport path. Older records without a DialIdentity are
// retained for static/legacy members and may use the weaker path/tag match.
func resolveStickySessionRecord(outbounds []adapter.Outbound, record adapter.SelectedRecord) adapter.Outbound {
	if record.DialIdentity != "" {
		for _, outbound := range outbounds {
			if outboundMatchesSelectionRecord(outbound, record, 'd') {
				return outbound
			}
		}
		return nil
	}
	return resolveSelectionRecord(outbounds, record)
}

func storeSelectedRecord(cacheFile adapter.CacheFile, group string, outbound adapter.Outbound) error {
	if cacheFile == nil {
		return nil
	}
	if store, ok := cacheFile.(adapter.SelectedRecordStore); ok {
		return store.StoreSelectedRecord(group, selectedRecordForOutbound(outbound))
	}
	if outbound == nil {
		return cacheFile.StoreSelected(group, "")
	}
	return cacheFile.StoreSelected(group, outbound.Tag())
}

func storeSelectedRecordValue(cacheFile adapter.CacheFile, group string, record adapter.SelectedRecord) error {
	if cacheFile == nil {
		return nil
	}
	if store, ok := cacheFile.(adapter.SelectedRecordStore); ok {
		return store.StoreSelectedRecord(group, record)
	}
	return cacheFile.StoreSelected(group, record.DisplayTag)
}

func clearSelectedRecord(cacheFile adapter.CacheFile, group string) error {
	if cacheFile == nil {
		return nil
	}
	if store, ok := cacheFile.(adapter.SelectedRecordStore); ok {
		return store.StoreSelectedRecord(group, adapter.SelectedRecord{Version: 1})
	}
	return cacheFile.StoreSelected(group, "")
}
