package adaptive

import (
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type selectionMemoryEntry struct {
	reason      string
	selectionAt time.Time
	failure     string
	serviceID   string
	path        string
	failureAt   time.Time
	at          time.Time
}

type selectionMemoryKey struct {
	handle    NodeHandle
	serviceID string
	path      string
}

const selectionMemoryLimit = 4096

func (p *AdaptivePool) rememberPolicySelectionWithReason(service ServiceContext, candidate Candidate, reason DecisionReason) {
	if p == nil {
		return
	}
	key := ""
	policy := p.policySnapshot()
	if policy != nil {
		key = policy.stickyKey(service)
	}
	now := time.Now()
	if policy != nil {
		policy.RememberSelection(key, candidate.Handle, now)
	}
	p.recordSelectionMemory(candidate.Handle, string(reason), "", service.ID, serviceHealthTransport(service), now)
}

func (p *AdaptivePool) recordSelectionMemory(handle NodeHandle, reason, failure, serviceID, path string, at time.Time) {
	if p == nil || handle.NodeID == (NodeID{}) {
		return
	}
	p.selectionMemoryAccess.Lock()
	if p.selectionMemory == nil {
		p.selectionMemory = make(map[selectionMemoryKey]selectionMemoryEntry)
	}
	key := selectionMemoryKey{handle: handle, serviceID: serviceID, path: path}
	entry := p.selectionMemory[key]
	if failure != "" {
		entry.failure = failure
		entry.serviceID = serviceID
		entry.path = path
		entry.failureAt = at
	} else if reason != "" {
		entry.reason = reason
		entry.selectionAt = at
	}
	entry.at = at
	p.selectionMemory[key] = entry
	if len(p.selectionMemory) > selectionMemoryLimit {
		var oldest selectionMemoryKey
		var oldestAt time.Time
		first := true
		for id, entry := range p.selectionMemory {
			if first || entry.at.Before(oldestAt) {
				oldest = id
				oldestAt = entry.at
				first = false
			}
		}
		delete(p.selectionMemory, oldest)
	}
	p.selectionMemoryAccess.Unlock()
}

func (p *AdaptivePool) recordFailureMemory(candidate Candidate, failure FailureClass, serviceID, path string) {
	if p == nil || candidate.ID == (NodeID{}) {
		return
	}
	p.recordSelectionMemory(candidate.Handle, "failure", string(failure), serviceID, path, time.Now())
}

type selectionMemoryView struct {
	latestSelection selectionMemoryEntry
	latestFailure   selectionMemoryEntry
	services        []adapter.AdaptiveServiceMemory
}

func (p *AdaptivePool) selectionMemoryFor(nodeID NodeID) selectionMemoryEntry {
	view := p.selectionMemoryForHandle(NodeHandle{NodeID: nodeID})
	entry := view.latestSelection
	if view.latestFailure.failureAt.After(entry.failureAt) {
		entry.failure = view.latestFailure.failure
		entry.serviceID = view.latestFailure.serviceID
		entry.path = view.latestFailure.path
		entry.failureAt = view.latestFailure.failureAt
	}
	if view.latestFailure.at.After(entry.at) {
		entry.at = view.latestFailure.at
	}
	return entry
}

func (p *AdaptivePool) selectionMemoryForHandle(handle NodeHandle) selectionMemoryView {
	view := selectionMemoryView{}
	if p == nil {
		return view
	}
	p.selectionMemoryAccess.Lock()
	defer p.selectionMemoryAccess.Unlock()
	byService := make(map[string]adapter.AdaptiveServiceMemory)
	for key, candidate := range p.selectionMemory {
		if key.handle != handle && key.handle.NodeID != handle.NodeID {
			continue
		}
		if candidate.selectionAt.After(view.latestSelection.selectionAt) {
			view.latestSelection = candidate
			view.latestSelection.serviceID = firstNonEmpty(candidate.serviceID, key.serviceID)
		}
		if candidate.failureAt.After(view.latestFailure.failureAt) {
			view.latestFailure = candidate
			view.latestFailure.serviceID = firstNonEmpty(candidate.serviceID, key.serviceID)
			view.latestFailure.path = firstNonEmpty(candidate.path, key.path)
		}
		serviceID := firstNonEmpty(candidate.serviceID, key.serviceID)
		if serviceID == "" {
			serviceID = "unknown"
		}
		item := byService[serviceID]
		item.ServiceID = serviceID
		if candidate.selectionAt.After(item.SelectedAt) {
			item.SelectionReason = candidate.reason
			item.SelectedAt = candidate.selectionAt
			if key.path != "" {
				item.Path = key.path
			}
		}
		if candidate.failureAt.After(item.FailedAt) {
			item.Failure = candidate.failure
			item.FailedAt = candidate.failureAt
			item.Path = firstNonEmpty(candidate.path, key.path, item.Path)
		}
		byService[serviceID] = item
	}
	if len(byService) == 0 {
		return view
	}
	view.services = make([]adapter.AdaptiveServiceMemory, 0, len(byService))
	for _, item := range byService {
		view.services = append(view.services, item)
	}
	sort.Slice(view.services, func(i, j int) bool {
		left, right := view.services[i], view.services[j]
		leftAt, rightAt := left.SelectedAt, right.SelectedAt
		if left.FailedAt.After(leftAt) {
			leftAt = left.FailedAt
		}
		if right.FailedAt.After(rightAt) {
			rightAt = right.FailedAt
		}
		if !leftAt.Equal(rightAt) {
			return leftAt.After(rightAt)
		}
		return left.ServiceID < right.ServiceID
	})
	return view
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (p *AdaptivePool) clearSelectionMemory() {
	if p == nil {
		return
	}
	p.selectionMemoryAccess.Lock()
	p.selectionMemory = make(map[selectionMemoryKey]selectionMemoryEntry)
	p.selectionMemoryAccess.Unlock()
}

func adapterCapabilities(profile NodeCapabilityProfile) *adapter.AdaptiveNodeCapabilities {
	known := profile.TCP4.Known || profile.TCP6.Known || profile.DNSUDPv4.Known || profile.DNSUDPv6.Known ||
		profile.DataUDPv4.Known || profile.DataUDPv6.Known || profile.Endpoint.Known || profile.ThroughputBPS > 0
	return &adapter.AdaptiveNodeCapabilities{
		TCP4: adapterPathCapability(profile.TCP4), TCP6: adapterPathCapability(profile.TCP6),
		DNSUDPv4: adapterPathCapability(profile.DNSUDPv4), DNSUDPv6: adapterPathCapability(profile.DNSUDPv6),
		DataUDPv4: adapterPathCapability(profile.DataUDPv4), DataUDPv6: adapterPathCapability(profile.DataUDPv6),
		Endpoint: adapterPathCapability(profile.Endpoint), ThroughputOK: profile.ThroughputOK,
		ThroughputBPS: profile.ThroughputBPS, Known: known,
	}
}

func adapterPathCapability(path PathCapability) adapter.AdaptivePathCapability {
	state := path.State
	if state == "" {
		state = PathStateUnknown
		if path.Known {
			if path.Available {
				state = PathStateHealthy
			} else {
				state = PathStateUnreachable
			}
		}
	}
	return adapter.AdaptivePathCapability{Known: path.Known, Available: path.Available, State: state}
}

func durationMillis32(value time.Duration) uint32 {
	if value <= 0 {
		return 0
	}
	milliseconds := value.Milliseconds()
	if milliseconds >= int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(milliseconds)
}
