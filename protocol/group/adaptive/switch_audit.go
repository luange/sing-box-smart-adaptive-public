package adaptive

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const switchAuditLimit = 64
const pendingSwitchLimit = 1024

type pendingSwitchFailure struct {
	serviceID string
	node      NodeHandle
	tag       string
	failure   FailureClass
	source    string
	at        time.Time
}

type SwitchAuditStore struct {
	access  sync.Mutex
	entries []adapter.AdaptiveSwitchAudit
	pending map[SessionKey]pendingSwitchFailure
	total   uint64
}

func NewSwitchAuditStore() *SwitchAuditStore {
	return &SwitchAuditStore{pending: make(map[SessionKey]pendingSwitchFailure)}
}

func (s *SwitchAuditStore) RecordFailure(session SessionKey, serviceID string, candidate Candidate, failure FailureClass, source string, at time.Time) {
	if s == nil || session == (SessionKey{}) || candidate.ID == (NodeID{}) || serviceID == "" {
		return
	}
	s.access.Lock()
	if len(s.pending) >= pendingSwitchLimit {
		for key, item := range s.pending {
			if at.Sub(item.at) > 10*time.Minute {
				delete(s.pending, key)
			}
		}
	}
	if len(s.pending) < pendingSwitchLimit {
		s.pending[session] = pendingSwitchFailure{serviceID: serviceID, node: candidate.Handle, tag: safePersistentTag(candidate.PrimaryTag), failure: failure, source: source, at: at}
	}
	s.access.Unlock()
}

func (s *SwitchAuditStore) RecordSelection(session SessionKey, serviceID string, previous NodeHandle, candidate Candidate, reason DecisionReason, at time.Time) {
	if s == nil || candidate.ID == (NodeID{}) || serviceID == "" {
		return
	}
	s.access.Lock()
	pending, failed := s.pending[session]
	if failed {
		delete(s.pending, session)
	}
	sameNode := previous.NodeID == candidate.Handle.NodeID && previous.Slot == candidate.Handle.Slot && previous.Version == candidate.Handle.Version
	if !failed && (previous.NodeID == (NodeID{}) || sameNode) {
		s.access.Unlock()
		return
	}
	event := adapter.AdaptiveSwitchAudit{
		ServiceID: serviceID, SessionID: session.String(), NewNodeID: candidate.ID.String(), NewTag: safePersistentTag(candidate.PrimaryTag),
		Reason: string(reason), OccurredAt: at,
	}
	if failed {
		event.OldNodeID, event.OldTag = pending.node.NodeID.String(), pending.tag
		event.Failure = string(pending.failure)
		event.FailureSource = pending.source
		if pending.node.NodeID == candidate.ID && pending.node.Slot == candidate.Handle.Slot && pending.node.Version == candidate.Handle.Version {
			event.Reason = "failure_retry"
		} else {
			event.Reason = "failure_failover"
			s.total++
		}
	} else {
		event.OldNodeID = previous.NodeID.String()
		s.total++
	}
	s.entries = append(s.entries, event)
	if len(s.entries) > switchAuditLimit {
		copy(s.entries, s.entries[len(s.entries)-switchAuditLimit:])
		s.entries = s.entries[:switchAuditLimit]
	}
	s.access.Unlock()
}

func (s *SwitchAuditStore) Snapshot() ([]adapter.AdaptiveSwitchAudit, uint64) {
	if s == nil {
		return nil, 0
	}
	s.access.Lock()
	entries := append([]adapter.AdaptiveSwitchAudit(nil), s.entries...)
	total := s.total
	s.access.Unlock()
	return entries, total
}

// Clear drops audit history and pending failure correlations. Used on pool
// close/retire so reload cycles cannot retain unbounded session maps.
func (s *SwitchAuditStore) Clear() {
	if s == nil {
		return
	}
	s.access.Lock()
	s.entries = nil
	s.pending = make(map[SessionKey]pendingSwitchFailure)
	s.access.Unlock()
}
