package adaptive

import (
	"container/list"
	"context"
	"sync"
	"time"
)

type SessionLease struct {
	Key         SessionKey
	NodeID      NodeID
	NodeSlot    uint64
	NodeVersion uint64
	ServiceID   string
	Mode        PolicyMode
	ExpiresAt   time.Time
	UpdatedAt   time.Time
}

type leaseRecord struct {
	lease   SessionLease
	element *list.Element
}

type pendingRecord struct {
	generation uint64
	token      uint64
	wait       chan struct{}
	waiters    int
}

type LeaseReservation struct {
	manager    *SessionLeaseManager
	key        SessionKey
	generation uint64
	token      uint64
	once       sync.Once
}

type SessionLeaseManager struct {
	access     sync.Mutex
	leases     map[SessionKey]*leaseRecord
	pending    map[SessionKey]*pendingRecord
	lru        list.List
	maxEntries int
	evictions  uint64
	generation uint64
	nextToken  uint64
}

func NewSessionLeaseManager(maxEntries int) *SessionLeaseManager {
	if maxEntries <= 0 {
		maxEntries = 8192
	}
	return &SessionLeaseManager{
		leases:     make(map[SessionKey]*leaseRecord),
		pending:    make(map[SessionKey]*pendingRecord),
		maxEntries: maxEntries,
	}
}

func (m *SessionLeaseManager) Reserve(ctx context.Context, key SessionKey, now time.Time) (SessionLease, *LeaseReservation, error) {
	for {
		m.access.Lock()
		if record := m.leases[key]; record != nil {
			if record.lease.ExpiresAt.After(now) {
				m.lru.MoveToFront(record.element)
				lease := record.lease
				m.access.Unlock()
				return lease, nil, nil
			}
			m.removeLocked(record)
		}
		if pending := m.pending[key]; pending != nil {
			pending.waiters++
			wait := pending.wait
			m.access.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return SessionLease{}, nil, ctx.Err()
			}
		}
		m.nextToken++
		pending := &pendingRecord{
			generation: m.generation,
			token:      m.nextToken,
			wait:       make(chan struct{}),
		}
		m.pending[key] = pending
		m.access.Unlock()
		return SessionLease{}, &LeaseReservation{manager: m, key: key, generation: pending.generation, token: pending.token}, nil
	}
}

func (m *SessionLeaseManager) Peek(key SessionKey, now time.Time) (SessionLease, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	record := m.leases[key]
	if record == nil {
		return SessionLease{}, false
	}
	if !record.lease.ExpiresAt.After(now) {
		m.removeLocked(record)
		return SessionLease{}, false
	}
	m.lru.MoveToFront(record.element)
	return record.lease, true
}

func (r *LeaseReservation) Commit(nodeID NodeID, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	return r.CommitVersion(nodeID, 0, serviceID, mode, ttl, now)
}

func (r *LeaseReservation) CommitVersion(nodeID NodeID, nodeVersion uint64, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	return r.CommitHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion}, serviceID, mode, ttl, now)
}

func (r *LeaseReservation) CommitHandle(handle NodeHandle, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	var committed SessionLease
	r.once.Do(func() {
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		manager := r.manager
		manager.access.Lock()
		if r.generation != manager.generation || !manager.pendingOwnedByLocked(r.key, r.generation, r.token) {
			manager.access.Unlock()
			return
		}
		committed = SessionLease{
			Key:         r.key,
			NodeID:      handle.NodeID,
			NodeSlot:    handle.Slot,
			NodeVersion: handle.Version,
			ServiceID:   serviceID,
			Mode:        mode,
			ExpiresAt:   now.Add(ttl),
			UpdatedAt:   now,
		}
		record := &leaseRecord{lease: committed}
		record.element = manager.lru.PushFront(record)
		manager.leases[r.key] = record
		for len(manager.leases) > manager.maxEntries {
			manager.removeOldestLocked()
		}
		manager.finishPendingLocked(r.key, r.generation, r.token)
		manager.access.Unlock()
	})
	return committed
}

func (r *LeaseReservation) Abort() {
	r.once.Do(func() {
		r.manager.access.Lock()
		r.manager.finishPendingLocked(r.key, r.generation, r.token)
		r.manager.access.Unlock()
	})
}

func (m *SessionLeaseManager) Invalidate(key SessionKey, expected NodeID) {
	m.access.Lock()
	if record := m.leases[key]; record != nil && (expected == (NodeID{}) || record.lease.NodeID == expected) {
		m.removeLocked(record)
	}
	m.access.Unlock()
}

func (m *SessionLeaseManager) Replace(key SessionKey, expected, nodeID NodeID, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	return m.ReplaceVersion(key, expected, 0, nodeID, 0, serviceID, mode, ttl, now)
}

func (m *SessionLeaseManager) ReplaceVersion(key SessionKey, expected NodeID, expectedVersion uint64, nodeID NodeID, nodeVersion uint64, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	return m.ReplaceHandle(key, NodeHandle{NodeID: expected, Version: expectedVersion}, NodeHandle{NodeID: nodeID, Version: nodeVersion}, serviceID, mode, ttl, now)
}

func (m *SessionLeaseManager) ReplaceHandle(key SessionKey, expected, next NodeHandle, serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) SessionLease {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	m.access.Lock()
	defer m.access.Unlock()
	if record := m.leases[key]; record != nil {
		if expected.NodeID != (NodeID{}) && (record.lease.NodeID != expected.NodeID || record.lease.NodeSlot != expected.Slot || record.lease.NodeVersion != expected.Version) {
			return record.lease
		}
		record.lease.NodeID = next.NodeID
		record.lease.NodeSlot = next.Slot
		record.lease.NodeVersion = next.Version
		record.lease.ServiceID = serviceID
		record.lease.Mode = mode
		record.lease.ExpiresAt = now.Add(ttl)
		record.lease.UpdatedAt = now
		m.lru.MoveToFront(record.element)
		return record.lease
	}
	if expected.NodeID != (NodeID{}) {
		return SessionLease{}
	}
	lease := SessionLease{Key: key, NodeID: next.NodeID, NodeSlot: next.Slot, NodeVersion: next.Version, ServiceID: serviceID, Mode: mode, ExpiresAt: now.Add(ttl), UpdatedAt: now}
	record := &leaseRecord{lease: lease}
	record.element = m.lru.PushFront(record)
	m.leases[key] = record
	for len(m.leases) > m.maxEntries {
		m.removeOldestLocked()
	}
	return lease
}

func (m *SessionLeaseManager) RenewHandle(key SessionKey, expected NodeHandle, ttl time.Duration, now time.Time) SessionLease {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	m.access.Lock()
	defer m.access.Unlock()
	record := m.leases[key]
	if record == nil || record.lease.NodeID != expected.NodeID || record.lease.NodeSlot != expected.Slot || record.lease.NodeVersion != expected.Version {
		return SessionLease{}
	}
	record.lease.ExpiresAt = now.Add(ttl)
	record.lease.UpdatedAt = now
	m.lru.MoveToFront(record.element)
	return record.lease
}

func (m *SessionLeaseManager) RetireNodeVersion(nodeID NodeID, nodeVersion uint64) {
	m.RetireNodeHandle(NodeHandle{NodeID: nodeID, Version: nodeVersion})
}

func (m *SessionLeaseManager) RetireNodeHandle(handle NodeHandle) {
	m.access.Lock()
	for _, record := range m.leases {
		if record.lease.NodeID == handle.NodeID && record.lease.NodeSlot == handle.Slot && record.lease.NodeVersion == handle.Version {
			m.removeLocked(record)
		}
	}
	m.access.Unlock()
}

func (m *SessionLeaseManager) Clear() {
	m.access.Lock()
	m.generation++
	clear(m.leases)
	m.lru.Init()
	for key, pending := range m.pending {
		delete(m.pending, key)
		close(pending.wait)
	}
	m.access.Unlock()
}

func (m *SessionLeaseManager) Stats() (active int, evictions uint64) {
	m.access.Lock()
	active = len(m.leases)
	evictions = m.evictions
	m.access.Unlock()
	return
}

func (m *SessionLeaseManager) PersistenceSnapshot(now time.Time) []SessionLease {
	m.access.Lock()
	defer m.access.Unlock()
	result := make([]SessionLease, 0, len(m.leases))
	for _, record := range m.leases {
		if record.lease.ExpiresAt.After(now) {
			result = append(result, record.lease)
		}
	}
	return result
}

func (m *SessionLeaseManager) RestorePersistence(leases []SessionLease, now time.Time) {
	m.access.Lock()
	defer m.access.Unlock()
	for _, lease := range leases {
		if lease.Key == (SessionKey{}) || lease.NodeID == (NodeID{}) || lease.NodeSlot == 0 || lease.NodeVersion == 0 || !lease.ExpiresAt.After(now) {
			continue
		}
		if existing := m.leases[lease.Key]; existing != nil {
			if existing.lease.UpdatedAt.After(lease.UpdatedAt) {
				continue
			}
			m.removeLocked(existing)
		}
		record := &leaseRecord{lease: lease}
		record.element = m.lru.PushFront(record)
		m.leases[lease.Key] = record
	}
	for len(m.leases) > m.maxEntries {
		m.removeOldestLocked()
	}
}

func (m *SessionLeaseManager) pendingOwnedByLocked(key SessionKey, generation, token uint64) bool {
	pending := m.pending[key]
	return pending != nil && pending.generation == generation && pending.token == token
}

func (m *SessionLeaseManager) finishPendingLocked(key SessionKey, generation, token uint64) bool {
	pending := m.pending[key]
	if pending == nil || pending.generation != generation || pending.token != token {
		return false
	}
	delete(m.pending, key)
	close(pending.wait)
	return true
}

func (m *SessionLeaseManager) removeOldestLocked() {
	element := m.lru.Back()
	if element == nil {
		return
	}
	m.removeLocked(element.Value.(*leaseRecord))
}

func (m *SessionLeaseManager) removeLocked(record *leaseRecord) {
	delete(m.leases, record.lease.Key)
	m.lru.Remove(record.element)
	m.evictions++
}
