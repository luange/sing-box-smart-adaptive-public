package adaptive

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/service"
)

type ControlState struct {
	access       sync.RWMutex
	pinned       NodeID
	pinnedTag    string
	latestTag    string
	bulkSequence atomic.Uint64
	revision     atomic.Uint64
}

type RuntimeEpochID uint64
type CatalogRevision uint64

type NodeHandle struct {
	NodeID                      NodeID
	Slot, Version, BornRevision uint64
}

type EpochLifecycle uint8

const (
	EpochActive EpochLifecycle = iota + 1
	EpochRetiring
	EpochRetired
)

type IdentityNode struct {
	NodeID         NodeID
	IdentityStable bool
}

type IdentitySnapshot struct {
	SourceGeneration uint64
	Nodes            []IdentityNode
}

func IdentityFromSource(source SourceSnapshot) (IdentitySnapshot, error) {
	identity := IdentitySnapshot{SourceGeneration: source.Generation, Nodes: make([]IdentityNode, len(source.Nodes))}
	for index, node := range source.Nodes {
		identity.Nodes[index] = IdentityNode{NodeID: node.NodeID, IdentityStable: node.IdentityStable}
	}
	return identity, validateIdentitySnapshot(identity)
}

type RuntimeIdentity struct {
	EpochID            RuntimeEpochID
	Revision           CatalogRevision
	SourceGeneration   uint64
	Handles            map[NodeID]NodeHandle
	RetiredHandles     []NodeHandle
	VersionTransitions []VersionTransition
}

type VersionTransition struct {
	Previous NodeHandle
	Current  NodeHandle
}

type stableNodeLineage struct {
	handle          NodeHandle
	presentInLatest bool
}

type retiredLineageItem struct {
	nodeID   NodeID
	revision CatalogRevision
}

type stableEpoch struct {
	lifecycle            EpochLifecycle
	revision             CatalogRevision
	lastSourceGeneration uint64
	refCount             int
	handles              map[NodeID]NodeHandle
}

type stableIdentityState struct {
	nextEpoch     RuntimeEpochID
	nextRevision  CatalogRevision
	nextSlot      uint64
	currentEpoch  RuntimeEpochID
	lineage       map[NodeID]stableNodeLineage
	retired       []retiredLineageItem
	retiredHead   int
	retiredQueued map[NodeID]CatalogRevision
	maxRetired    int
}

type sharedGroupState struct {
	health   *HealthStore
	leases   *SessionLeaseManager
	control  *ControlState
	identity *stableIdentityState
	epochs   map[RuntimeEpochID]*stableEpoch
}

type RuntimeManager struct {
	access          sync.RWMutex
	groups          map[string]*sharedGroupState
	groupUsers      map[string]int
	schedulerAccess sync.Mutex
	schedulers      map[string]*SchedulerCoordinator
	schedulerWaiter map[string]*SchedulerCoordinator
}

func NewRuntimeManager() *RuntimeManager {
	return &RuntimeManager{
		groups:          make(map[string]*sharedGroupState),
		groupUsers:      make(map[string]int),
		schedulers:      make(map[string]*SchedulerCoordinator),
		schedulerWaiter: make(map[string]*SchedulerCoordinator),
	}
}

// RegisterGroup accounts for one AdaptivePool instance. It deliberately does
// not create runtime state: a pool may be registered before its first publish.
func (m *RuntimeManager) RegisterGroup(groupID string) {
	if m == nil || groupID == "" {
		return
	}
	m.access.Lock()
	if m.groupUsers == nil {
		m.groupUsers = make(map[string]int)
	}
	m.groupUsers[groupID]++
	m.access.Unlock()
}

func (m *RuntimeManager) UnregisterGroup(groupID string) {
	if m == nil || groupID == "" {
		return
	}
	m.access.Lock()
	if m.groupUsers[groupID] > 1 {
		m.groupUsers[groupID]--
		m.access.Unlock()
		return
	}
	delete(m.groupUsers, groupID)
	m.tryCleanupGroupLocked(groupID)
	m.access.Unlock()
	m.tryCleanupScheduler(groupID)
}

func (m *RuntimeManager) tryCleanupGroupLocked(groupID string) {
	if m.groupUsers[groupID] != 0 {
		return
	}
	state := m.groups[groupID]
	if state != nil && len(state.epochs) == 0 {
		delete(m.groups, groupID)
	}
}

func (m *RuntimeManager) tryCleanupScheduler(groupID string) {
	if m == nil || groupID == "" {
		return
	}
	m.access.RLock()
	state := m.groups[groupID]
	eligible := m.groupUsers[groupID] == 0 && (state == nil || len(state.epochs) == 0)
	m.access.RUnlock()
	if !eligible {
		return
	}
	m.schedulerAccess.Lock()
	coordinator := m.schedulers[groupID]
	if coordinator == nil {
		m.schedulerAccess.Unlock()
		return
	}
	drain, idle := coordinator.cleanupState()
	if idle {
		delete(m.schedulers, groupID)
		delete(m.schedulerWaiter, groupID)
		m.schedulerAccess.Unlock()
		return
	}
	if drain == nil {
		m.schedulerAccess.Unlock()
		return
	}
	if m.schedulerWaiter == nil {
		m.schedulerWaiter = make(map[string]*SchedulerCoordinator)
	}
	if m.schedulerWaiter[groupID] == coordinator {
		m.schedulerAccess.Unlock()
		return
	}
	m.schedulerWaiter[groupID] = coordinator
	m.schedulerAccess.Unlock()
	go func(expected *SchedulerCoordinator, wait <-chan struct{}) {
		<-wait
		m.schedulerAccess.Lock()
		if m.schedulerWaiter[groupID] == expected {
			delete(m.schedulerWaiter, groupID)
		}
		if m.schedulers[groupID] != expected {
			m.schedulerAccess.Unlock()
			return
		}
		m.access.RLock()
		users := m.groupUsers[groupID]
		state := m.groups[groupID]
		canDeleteGroup := users == 0 && (state == nil || len(state.epochs) == 0)
		m.access.RUnlock()
		_, idle := expected.cleanupState()
		if canDeleteGroup && idle {
			delete(m.schedulers, groupID)
		}
		m.schedulerAccess.Unlock()
	}(coordinator, drain)
}

func (m *RuntimeManager) RuntimeStats() (groups, schedulers, users int) {
	if m == nil {
		return
	}
	m.access.RLock()
	groups, users = len(m.groups), len(m.groupUsers)
	m.access.RUnlock()
	m.schedulerAccess.Lock()
	schedulers = len(m.schedulers)
	m.schedulerAccess.Unlock()
	return
}

func (m *RuntimeManager) SchedulerCoordinator(groupID string) *SchedulerCoordinator {
	m.schedulerAccess.Lock()
	if m.schedulers == nil {
		m.schedulers = make(map[string]*SchedulerCoordinator)
	}
	coordinator := m.schedulers[groupID]
	if coordinator == nil {
		coordinator = new(SchedulerCoordinator)
		m.schedulers[groupID] = coordinator
	}
	m.schedulerAccess.Unlock()
	return coordinator
}

func (m *RuntimeManager) PersistenceSnapshot(groupID string) *persistedIdentityState {
	m.access.RLock()
	state := m.groups[groupID]
	if state == nil || state.identity == nil {
		m.access.RUnlock()
		return nil
	}
	identity := state.identity
	snapshot := &persistedIdentityState{NextEpoch: identity.nextEpoch, NextRevision: identity.nextRevision, NextSlot: identity.nextSlot, Lineage: make([]persistedIdentityLineage, 0, len(identity.lineage))}
	for nodeID, lineage := range identity.lineage {
		snapshot.Lineage = append(snapshot.Lineage, persistedIdentityLineage{NodeID: nodeID, Handle: lineage.handle, PresentInLatest: lineage.presentInLatest})
	}
	m.access.RUnlock()
	sort.Slice(snapshot.Lineage, func(first, second int) bool {
		return bytes.Compare(snapshot.Lineage[first].NodeID[:], snapshot.Lineage[second].NodeID[:]) < 0
	})
	return snapshot
}

func (m *RuntimeManager) RestorePersistence(groupID string, health *HealthStore, leases *SessionLeaseManager, control *ControlState, persisted *persistedIdentityState) error {
	if groupID == "" || health == nil || leases == nil || control == nil || persisted == nil {
		return errors.New("adaptive persisted identity dependency is invalid")
	}
	m.access.RLock()
	exists := m.groups[groupID] != nil
	m.access.RUnlock()
	if exists {
		return nil
	}
	identity, err := restoreStableIdentityState(persisted)
	if err != nil {
		return err
	}
	m.access.Lock()
	if m.groups[groupID] == nil {
		m.groups[groupID] = &sharedGroupState{health: health, leases: leases, control: control, identity: identity, epochs: make(map[RuntimeEpochID]*stableEpoch)}
	}
	m.access.Unlock()
	return nil
}

func restoreStableIdentityState(persisted *persistedIdentityState) (*stableIdentityState, error) {
	if persisted.NextEpoch == 0 || persisted.NextRevision == 0 || len(persisted.Lineage) > 1<<20 {
		return nil, errors.New("adaptive persisted identity counters are invalid")
	}
	identity := newStableIdentityState()
	identity.nextEpoch, identity.currentEpoch, identity.nextRevision, identity.nextSlot = persisted.NextEpoch, persisted.NextEpoch, persisted.NextRevision, persisted.NextSlot
	usedSlots := make(map[uint64]struct{}, len(persisted.Lineage))
	for _, item := range persisted.Lineage {
		handle := item.Handle
		if item.NodeID == (NodeID{}) || handle.NodeID != item.NodeID || handle.Slot == 0 || handle.Slot > persisted.NextSlot || handle.Version == 0 || handle.BornRevision == 0 || CatalogRevision(handle.BornRevision) > persisted.NextRevision {
			return nil, errors.New("adaptive persisted identity lineage is invalid")
		}
		if _, exists := identity.lineage[item.NodeID]; exists {
			return nil, errors.New("adaptive persisted identity contains duplicate node")
		}
		if _, exists := usedSlots[handle.Slot]; exists {
			return nil, errors.New("adaptive persisted identity contains duplicate slot")
		}
		usedSlots[handle.Slot] = struct{}{}
		identity.lineage[item.NodeID] = stableNodeLineage{handle: handle, presentInLatest: item.PresentInLatest}
		if !item.PresentInLatest {
			if len(identity.retired) >= identity.maxRetired {
				return nil, errors.New("adaptive persisted retired lineage exceeds bound")
			}
			identity.retired = append(identity.retired, retiredLineageItem{nodeID: item.NodeID, revision: persisted.NextRevision})
			identity.retiredQueued[item.NodeID] = persisted.NextRevision
		}
	}
	return identity, nil
}

func newStableIdentityState() *stableIdentityState {
	return &stableIdentityState{lineage: make(map[NodeID]stableNodeLineage), retiredQueued: make(map[NodeID]CatalogRevision), maxRetired: 16384}
}

func ContextWithDefaultRuntimeManager(ctx context.Context) context.Context {
	if service.PtrFromContext[RuntimeManager](ctx) != nil {
		return ctx
	}
	return service.ContextWithPtr(ctx, NewRuntimeManager())
}

type PreparedIdentity struct {
	manager       *RuntimeManager
	groupID       string
	baseRevision  CatalogRevision
	baseState     *stableIdentityState
	nextState     *stableIdentityState
	identity      RuntimeIdentity
	health        *HealthStore
	leases        *SessionLeaseManager
	control       *ControlState
	newEpoch      bool
	committed     atomic.Bool
	rolledBack    atomic.Bool
	previousEpoch *stableEpoch
}

func (m *RuntimeManager) PrepareEpoch(groupID string, health *HealthStore, leases *SessionLeaseManager, control *ControlState, snapshot IdentitySnapshot) (*PreparedIdentity, error) {
	if groupID == "" {
		return nil, errors.New("adaptive stable group id is required")
	}
	if err := validateIdentitySnapshot(snapshot); err != nil {
		return nil, err
	}
	m.access.Lock()
	state := m.groups[groupID]
	var base *stableIdentityState
	if state != nil {
		base = state.identity
	} else {
		base = newStableIdentityState()
	}
	next := cloneStableIdentity(base)
	identity := next.preparePublish(snapshot, true)
	m.access.Unlock()
	return &PreparedIdentity{manager: m, groupID: groupID, baseRevision: base.nextRevision, baseState: func() *stableIdentityState {
		if state == nil {
			return nil
		}
		return state.identity
	}(), nextState: next, identity: identity, health: health, leases: leases, control: control, newEpoch: true}, nil
}

func (m *RuntimeManager) PrepareRevision(groupID string, epochID RuntimeEpochID, snapshot IdentitySnapshot) (*PreparedIdentity, error) {
	if err := validateIdentitySnapshot(snapshot); err != nil {
		return nil, err
	}
	m.access.Lock()
	defer m.access.Unlock()
	state := m.groups[groupID]
	if state == nil || state.identity == nil || state.identity.currentEpoch != epochID {
		return nil, errors.New("adaptive runtime epoch is not current")
	}
	epoch := state.epochs[epochID]
	if epoch == nil || epoch.lifecycle != EpochActive {
		return nil, errors.New("adaptive runtime epoch is not active")
	}
	if snapshot.SourceGeneration <= epoch.lastSourceGeneration {
		return nil, ErrSourceGenerationOutOfOrder
	}
	next := cloneStableIdentity(state.identity)
	identity := next.preparePublish(snapshot, false)
	previousEpoch := *epoch
	previousEpoch.handles = cloneHandles(epoch.handles)
	return &PreparedIdentity{manager: m, groupID: groupID, baseRevision: state.identity.nextRevision, baseState: state.identity, nextState: next, identity: identity, previousEpoch: &previousEpoch}, nil
}

func (p *PreparedIdentity) Rollback() error {
	if p == nil || p.manager == nil || !p.committed.Load() || !p.rolledBack.CompareAndSwap(false, true) {
		return nil
	}
	p.manager.access.Lock()
	defer p.manager.access.Unlock()
	state := p.manager.groups[p.groupID]
	if state == nil || state.identity != p.nextState {
		return ErrPreparedIdentityStale
	}
	if p.baseState == nil {
		delete(p.manager.groups, p.groupID)
		return nil
	}
	state.identity = p.baseState
	if p.newEpoch {
		delete(state.epochs, p.identity.EpochID)
	} else if p.previousEpoch != nil {
		restored := *p.previousEpoch
		restored.handles = cloneHandles(p.previousEpoch.handles)
		state.epochs[p.identity.EpochID] = &restored
	}
	return nil
}

func (p *PreparedIdentity) Identity() RuntimeIdentity { return cloneRuntimeIdentity(p.identity) }

func (p *PreparedIdentity) Commit() (*sharedGroupState, RuntimeIdentity, error) {
	if p == nil || p.manager == nil {
		return nil, RuntimeIdentity{}, errors.New("adaptive identity preparation is no longer committable")
	}
	p.manager.access.Lock()
	defer p.manager.access.Unlock()
	if p.committed.Load() || p.rolledBack.Load() {
		return nil, RuntimeIdentity{}, errors.New("adaptive identity preparation is no longer committable")
	}
	state := p.manager.groups[p.groupID]
	if p.baseState == nil {
		if state != nil {
			return nil, RuntimeIdentity{}, ErrPreparedIdentityStale
		}
		state = &sharedGroupState{health: p.health, leases: p.leases, control: p.control, epochs: make(map[RuntimeEpochID]*stableEpoch)}
		p.manager.groups[p.groupID] = state
	} else if state == nil || state.identity != p.baseState || state.identity.nextRevision != p.baseRevision {
		return nil, RuntimeIdentity{}, ErrPreparedIdentityStale
	}
	if !p.newEpoch {
		epoch := state.epochs[p.identity.EpochID]
		if epoch == nil || epoch.lifecycle != EpochActive || epoch.lastSourceGeneration >= p.identity.SourceGeneration {
			return nil, RuntimeIdentity{}, ErrPreparedIdentityStale
		}
	}
	// Mark committed only after all stale/base checks succeed.  A failed
	// optimistic publish remains retryable instead of consuming the prepared
	// object and leaving the pool stuck in publishing phase.
	p.committed.Store(true)
	state.identity = p.nextState
	if p.newEpoch {
		state.epochs[p.identity.EpochID] = &stableEpoch{lifecycle: EpochActive, revision: p.identity.Revision, lastSourceGeneration: p.identity.SourceGeneration, handles: cloneHandles(p.identity.Handles)}
	} else {
		epoch := state.epochs[p.identity.EpochID]
		epoch.revision = p.identity.Revision
		epoch.lastSourceGeneration = p.identity.SourceGeneration
		epoch.handles = cloneHandles(p.identity.Handles)
	}
	return state, cloneRuntimeIdentity(p.identity), nil
}

var ErrPreparedIdentityStale = errors.New("adaptive prepared identity is stale")

func (m *RuntimeManager) AcquireEpoch(groupID string, epochID RuntimeEpochID) (*RuntimeEpochIdentityLease, error) {
	m.access.Lock()
	defer m.access.Unlock()
	state := m.groups[groupID]
	if state == nil || state.identity == nil {
		return nil, errors.New("adaptive runtime group is not published")
	}
	epoch := state.epochs[epochID]
	if epoch == nil || epoch.lifecycle != EpochActive {
		return nil, errors.New("adaptive runtime epoch is not active")
	}
	epoch.refCount++
	return &RuntimeEpochIdentityLease{manager: m, groupID: groupID, epochID: epochID}, nil
}

type RuntimeEpochIdentityLease struct {
	manager  *RuntimeManager
	groupID  string
	epochID  RuntimeEpochID
	released atomic.Bool
}

func (l *RuntimeEpochIdentityLease) ValidateObservation(revision CatalogRevision, nodeID NodeID, slot, version uint64) bool {
	return l.ValidateEvidence(l.epochID, revision, 1, NodeHandle{NodeID: nodeID, Slot: slot, Version: version})
}

func (l *RuntimeEpochIdentityLease) ValidateEvidence(epochID RuntimeEpochID, revision CatalogRevision, sourceGeneration uint64, handle NodeHandle) bool {
	if l == nil || l.released.Load() {
		return false
	}
	l.manager.access.RLock()
	defer l.manager.access.RUnlock()
	if epochID != l.epochID {
		return false
	}
	return validateEpochObservation(l.manager.groups[l.groupID], l.epochID, revision, sourceGeneration, handle.NodeID, handle.Slot, handle.Version, true)
}

func (l *RuntimeEpochIdentityLease) Release() {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	l.manager.access.Lock()
	state := l.manager.groups[l.groupID]
	if state == nil || state.identity == nil {
		l.manager.access.Unlock()
		return
	}
	epoch := state.epochs[l.epochID]
	if epoch == nil {
		l.manager.access.Unlock()
		return
	}
	if epoch.refCount > 0 {
		epoch.refCount--
	}
	if epoch.lifecycle == EpochRetiring && epoch.refCount == 0 {
		epoch.lifecycle = EpochRetired
		delete(state.epochs, l.epochID)
		l.manager.tryCleanupGroupLocked(l.groupID)
	}
	l.manager.access.Unlock()
	l.manager.tryCleanupScheduler(l.groupID)
}

func (m *RuntimeManager) RetireEpoch(groupID string, epochID RuntimeEpochID) {
	m.access.Lock()
	state := m.groups[groupID]
	if state == nil || state.identity == nil {
		m.access.Unlock()
		return
	}
	epoch := state.epochs[epochID]
	if epoch == nil || epoch.lifecycle == EpochRetired {
		m.access.Unlock()
		return
	}
	epoch.lifecycle = EpochRetiring
	if epoch.refCount == 0 {
		epoch.lifecycle = EpochRetired
		delete(state.epochs, epochID)
		m.tryCleanupGroupLocked(groupID)
	}
	m.access.Unlock()
	m.tryCleanupScheduler(groupID)
}

// Validation without a lease accepts only the active epoch. Retiring
// connections must use the lease acquired while the epoch was active.
func (m *RuntimeManager) ValidateObservation(groupID string, epochID RuntimeEpochID, revision CatalogRevision, nodeID NodeID, slot, version uint64) bool {
	m.access.RLock()
	defer m.access.RUnlock()
	return validateEpochObservation(m.groups[groupID], epochID, revision, 1, nodeID, slot, version, false)
}

func validateEpochObservation(state *sharedGroupState, epochID RuntimeEpochID, revision CatalogRevision, sourceGeneration uint64, nodeID NodeID, slot, version uint64, allowRetiring bool) bool {
	if state == nil || state.identity == nil || revision == 0 || sourceGeneration == 0 || slot == 0 || version == 0 {
		return false
	}
	epoch := state.epochs[epochID]
	if epoch == nil || epoch.lifecycle == EpochRetired || (epoch.lifecycle == EpochRetiring && !allowRetiring) || revision > epoch.revision || sourceGeneration > epoch.lastSourceGeneration {
		return false
	}
	handle, ok := epoch.handles[nodeID]
	lineage, current := state.identity.lineage[nodeID]
	return ok && current && lineage.presentInLatest && lineage.handle.Slot == slot && lineage.handle.Version == version && handle.Slot == slot && handle.Version == version && revision >= CatalogRevision(handle.BornRevision)
}

func validateIdentitySnapshot(snapshot IdentitySnapshot) error {
	if snapshot.SourceGeneration == 0 {
		return errors.New("adaptive source generation is required")
	}
	seen := make(map[NodeID]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if node.NodeID == (NodeID{}) {
			return errors.New("adaptive identity contains empty node")
		}
		if _, loaded := seen[node.NodeID]; loaded {
			return errors.New("adaptive identity contains duplicate node")
		}
		seen[node.NodeID] = struct{}{}
	}
	return nil
}

func (s *stableIdentityState) preparePublish(snapshot IdentitySnapshot, newEpoch bool) RuntimeIdentity {
	s.nextRevision++
	if newEpoch {
		s.nextEpoch++
		s.currentEpoch = s.nextEpoch
	}
	revision := s.nextRevision
	handles := make(map[NodeID]NodeHandle, len(snapshot.Nodes))
	var retiredHandles []NodeHandle
	var transitions []VersionTransition
	seen := make(map[NodeID]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		lineage, exists := s.lineage[node.NodeID]
		previous := lineage.handle
		if !exists {
			s.nextSlot++
			lineage.handle = NodeHandle{NodeID: node.NodeID, Slot: s.nextSlot, Version: 1, BornRevision: uint64(revision)}
		} else if !lineage.presentInLatest || !node.IdentityStable {
			lineage.handle.Version++
			lineage.handle.BornRevision = uint64(revision)
			retiredHandles = append(retiredHandles, previous)
			transitions = append(transitions, VersionTransition{Previous: previous, Current: lineage.handle})
		}
		lineage.presentInLatest = true
		s.lineage[node.NodeID] = lineage
		delete(s.retiredQueued, node.NodeID)
		handles[node.NodeID] = lineage.handle
		seen[node.NodeID] = struct{}{}
	}
	for id, lineage := range s.lineage {
		if _, loaded := seen[id]; !loaded && lineage.presentInLatest {
			lineage.presentInLatest = false
			s.lineage[id] = lineage
			retiredHandles = append(retiredHandles, lineage.handle)
			s.retired = append(s.retired, retiredLineageItem{nodeID: id, revision: revision})
			s.retiredQueued[id] = revision
		}
	}
	for len(s.retired)-s.retiredHead > s.maxRetired {
		item := s.retired[s.retiredHead]
		s.retiredHead++
		if s.retiredQueued[item.nodeID] != item.revision {
			continue
		}
		delete(s.retiredQueued, item.nodeID)
		if lineage, loaded := s.lineage[item.nodeID]; loaded && !lineage.presentInLatest {
			delete(s.lineage, item.nodeID)
		}
	}
	if s.retiredHead > 1024 && s.retiredHead*2 > len(s.retired) {
		s.retired = append([]retiredLineageItem(nil), s.retired[s.retiredHead:]...)
		s.retiredHead = 0
	}
	return RuntimeIdentity{EpochID: s.currentEpoch, Revision: revision, SourceGeneration: snapshot.SourceGeneration, Handles: cloneHandles(handles), RetiredHandles: append([]NodeHandle(nil), retiredHandles...), VersionTransitions: append([]VersionTransition(nil), transitions...)}
}

func cloneStableIdentity(source *stableIdentityState) *stableIdentityState {
	clone := &stableIdentityState{nextEpoch: source.nextEpoch, nextRevision: source.nextRevision, nextSlot: source.nextSlot, currentEpoch: source.currentEpoch, lineage: make(map[NodeID]stableNodeLineage, len(source.lineage)), retired: append([]retiredLineageItem(nil), source.retired...), retiredHead: source.retiredHead, retiredQueued: make(map[NodeID]CatalogRevision, len(source.retiredQueued)), maxRetired: source.maxRetired}
	for id, lineage := range source.lineage {
		clone.lineage[id] = lineage
	}
	for id, revision := range source.retiredQueued {
		clone.retiredQueued[id] = revision
	}
	return clone
}

func cloneHandles(source map[NodeID]NodeHandle) map[NodeID]NodeHandle {
	clone := make(map[NodeID]NodeHandle, len(source))
	for id, handle := range source {
		clone[id] = handle
	}
	return clone
}

func cloneRuntimeIdentity(source RuntimeIdentity) RuntimeIdentity {
	source.Handles = cloneHandles(source.Handles)
	source.RetiredHandles = append([]NodeHandle(nil), source.RetiredHandles...)
	source.VersionTransitions = append([]VersionTransition(nil), source.VersionTransitions...)
	return source
}
