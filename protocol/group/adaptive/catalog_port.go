package adaptive

import (
	"errors"
	"sync"
	"sync/atomic"
)

var ErrNoCandidates = errors.New("adaptive pool has no leaf candidates")

type Candidate struct {
	ID                    NodeID
	EndpointID            NodeID
	EndpointConflictCount int
	Handle                NodeHandle
	PrimaryTag            string
	Aliases               []string
	Sources               []string
	Transport             []string
	IdentityStable        bool
}

type ExecutionSnapshot struct {
	RuntimeEpochID       RuntimeEpochID
	CatalogRevision      CatalogRevision
	Generation           uint64
	Candidates           []Candidate
	ByID                 map[NodeID]int
	AliasToID            map[string]NodeID
	DuplicatesSuppressed int
	StableIdentityCount  int
}

type PreparedExecution struct {
	view     *ExecutionSnapshot
	bindings *EpochBindingSet
}

type committedCatalog struct {
	view     *ExecutionSnapshot
	bindings *EpochBindingSet
}

func (s *ExecutionSnapshot) Candidate(id NodeID) (Candidate, bool) {
	if s == nil {
		return Candidate{}, false
	}
	index, loaded := s.ByID[id]
	if !loaded || index < 0 || index >= len(s.Candidates) {
		return Candidate{}, false
	}
	return s.Candidates[index], true
}

type CatalogPort struct {
	access          sync.RWMutex
	current         *committedCatalog
	retiredBindings atomic.Uint64
}

func NewCatalogPort() *CatalogPort { return new(CatalogPort) }

// PrepareCommitted binds canonical runtime nodes to handles allocated by the
// stable manager. It never allocates or mutates handle lineage.
func (p *CatalogPort) PrepareCommitted(source SourcePublication, identity RuntimeIdentity) (*PreparedExecution, error) {
	if source.Generation == 0 || identity.EpochID == 0 || identity.Revision == 0 || source.Generation != identity.SourceGeneration || len(source.Nodes) != len(identity.Handles) {
		return nil, errors.New("adaptive committed identity does not match source")
	}
	seen := make(map[NodeID]bool, len(source.Nodes))
	for _, node := range source.Nodes {
		handle, loaded := identity.Handles[node.NodeID]
		if node.NodeID == (NodeID{}) || seen[node.NodeID] || source.Bindings[node.NodeID] == nil || !loaded || handle.NodeID != node.NodeID || handle.Version == 0 || (node.SourceKey == "" && len(node.Aliases) == 0) {
			return nil, errors.New("adaptive canonical source or committed handle is invalid")
		}
		seen[node.NodeID] = true
	}
	view := buildExecutionView(source.SourceSnapshot, identity)
	bindings, err := newEpochBindingSet(source, identity)
	if err != nil {
		return nil, err
	}
	return &PreparedExecution{view: view, bindings: bindings}, nil
}

func (p *CatalogPort) CommitPrepared(prepared *PreparedExecution) *ExecutionSnapshot {
	if prepared == nil || prepared.view == nil || prepared.bindings == nil {
		return nil
	}
	p.access.Lock()
	if p.current != nil && p.current.bindings != nil {
		p.current.bindings.access.Lock()
		count := len(p.current.bindings.ports)
		p.current.bindings.access.Unlock()
		p.retiredBindings.Add(uint64(count))
		p.current.bindings.retire()
	}
	p.current = &committedCatalog{view: prepared.view, bindings: prepared.bindings}
	p.access.Unlock()
	return cloneExecutionSnapshot(prepared.view)
}

func (p *CatalogPort) RollbackEpoch(epochID RuntimeEpochID) {
	p.access.Lock()
	if p.current != nil && p.current.view.RuntimeEpochID == epochID {
		if p.current.bindings != nil {
			p.current.bindings.access.Lock()
			count := len(p.current.bindings.ports)
			p.current.bindings.access.Unlock()
			p.retiredBindings.Add(uint64(count))
			p.current.bindings.retire()
		}
		p.current = nil
	}
	p.access.Unlock()
}

type BindingStats struct {
	Active  int
	Retired uint64
}

func (p *CatalogPort) BindingStats() BindingStats {
	p.access.RLock()
	active := 0
	if p.current != nil && p.current.bindings != nil {
		p.current.bindings.access.Lock()
		active = len(p.current.bindings.ports)
		p.current.bindings.access.Unlock()
	}
	p.access.RUnlock()
	return BindingStats{Active: active, Retired: p.retiredBindings.Load()}
}

func buildExecutionView(source SourceSnapshot, identity RuntimeIdentity) *ExecutionSnapshot {
	view := &ExecutionSnapshot{RuntimeEpochID: identity.EpochID, CatalogRevision: identity.Revision, Generation: source.Generation, Candidates: make([]Candidate, 0, len(source.Nodes)), ByID: make(map[NodeID]int), AliasToID: make(map[string]NodeID), DuplicatesSuppressed: source.DuplicatesSuppressed}
	for _, node := range source.Nodes {
		aliases := append([]string(nil), node.Aliases...)
		primaryTag := node.SourceKey
		if primaryTag == "" && len(aliases) > 0 {
			primaryTag = aliases[0]
		}
		aliases = appendUnique(aliases, primaryTag)
		sources := []string(nil)
		if node.Metadata != nil && node.Metadata["source"] != "" {
			sources = []string{node.Metadata["source"]}
		}
		candidate := Candidate{ID: node.NodeID, EndpointID: node.EndpointID, EndpointConflictCount: node.EndpointConflictCount, Handle: identity.Handles[node.NodeID], PrimaryTag: primaryTag, Aliases: aliases, Sources: sources, Transport: append([]string(nil), node.Transport...), IdentityStable: node.IdentityStable}
		view.ByID[node.NodeID] = len(view.Candidates)
		view.Candidates = append(view.Candidates, candidate)
		for _, alias := range aliases {
			view.AliasToID[alias] = node.NodeID
		}
		if node.IdentityStable {
			view.StableIdentityCount++
		}
	}
	return view
}

func (p *CatalogPort) Snapshot() *ExecutionSnapshot {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.current == nil {
		return nil
	}
	return cloneExecutionSnapshot(p.current.view)
}
func (p *CatalogPort) load() *ExecutionSnapshot {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.current == nil {
		return nil
	}
	return p.current.view
}

func (p *CatalogPort) AcquireExecution(token ExecutionToken) (*ExecutionLease, bool) {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.current == nil {
		return nil, false
	}
	return p.current.bindings.acquire(token)
}

func (p *CatalogPort) ResolveExecution(token ExecutionToken) (ExecutionPort, bool) {
	lease, loaded := p.AcquireExecution(token)
	if !loaded {
		return nil, false
	}
	port := lease.Port
	lease.Release()
	return port, true
}
func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func cloneExecutionSnapshot(snapshot *ExecutionSnapshot) *ExecutionSnapshot {
	if snapshot == nil {
		return nil
	}
	clone := &ExecutionSnapshot{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, Generation: snapshot.Generation, DuplicatesSuppressed: snapshot.DuplicatesSuppressed, StableIdentityCount: snapshot.StableIdentityCount, Candidates: make([]Candidate, len(snapshot.Candidates)), ByID: make(map[NodeID]int, len(snapshot.ByID)), AliasToID: make(map[string]NodeID, len(snapshot.AliasToID))}
	for index, candidate := range snapshot.Candidates {
		candidate.Aliases = append([]string(nil), candidate.Aliases...)
		candidate.Sources = append([]string(nil), candidate.Sources...)
		candidate.Transport = append([]string(nil), candidate.Transport...)
		clone.Candidates[index] = candidate
	}
	for id, index := range snapshot.ByID {
		clone.ByID[id] = index
	}
	for alias, id := range snapshot.AliasToID {
		clone.AliasToID[alias] = id
	}
	return clone
}
