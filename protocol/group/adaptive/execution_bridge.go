package adaptive

import (
	"context"
	"errors"
	"net"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
)

// ExecutionPort is the stable contract consumed by Smart execution code. The
// source adapter may wrap any official outbound implementation behind it.
// Core policy/health/lease code must not depend on adapter.Outbound.
type ExecutionPort interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error)
}

var ErrExecutionBindingUnavailable = errors.New("adaptive execution binding is unavailable")

type ExecutionToken struct {
	RuntimeEpochID  RuntimeEpochID
	CatalogRevision CatalogRevision
	Handle          NodeHandle
}

type ExecutionBridge interface {
	AcquireExecution(ExecutionToken) (*ExecutionLease, bool)
}

type ExecutionLease struct {
	Port    ExecutionPort
	release func()
	once    sync.Once
}

func (l *ExecutionLease) Release() {
	if l != nil && l.release != nil {
		l.once.Do(l.release)
	}
}

// EpochBindingSet is immutable after prepare and belongs to exactly one
// catalog revision. It must never be persisted or stored in RuntimeManager.
type EpochBindingSet struct {
	access   sync.Mutex
	epochID  RuntimeEpochID
	revision CatalogRevision
	ports    map[NodeHandle]ExecutionPort
	refs     int
	retiring bool
}

func newEpochBindingSet(source SourcePublication, identity RuntimeIdentity) (*EpochBindingSet, error) {
	bindings := &EpochBindingSet{epochID: identity.EpochID, revision: identity.Revision, ports: make(map[NodeHandle]ExecutionPort, len(source.Nodes))}
	for _, node := range source.Nodes {
		handle, loaded := identity.Handles[node.NodeID]
		port := source.Bindings[node.NodeID]
		if !loaded || port == nil {
			return nil, ErrExecutionBindingUnavailable
		}
		bindings.ports[handle] = port
	}
	return bindings, nil
}

func (s *EpochBindingSet) acquire(token ExecutionToken) (*ExecutionLease, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if s == nil || s.retiring || token.RuntimeEpochID != s.epochID || token.CatalogRevision != s.revision || token.Handle.NodeID == (NodeID{}) || token.Handle.Slot == 0 || token.Handle.Version == 0 {
		return nil, false
	}
	port, loaded := s.ports[token.Handle]
	if !loaded || port == nil {
		return nil, false
	}
	s.refs++
	return &ExecutionLease{Port: port, release: func() { s.release() }}, true
}

func (s *EpochBindingSet) release() {
	s.access.Lock()
	if s.refs > 0 {
		s.refs--
	}
	if s.retiring && s.refs == 0 {
		s.ports = nil
	}
	s.access.Unlock()
}

func (s *EpochBindingSet) retire() {
	s.access.Lock()
	s.retiring = true
	if s.refs == 0 {
		s.ports = nil
	}
	s.access.Unlock()
}
