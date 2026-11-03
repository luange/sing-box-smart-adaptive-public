//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
	"time"
)

const (
	udpClientIdleTTL       = 2 * time.Minute
	udpClientPruneInterval = 30 * time.Second
	udpClientMaxEntries    = 8192
)

type udpClientTable struct {
	access             sync.RWMutex
	clients            map[netip.AddrPort]*udpClientState
	redirectAccess     sync.Mutex
	redirectReferences map[netip.Addr]uint32
	nextPrune          time.Time
}

type udpClientState struct {
	access     sync.RWMutex
	connected  bool
	uid        uint32
	references uint32
	bindings   map[netip.AddrPort]udpRedirectBinding
	lastSeen   time.Time
}

func (t *udpClientTable) setUID(client netip.AddrPort, uid uint32) {
	clientState := t.loadOrCreate(client)
	clientState.access.Lock()
	clientState.uid = uid
	clientState.lastSeen = time.Now()
	clientState.access.Unlock()
}

type udpRedirectBinding struct {
	address   netip.Addr
	connected bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	t.access.RUnlock()
	return clientState, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	t.access.Lock()
	defer t.access.Unlock()
	return t.loadOrCreateLocked(client)
}

func (t *udpClientTable) retain(client netip.AddrPort) *udpClientState {
	t.access.Lock()
	clientState := t.loadOrCreateLocked(client)
	clientState.access.Lock()
	clientState.references++
	clientState.lastSeen = time.Now()
	clientState.access.Unlock()
	t.access.Unlock()
	return clientState
}

func (t *udpClientTable) loadOrCreateLocked(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.clients[client]; loaded {
		return clientState
	}
	if t.clients == nil {
		t.clients = make(map[netip.AddrPort]*udpClientState)
	}
	clientState := &udpClientState{bindings: make(map[netip.AddrPort]udpRedirectBinding), lastSeen: time.Now()}
	t.clients[client] = clientState
	return clientState
}

func (t *udpClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) (released []netip.Addr) {
	defer func() {
		released = append(released, t.pruneIdle(time.Now())...)
	}()
	t.access.RLock()
	clientState, loaded := t.clients[client]
	if loaded {
		released = t.setClientBinding(clientState, destination, redirectAddress, connected)
		t.access.RUnlock()
		return released
	}
	t.access.RUnlock()

	t.access.Lock()
	clientState = t.loadOrCreateLocked(client)
	released = t.setClientBinding(clientState, destination, redirectAddress, connected)
	t.access.Unlock()
	return released
}

func (t *udpClientTable) setClientBinding(
	clientState *udpClientState,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected {
		clientState.access.Lock()
		clientState.lastSeen = time.Now()
		clientState.access.Unlock()
		return nil
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	if loaded && current.address == redirectAddress && current.connected == connected {
		clientState.lastSeen = time.Now()
		return nil
	}
	clientState.bindings[destination] = udpRedirectBinding{
		address:   redirectAddress,
		connected: connected,
	}
	clientState.lastSeen = time.Now()

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if !connected {
		t.retainRedirectLocked(redirectAddress)
	}
	if loaded && !current.connected && t.releaseRedirectLocked(current.address) {
		return []netip.Addr{current.address}
	}
	return nil
}

// pruneIdle removes packet-only UDP rows that never acquired a NAT session.
// Those rows otherwise retain one entry per ephemeral client port forever.
// It only deletes reference-free states, so a live packet connection keeps its
// metadata and redirect bindings until its normal close callback runs.
func (t *udpClientTable) pruneIdle(now time.Time) (released []netip.Addr) {
	t.access.Lock()
	defer t.access.Unlock()
	if now.Before(t.nextPrune) && len(t.clients) < udpClientMaxEntries {
		return nil
	}
	t.nextPrune = now.Add(udpClientPruneInterval)
	for client, state := range t.clients {
		state.access.RLock()
		idle := state.references == 0 && now.Sub(state.lastSeen) > udpClientIdleTTL
		state.access.RUnlock()
		if !idle {
			continue
		}
		released = append(released, t.removeIdleLocked(client, state)...)
	}
	for len(t.clients) > udpClientMaxEntries {
		var oldestClient netip.AddrPort
		var oldestState *udpClientState
		var oldestSeen time.Time
		for client, state := range t.clients {
			state.access.RLock()
			seen, referenced := state.lastSeen, state.references > 0
			state.access.RUnlock()
			if referenced || (!oldestSeen.IsZero() && !seen.Before(oldestSeen)) {
				continue
			}
			oldestClient, oldestState, oldestSeen = client, state, seen
		}
		if oldestState == nil {
			break
		}
		released = append(released, t.removeIdleLocked(oldestClient, oldestState)...)
	}
	return released
}

// removeIdleLocked holds t.access and only accepts a reference-free state.
func (t *udpClientTable) removeIdleLocked(client netip.AddrPort, state *udpClientState) (released []netip.Addr) {
	if t.clients[client] != state {
		return nil
	}
	state.access.Lock()
	defer state.access.Unlock()
	if state.references != 0 {
		return nil
	}
	delete(t.clients, client)
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	for _, binding := range state.bindings {
		if !binding.connected && t.releaseRedirectLocked(binding.address) {
			released = append(released, binding.address)
		}
	}
	clear(state.bindings)
	return released
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	t.access.Lock()
	defer t.access.Unlock()
	if t.clients[client] != expected {
		return nil
	}
	// retain, binding updates, and idle pruning all protect the state fields
	// with expected.access.  Closing a NAT session must do the same: without
	// this lock the close callback can race a packet callback and leave an
	// orphaned row or release a redirect reference still used by that row.
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.references > 1 {
		expected.references--
		expected.lastSeen = time.Now()
		return nil
	}
	expected.references = 0
	delete(t.clients, client)

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []netip.Addr
	for _, binding := range expected.bindings {
		if !binding.connected && t.releaseRedirectLocked(binding.address) {
			released = append(released, binding.address)
		}
	}
	clear(expected.bindings)
	return released
}

func (t *udpClientTable) retainRedirectLocked(redirectAddress netip.Addr) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[netip.Addr]uint32)
	}
	t.redirectReferences[redirectAddress]++
}

func (t *udpClientTable) releaseRedirectLocked(redirectAddress netip.Addr) bool {
	references := t.redirectReferences[redirectAddress]
	if references > 1 {
		t.redirectReferences[redirectAddress] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, redirectAddress)
		return true
	}
	return false
}

func (s *udpClientState) redirectAddress(destination netip.AddrPort) (netip.Addr, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding.address, loaded
}

func (s *udpClientState) setConnected(connected bool) {
	s.access.Lock()
	s.connected = connected
	s.access.Unlock()
}

func (s *udpClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}

func (s *udpClientState) sourceUID() uint32 {
	s.access.RLock()
	uid := s.uid
	s.access.RUnlock()
	return uid
}
