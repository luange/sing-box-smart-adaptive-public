package adaptive

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
)

const maxProcessExitIdentityEntries = 65536
const maxExitIdentityVariantsPerNode = 16

type exitIdentityFamilyState struct {
	variants  [][16]byte
	saturated bool
}

type exitIdentityNodeState struct {
	families map[uint8]*exitIdentityFamilyState
}

type exitIdentityToken struct {
	digest [16]byte
	family uint8
}

type exitIdentityGroupState struct {
	identities     map[NodeID]*exitIdentityNodeState
	changes        uint64
	saturatedNodes uint64
}

var processExitIdentities struct {
	once   sync.Once
	key    [32]byte
	err    error
	access sync.Mutex
	groups map[string]*exitIdentityGroupState
}

// ExitIdentityStore is process-local by design. It survives configuration
// reloads, but the baseline disappears when the sing-box process exits. Raw
// addresses and even their keyed fingerprints are never exposed by its API.
type ExitIdentityStore struct {
	groupID string
}

func NewExitIdentityStore(groupID string) (*ExitIdentityStore, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, errors.New("adaptive exit identity group is empty")
	}
	processExitIdentities.once.Do(func() {
		_, processExitIdentities.err = rand.Read(processExitIdentities.key[:])
		processExitIdentities.groups = make(map[string]*exitIdentityGroupState)
	})
	if processExitIdentities.err != nil {
		return nil, errors.New("adaptive exit identity key initialization failed")
	}
	return &ExitIdentityStore{groupID: groupID}, nil
}

func tokenizeExitIdentity(value []byte) (exitIdentityToken, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(string(value)))
	if err != nil || !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsMulticast() {
		return exitIdentityToken{}, false
	}
	family := uint8(6)
	if address.Is4() || address.Is4In6() {
		family = 4
	}
	canonical := address.Unmap().String()
	digest := hmac.New(sha256.New, processExitIdentities.key[:])
	_, _ = digest.Write([]byte(canonical))
	sum := digest.Sum(nil)
	var token [16]byte
	copy(token[:], sum[:len(token)])
	return exitIdentityToken{digest: token, family: family}, true
}

func (s *ExitIdentityStore) Compare(handle NodeHandle, token exitIdentityToken) (changed bool, accepted bool) {
	if s == nil || s.groupID == "" || handle.NodeID == (NodeID{}) || token.digest == ([16]byte{}) || token.family != 4 && token.family != 6 {
		return false, false
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		return false, true
	}
	node, loaded := group.identities[handle.NodeID]
	if !loaded {
		return false, true
	}
	family := node.families[token.family]
	if family == nil {
		return false, true
	}
	for _, known := range family.variants {
		if hmac.Equal(known[:], token.digest[:]) {
			return false, true
		}
	}
	if family.saturated {
		return false, true
	}
	return true, true
}

func (s *ExitIdentityStore) Commit(handle NodeHandle, token exitIdentityToken) bool {
	if s == nil || s.groupID == "" || handle.NodeID == (NodeID{}) || token.digest == ([16]byte{}) || token.family != 4 && token.family != 6 {
		return false
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		group = &exitIdentityGroupState{identities: make(map[NodeID]*exitIdentityNodeState)}
		processExitIdentities.groups[s.groupID] = group
	}
	node, loaded := group.identities[handle.NodeID]
	if !loaded {
		entries := 0
		for _, state := range processExitIdentities.groups {
			entries += len(state.identities)
		}
		if entries >= maxProcessExitIdentityEntries {
			return false
		}
		group.identities[handle.NodeID] = &exitIdentityNodeState{families: map[uint8]*exitIdentityFamilyState{
			token.family: {variants: [][16]byte{token.digest}},
		}}
		return true
	}
	family := node.families[token.family]
	if family == nil {
		if node.families == nil {
			node.families = make(map[uint8]*exitIdentityFamilyState)
		}
		node.families[token.family] = &exitIdentityFamilyState{variants: [][16]byte{token.digest}}
		return true
	}
	for _, known := range family.variants {
		if hmac.Equal(known[:], token.digest[:]) {
			return true
		}
	}
	if family.saturated {
		return true
	}
	if len(family.variants) >= maxExitIdentityVariantsPerNode {
		family.saturated = true
		group.saturatedNodes++
		return true
	}
	family.variants = append(family.variants, token.digest)
	group.changes++
	return true
}

func (s *ExitIdentityStore) FamilyStats() (ipv4, ipv6, dualStack uint64) {
	if s == nil {
		return 0, 0, 0
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		return 0, 0, 0
	}
	for _, node := range group.identities {
		_, has4 := node.families[4]
		_, has6 := node.families[6]
		if has4 {
			ipv4++
		}
		if has6 {
			ipv6++
		}
		if has4 && has6 {
			dualStack++
		}
	}
	return
}

func (s *ExitIdentityStore) Stats() (baselines, changes, saturated uint64) {
	if s == nil {
		return 0, 0, 0
	}
	processExitIdentities.access.Lock()
	defer processExitIdentities.access.Unlock()
	group := processExitIdentities.groups[s.groupID]
	if group == nil {
		return 0, 0, 0
	}
	return uint64(len(group.identities)), group.changes, group.saturatedNodes
}
