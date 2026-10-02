package adaptive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/sagernet/sing-box/common/nodeidentity"
)

const identityVersion = 1

type NodeID [16]byte
type SessionKey [16]byte

func (id NodeID) String() string {
	return hex.EncodeToString(id[:])
}

func (key SessionKey) String() string {
	// Session keys are already keyed, process-independent opaque identities.
	// Expose only half of the digest so operators can correlate lease and switch
	// records without recovering client, process, inbound or destination data.
	return hex.EncodeToString(key[:8])
}

type IdentityHasher struct {
	key [32]byte
}

func NewIdentityHasher(key []byte) (*IdentityHasher, error) {
	if len(key) < sha256.Size {
		return nil, errors.New("adaptive identity key must contain at least 32 bytes")
	}
	hasher := new(IdentityHasher)
	copy(hasher.key[:], key[:sha256.Size])
	return hasher, nil
}

func (h *IdentityHasher) FromCanonicalOptions(outboundType string, options any) (NodeID, error) {
	payload, err := json.Marshal(struct {
		Version int    `json:"version"`
		Type    string `json:"type"`
		Options any    `json:"options"`
	}{
		Version: identityVersion,
		Type:    outboundType,
		Options: options,
	})
	if err != nil {
		return NodeID{}, err
	}
	return h.sum(payload), nil
}

// FromEndpointOptions derives an opaque endpoint identity while excluding
// credential fields. This lets the catalog report competing credentials for
// one server/SNI without merging their independent NodeIDs or persisting any
// secret material.
func (h *IdentityHasher) FromEndpointOptions(outboundType string, options any) (NodeID, error) {
	value, err := canonicalEndpointValue(outboundType, options)
	if err != nil {
		return NodeID{}, err
	}
	payload, err := json.Marshal(struct {
		Version int    `json:"version"`
		Type    string `json:"type"`
		Options any    `json:"options"`
	}{Version: identityVersion, Type: outboundType, Options: value})
	if err != nil {
		return NodeID{}, err
	}
	digest := hmac.New(sha256.New, h.key[:])
	_, _ = digest.Write([]byte("sing-box/adaptive-endpoint/v1\x00"))
	_, _ = digest.Write(payload)
	var id NodeID
	copy(id[:], digest.Sum(nil)[:len(id)])
	return id, nil
}

func canonicalEndpointValue(outboundType string, input any) (any, error) {
	return nodeidentity.CanonicalEndpointOptionsForType(outboundType, input)
}

func (h *IdentityHasher) FromRuntimeDescriptor(candidateType, tag string, networks, dependencies []string) NodeID {
	networks = append([]string(nil), networks...)
	dependencies = append([]string(nil), dependencies...)
	sort.Strings(networks)
	sort.Strings(dependencies)
	payload, _ := json.Marshal(struct {
		Version      int      `json:"version"`
		Type         string   `json:"type"`
		Tag          string   `json:"tag"`
		Networks     []string `json:"networks"`
		Dependencies []string `json:"dependencies"`
	}{
		Version:      identityVersion,
		Type:         candidateType,
		Tag:          tag,
		Networks:     networks,
		Dependencies: dependencies,
	})
	return h.sum(payload)
}

func (h *IdentityHasher) sum(payload []byte) NodeID {
	digest := hmac.New(sha256.New, h.key[:])
	_, _ = digest.Write([]byte("sing-box/adaptive-node/v1\x00"))
	_, _ = digest.Write(payload)
	full := digest.Sum(nil)
	var id NodeID
	copy(id[:], full[:len(id)])
	return id
}

func (h *IdentityHasher) Session(parts ...string) SessionKey {
	digest := hmac.New(sha256.New, h.key[:])
	_, _ = digest.Write([]byte("sing-box/adaptive-session/v1\x00"))
	for _, part := range parts {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{0})
	}
	full := digest.Sum(nil)
	var key SessionKey
	copy(key[:], full[:len(key)])
	return key
}
