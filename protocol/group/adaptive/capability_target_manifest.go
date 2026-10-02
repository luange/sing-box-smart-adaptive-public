package adaptive

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxSignedProbeManifestBytes = 256 * 1024

const (
	ProbeManifestKeyIDHeader     = "X-Adaptive-Probe-Key-Id"
	ProbeManifestSignatureHeader = "X-Adaptive-Probe-Signature"
	YouTubeProbeServiceID        = "youtube"
	YouTubeTargetSourceID        = "youtube-signed-control-plane-v1"
	probeManifestKeyIDHeader     = ProbeManifestKeyIDHeader
	probeManifestSignatureHeader = ProbeManifestSignatureHeader
)

var ErrProbeTargetFetch = errors.New("adaptive signed probe target fetch failed")

// SignedProbeTargetManifest keeps the bearer-like payload opaque until the
// provider verifies it. No formatter or JSON representation exposes payload,
// signature, URLs or tokens.
type SignedProbeTargetManifest struct {
	keyID     string
	payload   *redactedProbeURL
	signature []byte
}

func NewSignedProbeTargetManifest(keyID string, payload, signature []byte) (*SignedProbeTargetManifest, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || len(keyID) > 128 || strings.ContainsAny(keyID, "\r\n\t") || len(payload) == 0 || len(payload) > maxSignedProbeManifestBytes || len(signature) != ed25519.SignatureSize {
		return nil, ErrProbeTargetUntrusted
	}
	return &SignedProbeTargetManifest{
		keyID: keyID, payload: &redactedProbeURL{value: string(append([]byte(nil), payload...))}, signature: append([]byte(nil), signature...),
	}, nil
}

func (*SignedProbeTargetManifest) String() string   { return "<redacted-probe-manifest>" }
func (*SignedProbeTargetManifest) GoString() string { return "<redacted-probe-manifest>" }
func (*SignedProbeTargetManifest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<redacted-probe-manifest>")
}
func (*SignedProbeTargetManifest) MarshalJSON() ([]byte, error) {
	return []byte(`"<redacted-probe-manifest>"`), nil
}

type signedProbeManifestWire struct {
	SourceID   string                  `json:"source_id"`
	ServiceID  string                  `json:"service_id"`
	Generation uint64                  `json:"generation"`
	IssuedAt   int64                   `json:"issued_at"`
	ExpiresAt  int64                   `json:"expires_at"`
	Targets    []signedProbeTargetWire `json:"targets"`
}

type signedProbeTargetWire struct {
	URL            string          `json:"url"`
	Capability     ProbeCapability `json:"capability"`
	RangeStart     *int64          `json:"range_start,omitempty"`
	RangeEnd       *int64          `json:"range_end,omitempty"`
	ExpectedDigest string          `json:"expected_digest,omitempty"`
	RedirectHosts  []string        `json:"redirect_hosts,omitempty"`
}

// ProbeManifestTarget is the publisher-side representation. URL and digest
// are intentionally omitted from String/JSON helpers on the signed result;
// callers should load this structure from a mode-0600 control-plane file.
type ProbeManifestTarget struct {
	URL            string          `json:"url"`
	Capability     ProbeCapability `json:"capability"`
	RangeStart     *int64          `json:"range_start,omitempty"`
	RangeEnd       *int64          `json:"range_end,omitempty"`
	ExpectedDigest string          `json:"expected_digest,omitempty"`
	RedirectHosts  []string        `json:"redirect_hosts,omitempty"`
}

type ProbeManifestPayload struct {
	SourceID   string                `json:"source_id"`
	ServiceID  string                `json:"service_id"`
	Generation uint64                `json:"generation"`
	IssuedAt   time.Time             `json:"issued_at"`
	ExpiresAt  time.Time             `json:"expires_at"`
	Targets    []ProbeManifestTarget `json:"targets"`
}

// PublishedProbeManifest is safe to pass through logging and error paths: all
// fmt and JSON representations are redacted. Payload is only exposed through
// WriteHTTP for the dedicated TLS control-plane handler.
type PublishedProbeManifest struct {
	keyID     string
	payload   []byte
	signature []byte
}

func (*PublishedProbeManifest) String() string   { return "<redacted-published-probe-manifest>" }
func (*PublishedProbeManifest) GoString() string { return "<redacted-published-probe-manifest>" }
func (*PublishedProbeManifest) MarshalJSON() ([]byte, error) {
	return []byte(`"<redacted-published-probe-manifest>"`), nil
}
func (*PublishedProbeManifest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<redacted-published-probe-manifest>")
}

func PublishProbeManifest(keyID string, privateKey ed25519.PrivateKey, spec ProbeManifestPayload) (*PublishedProbeManifest, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || len(keyID) > 128 || strings.ContainsAny(keyID, "\r\n\t") || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrProbeTargetUntrusted
	}
	if spec.SourceID == "" {
		spec.SourceID = YouTubeTargetSourceID
	}
	if spec.ServiceID == "" {
		spec.ServiceID = YouTubeProbeServiceID
	}
	if spec.SourceID != YouTubeTargetSourceID || spec.ServiceID != YouTubeProbeServiceID || spec.Generation == 0 || spec.IssuedAt.IsZero() || !spec.ExpiresAt.After(spec.IssuedAt) || len(spec.Targets) == 0 {
		return nil, ErrProbeTargetUntrusted
	}
	wire := signedProbeManifestWire{SourceID: spec.SourceID, ServiceID: spec.ServiceID, Generation: spec.Generation, IssuedAt: spec.IssuedAt.Unix(), ExpiresAt: spec.ExpiresAt.Unix(), Targets: make([]signedProbeTargetWire, len(spec.Targets))}
	for index, targetSpec := range spec.Targets {
		wire.Targets[index] = signedProbeTargetWire(targetSpec)
		// Reuse the consumer validation before signing so the publisher cannot
		// produce a structurally valid but unusable generation.
		var byteRange *ProbeByteRange
		if targetSpec.RangeStart != nil || targetSpec.RangeEnd != nil {
			if targetSpec.RangeStart == nil || targetSpec.RangeEnd == nil {
				return nil, ErrProbeTargetUntrusted
			}
			byteRange = &ProbeByteRange{Start: *targetSpec.RangeStart, End: *targetSpec.RangeEnd}
		}
		var digest []byte
		if targetSpec.ExpectedDigest != "" {
			decoded, err := hex.DecodeString(targetSpec.ExpectedDigest)
			if err != nil {
				return nil, ErrProbeTargetUntrusted
			}
			digest = decoded
		}
		target, err := NewProbeTarget(targetSpec.URL, spec.Generation, targetSpec.Capability, spec.IssuedAt, spec.ExpiresAt, byteRange, digest)
		if err != nil {
			return nil, ErrProbeTargetUntrusted
		}
		if _, err = target.WithRedirectHosts(targetSpec.RedirectHosts...); err != nil {
			return nil, ErrProbeTargetUntrusted
		}
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) == 0 || len(payload) > maxSignedProbeManifestBytes {
		return nil, ErrProbeTargetUntrusted
	}
	return &PublishedProbeManifest{keyID: keyID, payload: payload, signature: ed25519.Sign(privateKey, payload)}, nil
}

func (m *PublishedProbeManifest) WriteHTTP(header map[string][]string, writer io.Writer) error {
	if m == nil || len(m.payload) == 0 || len(m.signature) != ed25519.SignatureSize || writer == nil {
		return ErrProbeTargetUntrusted
	}
	header["Content-Type"] = []string{"application/json"}
	header["Cache-Control"] = []string{"no-store"}
	header[ProbeManifestKeyIDHeader] = []string{m.keyID}
	header[ProbeManifestSignatureHeader] = []string{base64.RawURLEncoding.EncodeToString(m.signature)}
	_, err := writer.Write(m.payload)
	return err
}

func (m *SignedProbeTargetManifest) verifyAndDecode(keyring map[string]ed25519.PublicKey, now time.Time) (*ProbeTargetSnapshot, error) {
	if m == nil || m.payload == nil || len(m.signature) != ed25519.SignatureSize {
		return nil, ErrProbeTargetUntrusted
	}
	publicKey := keyring[m.keyID]
	payload := []byte(m.payload.value)
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payload, m.signature) {
		return nil, ErrProbeTargetUntrusted
	}
	var wire signedProbeManifestWire
	decoder := json.NewDecoder(strings.NewReader(m.payload.value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, ErrProbeTargetUntrusted
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrProbeTargetUntrusted
	}
	if wire.SourceID != youtubeTargetSourceID || wire.ServiceID != youtubeProbeServiceID || wire.Generation == 0 || len(wire.Targets) == 0 {
		return nil, ErrProbeTargetUntrusted
	}
	issuedAt := time.Unix(wire.IssuedAt, 0)
	expiresAt := time.Unix(wire.ExpiresAt, 0)
	if wire.IssuedAt <= 0 || wire.ExpiresAt <= wire.IssuedAt || now.Before(issuedAt) || expiresAt.Sub(now) < minimumProbeTargetValidity {
		return nil, ErrProbeTargetExpired
	}
	targets := make([]ProbeTarget, 0, len(wire.Targets))
	for _, encoded := range wire.Targets {
		var byteRange *ProbeByteRange
		if encoded.RangeStart != nil || encoded.RangeEnd != nil {
			if encoded.RangeStart == nil || encoded.RangeEnd == nil {
				return nil, ErrProbeTargetUntrusted
			}
			byteRange = &ProbeByteRange{Start: *encoded.RangeStart, End: *encoded.RangeEnd}
		}
		var digest []byte
		if encoded.ExpectedDigest != "" {
			decoded, err := hex.DecodeString(encoded.ExpectedDigest)
			if err != nil {
				return nil, ErrProbeTargetUntrusted
			}
			digest = decoded
		}
		target, err := NewProbeTarget(encoded.URL, wire.Generation, encoded.Capability, issuedAt, expiresAt, byteRange, digest)
		if err != nil {
			return nil, ErrProbeTargetUntrusted
		}
		if len(encoded.RedirectHosts) > 0 {
			target, err = target.WithRedirectHosts(encoded.RedirectHosts...)
			if err != nil {
				return nil, ErrProbeTargetUntrusted
			}
		}
		targets = append(targets, target)
	}
	snapshot, err := NewProbeTargetSnapshot(wire.SourceID, wire.ServiceID, wire.Generation, issuedAt, expiresAt, targets)
	if err != nil {
		if errors.Is(err, ErrProbeTargetExpired) {
			return nil, err
		}
		return nil, ErrProbeTargetUntrusted
	}
	return snapshot, nil
}

func cloneProbeTargetKeyring(source map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	if len(source) == 0 {
		return nil, ErrProbeTargetUntrusted
	}
	cloned := make(map[string]ed25519.PublicKey, len(source))
	for keyID, publicKey := range source {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" || len(keyID) > 128 || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrProbeTargetUntrusted
		}
		cloned[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return cloned, nil
}
