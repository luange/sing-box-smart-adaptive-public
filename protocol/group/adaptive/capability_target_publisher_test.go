package adaptive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestPublishedProbeManifestRoundTripAndRedaction(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	manifest, err := PublishProbeManifest("rotation-7", privateKey, ProbeManifestPayload{
		Generation: 7,
		IssuedAt:   now.Add(-time.Minute),
		ExpiresAt:  now.Add(time.Hour),
		Targets:    []ProbeManifestTarget{{URL: "https://media.example.test/videoplayback?token=secret", Capability: ProbeCapabilityHTTP}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(manifest.String(), "media.example") {
		t.Fatal("published manifest leaked target")
	}
	header := make(map[string][]string)
	var payload bytes.Buffer
	if err = manifest.WriteHTTP(header, &payload); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(header[ProbeManifestSignatureHeader][0])
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := NewSignedProbeTargetManifest(header[ProbeManifestKeyIDHeader][0], payload.Bytes(), signature)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := consumer.verifyAndDecode(map[string]ed25519.PublicKey{"rotation-7": publicKey}, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 7 || len(snapshot.Targets()) != 1 {
		t.Fatalf("unexpected snapshot: generation=%d targets=%d", snapshot.Generation, len(snapshot.Targets()))
	}
}

func TestPublishProbeManifestRejectsInvalidRange(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	start := int64(0)
	_, err = PublishProbeManifest("key", privateKey, ProbeManifestPayload{
		Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []ProbeManifestTarget{{URL: "https://example.test/range", Capability: ProbeCapabilityRange, RangeStart: &start}},
	})
	if err == nil {
		t.Fatal("expected invalid range rejection")
	}
}
