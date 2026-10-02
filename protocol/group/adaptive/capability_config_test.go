package adaptive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

type capabilityConfigOutboundManager struct{ adapter.OutboundManager }

func TestParseCapabilityTrustedKeysIsStrictAndCopies(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := map[string]string{"rotation-a": base64.RawURLEncoding.EncodeToString(publicKey)}
	expected := append([]byte(nil), publicKey...)
	keys, err := parseCapabilityTrustedKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for index := range publicKey {
		publicKey[index] = 0
	}
	encoded["rotation-a"] = "changed"
	if !bytes.Equal(keys["rotation-a"], expected) {
		t.Fatal("parsed capability trust root was not independently owned")
	}
	for _, invalid := range []map[string]string{
		nil,
		{"key": "not-base64"},
		{"key": base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))},
		{"": base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))},
	} {
		if _, err = parseCapabilityTrustedKeys(invalid); err == nil {
			t.Fatalf("invalid capability keyring was accepted: %+v", invalid)
		}
	}
}

func TestAdaptivePoolCapabilityConfigIsExplicitAndDoesNotFetchDuringNew(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options := option.AdaptivePoolOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"node"}},
		State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "adaptive-state")},
		Capability: option.AdaptivePoolCapabilityOptions{
			Enabled: true, ManifestURL: "https://control.example.test/manifest",
			TrustedKeys:     map[string]string{"key-a": base64.RawURLEncoding.EncodeToString(publicKey)},
			RefreshInterval: badoption.Duration(time.Minute), Timeout: badoption.Duration(time.Second), Quorum: 2, CommonModeMinNodes: 2,
		},
	}
	if err = os.WriteFile(string(options.State.Path)+".json", []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &capabilityConfigOutboundManager{})
	outbound, err := New(ctx, nil, nil, "configured", options)
	if err != nil {
		t.Fatal(err)
	}
	pool := outbound.(*AdaptivePool)
	defer pool.Close()
	if pool.capabilityProvider == nil || len(pool.capabilityControllers) != 0 {
		t.Fatal("valid capability config fetched or started before publish")
	}
	if pool.stateWriter != nil {
		t.Fatal("configuration construction started the state writer before runtime Start")
	}
	if pool.statePersistenceFailures.Load() != 1 {
		t.Fatalf("corrupt state blocked New or was not reported: %d", pool.statePersistenceFailures.Load())
	}

	for _, invalid := range []option.AdaptivePoolCapabilityOptions{
		{Enabled: true, TrustedKeys: options.Capability.TrustedKeys},
		{Enabled: true, ManifestURL: "http://control.example.test/manifest", TrustedKeys: options.Capability.TrustedKeys},
		{Enabled: true, ManifestURL: "https://control.example.test/manifest?token=secret", TrustedKeys: options.Capability.TrustedKeys},
		{Enabled: true, ManifestURL: options.Capability.ManifestURL},
		{Enabled: true, ManifestURL: options.Capability.ManifestURL, TrustedKeys: map[string]string{"key": "bad"}},
	} {
		invalidOptions := options
		invalidOptions.Capability = invalid
		if _, err = New(ctx, nil, nil, "invalid", invalidOptions); err == nil {
			t.Fatalf("invalid capability config was accepted: %+v", invalid)
		}
	}
}

func TestAdaptivePoolBuiltinYouTubeTLSCapabilityNeedsNoManifest(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &capabilityConfigOutboundManager{})
	options := option.AdaptivePoolOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"node"}},
		State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "adaptive-state")},
		Capability: option.AdaptivePoolCapabilityOptions{
			Enabled: true, BuiltinYouTubeTLS: true,
			RefreshInterval: badoption.Duration(time.Minute), Timeout: badoption.Duration(time.Second), Quorum: 1, CommonModeMinNodes: 2,
		},
	}
	outbound, err := New(ctx, nil, nil, "builtin", options)
	if err != nil {
		t.Fatal(err)
	}
	pool := outbound.(*AdaptivePool)
	defer pool.Close()
	if _, loaded := pool.capabilityProvider.(*BuiltinYouTubeTLSTargetProvider); !loaded {
		t.Fatalf("builtin capability provider not configured: %T", pool.capabilityProvider)
	}

	options.Capability.ManifestURL = "https://control.example.test/manifest"
	if _, err = New(ctx, nil, nil, "ambiguous", options); err == nil {
		t.Fatal("builtin and manifest capability modes were accepted together")
	}
}

func TestAdaptivePoolBuiltinAIServiceCapabilityIsSealed(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &capabilityConfigOutboundManager{})
	options := option.AdaptivePoolOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"node"}},
		State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "adaptive-state")},
		Capability: option.AdaptivePoolCapabilityOptions{
			Enabled: true, BuiltinAIServiceTLS: true,
			RefreshInterval: badoption.Duration(time.Minute), Timeout: badoption.Duration(time.Second), Quorum: 1, CommonModeMinNodes: 2,
		},
	}
	if _, err := New(ctx, nil, nil, "builtin-ai", options); err == nil {
		t.Fatal("sealed builtin_ai_service_tls was accepted")
	}
	if _, err := NewBuiltinCapabilityTargetProvider(nil, false, true, false); err == nil {
		t.Fatal("sealed AI builtin provider was constructed")
	}
}

func TestAdaptivePoolBuiltinExitIdentityConfiguresProcessStore(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &capabilityConfigOutboundManager{})
	options := option.AdaptivePoolOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"node"}},
		State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "adaptive-state")},
		Capability: option.AdaptivePoolCapabilityOptions{
			Enabled: true, BuiltinExitIdentity: true,
			RefreshInterval: badoption.Duration(time.Minute), Timeout: badoption.Duration(time.Second), Quorum: 1, CommonModeMinNodes: 2,
		},
	}
	outbound, err := New(ctx, nil, nil, "builtin-exit-identity", options)
	if err != nil {
		t.Fatal(err)
	}
	pool := outbound.(*AdaptivePool)
	defer pool.Close()
	if pool.exitIdentityStore == nil || len(pool.capabilityServiceIDs) != 2 || pool.capabilityServiceIDs[0] != "exit_identity_v4" || pool.capabilityServiceIDs[1] != "exit_identity_v6" {
		t.Fatalf("exit identity capability was not configured: services=%v store=%v", pool.capabilityServiceIDs, pool.exitIdentityStore)
	}
}

func TestAdaptivePoolAIIPv6PolicyIsExplicit(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &capabilityConfigOutboundManager{})
	options := option.AdaptivePoolOutboundOptions{
		GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"node"}},
		State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "adaptive-state")},
		Policy:            option.AdaptivePoolPolicyOptions{AIIPv6Policy: "block"},
	}
	outbound, err := New(ctx, nil, nil, "ai-ipv6-policy", options)
	if err != nil {
		t.Fatal(err)
	}
	pool := outbound.(*AdaptivePool)
	defer pool.Close()
	if pool.aiIPv6Policy != "block" {
		t.Fatalf("unexpected AI IPv6 policy: %s", pool.aiIPv6Policy)
	}
	options.Policy.AIIPv6Policy = "prefer-v4"
	if _, err = New(ctx, nil, nil, "invalid-ai-ipv6-policy", options); err == nil {
		t.Fatal("invalid AI IPv6 policy was accepted")
	}
}
