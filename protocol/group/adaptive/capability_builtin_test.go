package adaptive

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBuiltinYouTubeTLSTargetProviderIsStaticRedactedAndRefreshable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	provider, err := NewBuiltinYouTubeTLSTargetProvider(clock)
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := first.executionTargets(now)
	if err != nil || len(targets) != 1 {
		t.Fatalf("builtin target missing: targets=%d err=%v", len(targets), err)
	}
	if targets[0].Capability != ProbeCapabilityTLS || targets[0].executionURL() != "https://www.youtube.com/" {
		t.Fatalf("unexpected builtin target: %+v", targets[0].Descriptor())
	}
	if formatted := fmt.Sprintf("%+v %#v", first, targets[0]); strings.Contains(formatted, "youtube.com") {
		t.Fatalf("builtin execution host leaked through formatting: %s", formatted)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil || second.Generation != first.Generation {
		t.Fatalf("fresh builtin target was needlessly rotated: generation=%d err=%v", second.Generation, err)
	}
	if _, err = provider.Snapshot(context.Background(), "chatgpt"); !errorsIs(err, ErrProbeRunUnknown) {
		t.Fatalf("builtin provider crossed service boundary: %v", err)
	}
}

func TestBuiltinAIServiceTargetsRemainSealed(t *testing.T) {
	// AI service probe framework is sealed; construction must fail and auth_http
	// / web_waf cannot be reintroduced via NewProbeTarget either.
	if _, err := NewBuiltinAIServiceTLSTargetProvider(&fakeClock{now: time.Now()}); err == nil {
		t.Fatal("expected sealed builtin AI service provider construction to fail")
	}
	now := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	for _, capability := range []ProbeCapability{ProbeCapabilityAuthHTTP, ProbeCapabilityWebWAF} {
		if _, err := NewProbeTarget("https://api.example.test/v1", 1, capability, now.Add(-time.Minute), now.Add(time.Hour), nil, nil); err == nil {
			t.Fatalf("sealed capability %q must be rejected at construct", capability)
		}
	}
}

func TestBuiltinExitIdentityCanShareBuiltinProvider(t *testing.T) {
	now := time.Date(2026, time.July, 28, 0, 0, 0, 0, time.UTC)
	provider, err := NewBuiltinCapabilityTargetProvider(&fakeClock{now: now}, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := provider.ServiceIDs(); len(got) != 3 || got[0] != "youtube" || got[1] != "exit_identity_v4" || got[2] != "exit_identity_v6" {
		t.Fatalf("unexpected builtin services: %v", got)
	}
	for _, serviceID := range []string{"exit_identity_v4", "exit_identity_v6"} {
		snapshot, err := provider.Snapshot(context.Background(), serviceID)
		if err != nil {
			t.Fatal(err)
		}
		targets, err := snapshot.executionTargets(now)
		if err != nil || len(targets) != 1 || targets[0].Capability != ProbeCapabilityExitIdentity {
			t.Fatalf("unexpected exit identity target: service=%s targets=%+v err=%v", serviceID, targets, err)
		}
		if formatted := fmt.Sprintf("%+v %#v", snapshot, targets[0]); strings.Contains(formatted, "ipify") {
			t.Fatalf("exit identity endpoint leaked through formatting: %s", formatted)
		}
	}
}
