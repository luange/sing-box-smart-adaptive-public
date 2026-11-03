//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestPromotedBypassEvictionPrefersExpiredThenSoonestExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	entries := map[netip.Addr]time.Time{
		netip.MustParseAddr("203.0.113.1"): now.Add(10 * time.Second),
		netip.MustParseAddr("203.0.113.2"): now.Add(30 * time.Second),
		netip.MustParseAddr("203.0.113.3"): now.Add(-time.Second),
	}
	evict, expired := promotedBypassEviction(entries, now)
	if evict != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("evict=%s want soonest live expiry", evict)
	}
	if len(expired) != 1 || expired[0] != netip.MustParseAddr("203.0.113.3") {
		t.Fatalf("expired=%v", expired)
	}
}

func TestVerdictPromoteBypassDefaultOnLearn(t *testing.T) {
	opts := verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "learn"})
	if !opts.promoteBypass {
		t.Fatal("promote_bypass should default true in learn mode")
	}
	if opts.ttl != 5*time.Minute {
		t.Fatalf("ttl default %v", opts.ttl)
	}
	f := false
	opts = verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "learn", PromoteBypass: &f})
	if opts.promoteBypass {
		t.Fatal("explicit false must win")
	}
	opts = verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "off"})
	if opts.promoteBypass {
		t.Fatal("off mode must not promote")
	}
}
