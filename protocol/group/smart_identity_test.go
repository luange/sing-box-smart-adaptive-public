package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type smartIdentityProvider struct {
	adapter.Provider
	options map[string]option.Outbound
}

func (p *smartIdentityProvider) OutboundOption(tag string) (option.Outbound, bool) {
	value, ok := p.options[tag]
	return value, ok
}

func TestSmartProbeIdentitySharesCredentialVariants(t *testing.T) {
	provider := &smartIdentityProvider{options: map[string]option.Outbound{
		"node-1": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "one", "tls": map[string]any{"server_name": "edge.example"}}},
		"node-2": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "two", "tls": map[string]any{"server_name": "edge.example"}}},
		"node-3": {Type: "trojan", Options: map[string]any{"server": "other.example", "server_port": 443, "password": "two", "tls": map[string]any{"server_name": "other.example"}}},
	}}
	smart := &Smart{providers: map[string]adapter.Provider{"p": provider}}
	a := newSmartFakeOutbound("node-1", nil)
	b := newSmartFakeOutbound("node-2", nil)
	c := newSmartFakeOutbound("node-3", nil)
	if gotA, gotB := smart.probeIdentityLocked(a), smart.probeIdentityLocked(b); gotA != gotB {
		t.Fatalf("credential variants must share endpoint identity: %q != %q", gotA, gotB)
	}
	if gotA, gotC := smart.probeIdentityLocked(a), smart.probeIdentityLocked(c); gotA == gotC {
		t.Fatalf("different endpoints must not share identity: %q", gotA)
	}
}

func TestSmartDialIdentitySeparatesCredentialVariants(t *testing.T) {
	provider := &smartIdentityProvider{options: map[string]option.Outbound{
		"node-1": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "one", "tls": map[string]any{"server_name": "edge.example"}}},
		"node-2": {Type: "trojan", Options: map[string]any{"server": "edge.example", "server_port": 443, "password": "two", "tls": map[string]any{"server_name": "edge.example"}}},
	}}
	smart := &Smart{providers: map[string]adapter.Provider{"p": provider}}
	a := newSmartFakeOutbound("node-1", nil)
	b := newSmartFakeOutbound("node-2", nil)
	if gotA, gotB := smart.probeIdentityLocked(a), smart.probeIdentityLocked(b); gotA != gotB {
		t.Fatalf("credential variants must share path identity: %q != %q", gotA, gotB)
	}
	gotA, gotB := smart.dialIdentityLocked(a), smart.dialIdentityLocked(b)
	if gotA == "" || gotB == "" || gotA == gotB {
		t.Fatalf("credential variants must have distinct dial identities: %q == %q", gotA, gotB)
	}
}

func TestSmartMetadataAlwaysHasPolicyIdentity(t *testing.T) {
	smart := &Smart{}
	metadata := smart.buildCandidateMetadata("static-node", "")
	if metadata.policyID == 0 {
		t.Fatal("static candidates must be represented in the Zig policy snapshot")
	}
	if metadata.policyID != smartPolicyID("static-node") {
		t.Fatalf("static policy identity = %d, want hash of stable tag", metadata.policyID)
	}
	other := smart.buildCandidateMetadata("other-static-node", "")
	if metadata.probeKey == other.probeKey {
		t.Fatal("static candidates must not share one probe key")
	}
}

func TestDedupeSmartCandidatesByDialIdentity(t *testing.T) {
	first := newSmartFakeOutbound("provider-b/HK", nil)
	second := newSmartFakeOutbound("provider-a/HK", nil)
	third := newSmartFakeOutbound("provider-c/HK", nil)
	metadata := map[string]smartCandidateMetadata{
		first.Tag():  {identity: "path-1", dialIdentity: "dial-shared"},
		second.Tag(): {identity: "path-1", dialIdentity: "dial-shared"},
		third.Tag():  {identity: "path-2", dialIdentity: "dial-other"},
	}
	got, gotMetadata := dedupeSmartCandidates([]adapter.Outbound{first, second, third}, metadata)
	if len(got) != 2 {
		t.Fatalf("candidate count=%d, want 2", len(got))
	}
	if got[0].Tag() != second.Tag() {
		t.Fatalf("shared dial identity winner=%q, want lexicographically stable %q", got[0].Tag(), second.Tag())
	}
	if _, ok := gotMetadata[first.Tag()]; ok {
		t.Fatal("duplicate alias metadata must not remain in Smart catalog")
	}
	if _, ok := gotMetadata[third.Tag()]; !ok {
		t.Fatal("distinct dial identity was removed")
	}
}
