package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestResolveSelectionRecordPrefersDialIdentity(t *testing.T) {
	old := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK", identity: "path"}, dialIdentity: "dial-b"}
	other := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK #2", identity: "path"}, dialIdentity: "dial-a"}
	record := adapter.SelectedRecord{Version: 1, DisplayTag: "HK #2", EndpointIdentity: "path", DialIdentity: "dial-a"}
	if got := resolveSelectionRecord([]adapter.Outbound{old, other}, record); got != other {
		t.Fatalf("resolved %v, want dial identity candidate", got)
	}
}

func TestResolveSelectionRecordEndpointFallbackPrefersDisplayTag(t *testing.T) {
	first := &providerTestNode{tag: "HK", identity: "path"}
	second := &providerTestNode{tag: "HK #2", identity: "path"}
	record := adapter.SelectedRecord{Version: 1, DisplayTag: "HK #2", EndpointIdentity: "path"}
	if got := resolveSelectionRecord([]adapter.Outbound{first, second}, record); got != second {
		t.Fatalf("resolved %v, want display-tag alias", got)
	}
}

func TestResolveStickySessionRecordDoesNotFallbackAcrossCredentials(t *testing.T) {
	remaining := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK #2", identity: "path"}, dialIdentity: "dial-b"}
	record := adapter.SelectedRecord{Version: 1, DisplayTag: "HK", EndpointIdentity: "path", DialIdentity: "dial-a"}
	if got := resolveStickySessionRecord([]adapter.Outbound{remaining}, record); got != nil {
		t.Fatalf("sticky resolver migrated to another credential: %v", got)
	}
}

func TestResolveStickySessionRecordKeepsLegacyPathFallback(t *testing.T) {
	first := &providerTestNode{tag: "HK", identity: "path"}
	second := &providerTestNode{tag: "HK #2", identity: "path"}
	record := adapter.SelectedRecord{Version: 1, DisplayTag: "HK #2", EndpointIdentity: "path"}
	if got := resolveStickySessionRecord([]adapter.Outbound{first, second}, record); got != second {
		t.Fatalf("legacy sticky record resolved to %v, want display-tag alias", got)
	}
}

func TestSelectedRecordForOutboundKeepsOpaqueIdentities(t *testing.T) {
	node := &providerDialTestNode{providerTestNode: providerTestNode{tag: "HK #2", identity: "endpoint:path"}, dialIdentity: "dial:credential"}
	record := selectedRecordForOutbound(node)
	if record.Version != 1 || record.DisplayTag != node.tag || record.EndpointIdentity != node.identity || record.DialIdentity != node.dialIdentity {
		t.Fatalf("unexpected selected record: %+v", record)
	}
}
