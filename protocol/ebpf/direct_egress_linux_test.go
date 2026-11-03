//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
)

func TestSharedNetworkDirectTableNameIsConfigurationScoped(t *testing.T) {
	first := sharedNetworkDirectTableName("eth1", 0x53420002)
	if first == "" || len(first) > 64 {
		t.Fatalf("invalid DIRECT table name: %q", first)
	}
	if got := sharedNetworkDirectTableName("eth1", 0x53420002); got != first {
		t.Fatalf("DIRECT table name is not deterministic: %q != %q", got, first)
	}
	if got := sharedNetworkDirectTableName("eth2", 0x53420002); got == first {
		t.Fatalf("different interfaces share DIRECT table name: %q", got)
	}
	if got := sharedNetworkDirectTableName("eth1", 0x53420003); got == first {
		t.Fatalf("different marks share DIRECT table name: %q", got)
	}
}

func TestDirectEgressRuleMatchesFullSafetyContract(t *testing.T) {
	const mark = uint32(0x53420002)
	rule := &nftables.Rule{Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: directEgressIfname("eth1")},
		&expr.Masq{},
	}}
	if !directEgressRuleMatches(rule, mark, "eth1") {
		t.Fatal("exact DIRECT safety rule was rejected")
	}
	if directEgressRuleMatches(rule, mark+1, "eth1") {
		t.Fatal("wrong mark was accepted")
	}
	if directEgressRuleMatches(rule, mark, "eth2") {
		t.Fatal("wrong egress interface was accepted")
	}
	rule.Exprs[4] = &expr.Counter{}
	if directEgressRuleMatches(rule, mark, "eth1") {
		t.Fatal("non-masquerade terminal action was accepted")
	}
}
