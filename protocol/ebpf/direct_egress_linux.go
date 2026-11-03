//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strings"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

const sharedNetworkDirectTablePrefix = "singbox_de"

type sharedNetworkDirectEgress struct {
	table *nftables.Table
	chain *nftables.Chain
	mark  uint32
	iface string
}

func sharedNetworkDirectTableName(interfaceName string, mark uint32) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(interfaceName))
	return fmt.Sprintf("%s_%08x_%08x", sharedNetworkDirectTablePrefix, mark, hash.Sum32())
}

func installSharedNetworkDirectEgress(interfaceName string, mark uint32, ipv4, ipv6 bool) (*sharedNetworkDirectEgress, error) {
	if mark == 0 || strings.TrimSpace(interfaceName) == "" {
		return nil, E.New("invalid DIRECT egress mark/interface")
	}
	if !ipv4 && !ipv6 {
		return nil, E.New("DIRECT egress has no enabled address family")
	}
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return nil, E.Cause(err, "find DIRECT egress interface")
	}
	if ipv4 {
		value, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(value)) != "1" {
			return nil, E.New("IPv4 forwarding is disabled; refusing unsafe kernel DIRECT")
		}
	}
	if ipv6 && hasDefaultRoute(unix.AF_INET6) {
		value, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if err != nil || strings.TrimSpace(string(value)) != "1" {
			return nil, E.New("IPv6 forwarding is disabled; refusing unsafe kernel DIRECT")
		}
	}
	nft, err := nftables.New()
	if err != nil {
		return nil, err
	}
	tableName := sharedNetworkDirectTableName(interfaceName, mark)
	if old, listErr := nft.ListTableOfFamily(tableName, nftables.TableFamilyINet); listErr == nil && old != nil {
		nft.DelTable(old)
		if err = nft.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
			return nil, E.Cause(err, "remove stale DIRECT egress table")
		}
	}
	table := nft.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
	chain := nft.AddChain(&nftables.Chain{
		Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: directEgressIfname(interfaceName)},
		&expr.Masq{},
	}})
	if err = nft.Flush(); err != nil {
		return nil, E.Cause(err, "install DIRECT egress masquerade")
	}
	return &sharedNetworkDirectEgress{table: table, chain: chain, mark: mark, iface: interfaceName}, nil
}

func (d *sharedNetworkDirectEgress) RuntimeInstalled() (bool, error) {
	if d == nil || d.table == nil || d.chain == nil {
		return false, nil
	}
	nft, err := nftables.New()
	if err != nil {
		return false, err
	}
	table, err := nft.ListTableOfFamily(d.table.Name, d.table.Family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if table == nil {
		return false, nil
	}
	rules, err := nft.GetRules(table, d.chain)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return len(rules) == 1 && directEgressRuleMatches(rules[0], d.mark, d.iface), nil
}

func directEgressRuleMatches(rule *nftables.Rule, mark uint32, interfaceName string) bool {
	if rule == nil || len(rule.Exprs) != 5 {
		return false
	}
	markMeta, ok := rule.Exprs[0].(*expr.Meta)
	if !ok || markMeta.Key != expr.MetaKeyMARK || markMeta.Register != 1 {
		return false
	}
	markCmp, ok := rule.Exprs[1].(*expr.Cmp)
	if !ok || markCmp.Op != expr.CmpOpEq || markCmp.Register != 1 ||
		!bytes.Equal(markCmp.Data, binaryutil.NativeEndian.PutUint32(mark)) {
		return false
	}
	ifaceMeta, ok := rule.Exprs[2].(*expr.Meta)
	if !ok || ifaceMeta.Key != expr.MetaKeyOIFNAME || ifaceMeta.Register != 1 {
		return false
	}
	ifaceCmp, ok := rule.Exprs[3].(*expr.Cmp)
	if !ok || ifaceCmp.Op != expr.CmpOpEq || ifaceCmp.Register != 1 ||
		!bytes.Equal(ifaceCmp.Data, directEgressIfname(interfaceName)) {
		return false
	}
	_, ok = rule.Exprs[4].(*expr.Masq)
	return ok
}

func directEgressIfname(name string) []byte {
	value := make([]byte, 16)
	copy(value, name)
	return value
}

func hasDefaultRoute(family int) bool {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return true // fail closed when the kernel route state cannot be read
	}
	for _, route := range routes {
		if route.Dst == nil {
			return true
		}
		if ones, _ := route.Dst.Mask.Size(); ones == 0 {
			return true
		}
	}
	return false
}

func (d *sharedNetworkDirectEgress) Close() error {
	if d == nil || d.table == nil {
		return nil
	}
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	nft.DelTable(d.table)
	if err = nft.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	d.table = nil
	d.chain = nil
	d.mark = 0
	d.iface = ""
	return nil
}
