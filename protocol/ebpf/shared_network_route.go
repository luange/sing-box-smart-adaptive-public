//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

const sharedNetworkRulePriority = 9000

type sharedNetworkPolicyRoute struct {
	rules  []netlink.Rule
	routes []netlink.Route
}

func installSharedNetworkPolicyRoute(mark uint32, table uint32, ipv4, ipv6 bool) (*sharedNetworkPolicyRoute, error) {
	if mark == 0 || table == 0 || table > 1<<31-1 {
		return nil, E.New("invalid shared-network policy route")
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, E.Cause(err, "find loopback for shared-network policy route")
	}
	result := &sharedNetworkPolicyRoute{}
	cleanup := func(startErr error) (*sharedNetworkPolicyRoute, error) {
		return nil, E.Errors(startErr, result.Close())
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if (family == unix.AF_INET && !ipv4) || (family == unix.AF_INET6 && !ipv6) {
			continue
		}
		rule := netlink.NewRule()
		rule.Family = family
		rule.Priority = sharedNetworkRulePriority
		rule.Table = int(table)
		rule.Mark = mark
		rule.MarkSet = true
		rule.Mask = int(^uint32(0))
		ruleExists, ruleErr := sharedNetworkPolicyRuleExists(*rule)
		if ruleErr != nil {
			return cleanup(ruleErr)
		}
		if !ruleExists {
			if err = netlink.RuleAdd(rule); err != nil {
				if !errors.Is(err, unix.EEXIST) {
					return cleanup(E.Cause(err, "add shared-network policy rule"))
				}
				if err = verifySharedNetworkPolicyRule(*rule); err != nil {
					return cleanup(err)
				}
			} else {
				result.rules = append(result.rules, *rule)
			}
		}
		prefix := netip.MustParsePrefix("0.0.0.0/0")
		if family == unix.AF_INET6 {
			prefix = netip.MustParsePrefix("::/0")
		}
		route := netlink.Route{
			LinkIndex: loopback.Attrs().Index,
			Family:    family,
			Dst:       &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(0, prefix.Addr().BitLen())},
			Scope:     netlink.Scope(unix.RT_SCOPE_HOST),
			Table:     int(table),
			Type:      unix.RTN_LOCAL,
		}
		routeExists, routeErr := sharedNetworkLocalRouteExists(route)
		if routeErr != nil {
			return cleanup(routeErr)
		}
		if !routeExists {
			if err = netlink.RouteAdd(&route); err != nil {
				if !errors.Is(err, unix.EEXIST) {
					return cleanup(E.Cause(err, "add shared-network local route"))
				}
				if err = verifySharedNetworkLocalRoute(route); err != nil {
					return cleanup(err)
				}
			} else {
				result.routes = append(result.routes, route)
			}
		}
	}
	return result, nil
}

func sharedNetworkPolicyRuleExists(expected netlink.Rule) (bool, error) {
	rules, err := netlink.RuleList(expected.Family)
	if err != nil {
		return false, E.Cause(err, "list shared-network policy rules")
	}
	found := false
	for _, current := range rules {
		if current.Priority != expected.Priority {
			continue
		}
		if current.Table == expected.Table && current.Mark == expected.Mark && current.Mask == expected.Mask {
			found = true
			continue
		}
		return false, E.New("shared-network policy rule priority ", expected.Priority,
			" is already owned by incompatible state: current={table:", current.Table,
			", mark:", current.Mark, ", mark_set:", current.MarkSet, ", mask:", current.Mask,
			"}, expected={table:", expected.Table, ", mark:", expected.Mark, ", mask:", expected.Mask, "}")
	}
	return found, nil
}

func sharedNetworkLocalRouteExists(expected netlink.Route) (bool, error) {
	routes, err := netlink.RouteListFiltered(expected.Family, &netlink.Route{Table: expected.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, E.Cause(err, "list shared-network routing table")
	}
	found := false
	for _, current := range routes {
		if current.Table == expected.Table && current.LinkIndex == expected.LinkIndex &&
			current.Type == expected.Type && compatibleLocalRouteScope(current.Scope, expected.Scope) && equalIPNet(current.Dst, expected.Dst) {
			found = true
			continue
		}
		return false, E.New("shared-network routing table ", expected.Table,
			" is already owned by incompatible state: current={link:", current.LinkIndex,
			", type:", current.Type, ", scope:", current.Scope, ", dst:", current.Dst,
			"}, expected={link:", expected.LinkIndex, ", type:", expected.Type,
			", scope:", expected.Scope, ", dst:", expected.Dst, "}")
	}
	return found, nil
}

func verifySharedNetworkPolicyRule(expected netlink.Rule) error {
	rules, err := netlink.RuleList(expected.Family)
	if err != nil {
		return E.Cause(err, "list colliding shared-network policy rules")
	}
	for _, current := range rules {
		if current.Priority == expected.Priority && current.Table == expected.Table &&
			current.Mark == expected.Mark && current.Mask == expected.Mask {
			return nil
		}
	}
	return E.New("shared-network policy rule priority ", expected.Priority, " is already owned by incompatible state")
}

func verifySharedNetworkLocalRoute(expected netlink.Route) error {
	routes, err := netlink.RouteListFiltered(
		expected.Family,
		&netlink.Route{Table: expected.Table},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return E.Cause(err, "list colliding shared-network local routes")
	}
	for _, current := range routes {
		if current.Table == expected.Table && current.LinkIndex == expected.LinkIndex &&
			current.Type == expected.Type && compatibleLocalRouteScope(current.Scope, expected.Scope) &&
			equalIPNet(current.Dst, expected.Dst) {
			return nil
		}
	}
	return E.New("shared-network routing table ", expected.Table, " is already owned by incompatible state")
}

func compatibleLocalRouteScope(current netlink.Scope, expected netlink.Scope) bool {
	return current == expected || (expected == netlink.Scope(unix.RT_SCOPE_HOST) && current == netlink.Scope(unix.RT_SCOPE_UNIVERSE))
}

func equalIPNet(left *net.IPNet, right *net.IPNet) bool {
	if left == nil || right == nil {
		return (left == nil && isDefaultIPNet(right)) || (right == nil && isDefaultIPNet(left))
	}
	return left.IP.Equal(right.IP) && string(left.Mask) == string(right.Mask)
}

func isDefaultIPNet(value *net.IPNet) bool {
	if value == nil {
		return true
	}
	ones, _ := value.Mask.Size()
	return ones == 0 && value.IP.IsUnspecified()
}

func (r *sharedNetworkPolicyRoute) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	for index := len(r.routes) - 1; index >= 0; index-- {
		if err := netlink.RouteDel(&r.routes[index]); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	for index := len(r.rules) - 1; index >= 0; index-- {
		if err := netlink.RuleDel(&r.rules[index]); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	if closeErr == nil {
		r.routes = nil
		r.rules = nil
	}
	return closeErr
}
