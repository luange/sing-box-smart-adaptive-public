package group

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

const groupPassiveFailureTTL = 30 * time.Second

// groupProfileIdentity separates the credential-sensitive observation key
// from the credential-free endpoint admission key. Probes for credentials on
// one physical path are serialized, while their health results never merge.
func groupProfileIdentity(outbound adapter.Outbound) (endpointKey, dialKey string) {
	record := selectedRecordForOutbound(outbound)
	endpointKey = record.EndpointIdentity
	if endpointKey == "" {
		endpointKey = record.DialIdentity
	}
	if endpointKey == "" {
		endpointKey = record.DisplayTag
	}
	dialKey = record.DialIdentity
	if dialKey == "" {
		dialKey = endpointKey
	}
	return
}

func groupTCPProfileKeyForIdentity(dialKey, link, network string) string {
	network = canonicalTCPNetwork(network)
	return nodeProfileKey(dialKey, link+"\x00"+network, 0)
}

func canonicalTCPNetwork(network string) string {
	switch network {
	case "tcp4", "tcp/ipv4":
		return "tcp/ipv4"
	case "tcp6", "tcp/ipv6":
		return "tcp/ipv6"
	case "", N.NetworkTCP:
		return N.NetworkTCP
	default:
		// Do not silently project an invalid transport onto generic TCP. The
		// distinct namespace makes an accidental caller visible and prevents
		// cross-transport health-state aliasing.
		return "invalid/" + network
	}
}

func isTCPFamily(network string) bool {
	switch network {
	case "", N.NetworkTCP, "tcp4", "tcp6", "tcp/ipv4", "tcp/ipv6":
		return true
	default:
		return false
	}
}

func groupTCPProfileKey(outbound adapter.Outbound, link string, network ...string) (endpointKey, profileKey string) {
	endpointKey, dialKey := groupProfileIdentity(outbound)
	profileNetwork := N.NetworkTCP
	if len(network) > 0 && network[0] != "" {
		profileNetwork = canonicalTCPNetwork(network[0])
	}
	return endpointKey, groupTCPProfileKeyForIdentity(dialKey, link, profileNetwork)
}

func groupUDPProfileKey(outbound adapter.Outbound) string {
	_, dialKey := groupProfileIdentity(outbound)
	return nodeProfileKey(dialKey, "passive\x00"+N.NetworkUDP, 0)
}

func groupTCPPassiveProfileKey(outbound adapter.Outbound, network ...string) string {
	_, dialKey := groupProfileIdentity(outbound)
	profileNetwork := N.NetworkTCP
	if len(network) > 0 {
		profileNetwork = canonicalTCPNetwork(network[0])
	}
	return nodeProfileKey(dialKey, "passive\x00"+profileNetwork, 0)
}

func groupProfileBaselineAlive(registry *nodeProfileRegistry, outbound adapter.Outbound, link string, window time.Duration, network ...string) bool {
	result, loaded := groupTCPProfileSnapshot(registry, outbound, link, network...)
	if !loaded || !result.success {
		return false
	}
	if window > 0 && time.Since(result.completedAt) >= window {
		return false
	}
	return true
}

func groupProfileAlive(registry *nodeProfileRegistry, outbound adapter.Outbound, link string, window time.Duration, network ...string) bool {
	if !groupProfileBaselineAlive(registry, outbound, link, window, network...) {
		return false
	}
	return groupTransportAvailable(registry, outbound, firstNetwork(network))
}

func firstNetwork(network []string) string {
	if len(network) == 0 {
		return N.NetworkTCP
	}
	return network[0]
}

func groupTransportAvailable(registry *nodeProfileRegistry, outbound adapter.Outbound, network string) bool {
	if N.NetworkName(network) == N.NetworkUDP {
		return groupUDPAvailable(registry, outbound)
	}
	return groupTCPAvailable(registry, outbound, network)
}

func groupTCPAvailable(registry *nodeProfileRegistry, outbound adapter.Outbound, network ...string) bool {
	return registry == nil || !registry.passiveFailureActive(groupTCPPassiveProfileKey(outbound, network...))
}

func groupTCPProfileSnapshot(registry *nodeProfileRegistry, outbound adapter.Outbound, link string, network ...string) (nodeProfileResult, bool) {
	if registry == nil {
		return nodeProfileResult{}, false
	}
	if len(network) > 0 && isTCPFamily(network[0]) && canonicalTCPNetwork(network[0]) != N.NetworkTCP {
		_, familyKey := groupTCPProfileKey(outbound, link, network[0])
		if result, loaded := registry.snapshot(familyKey); loaded {
			return result, true
		}
	}
	_, key := groupTCPProfileKey(outbound, link)
	return registry.snapshot(key)
}

func groupUDPAvailable(registry *nodeProfileRegistry, outbound adapter.Outbound) bool {
	return registry == nil || !registry.passiveFailureActive(groupUDPProfileKey(outbound))
}
