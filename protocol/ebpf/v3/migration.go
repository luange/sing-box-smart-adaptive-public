package v3

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	EngineV2 = "v2"
	EngineV3 = "v3"
)

// NormalizeSharedNetwork applies v3 defaults and validates engine selection.
// Unspecified engine keeps v2 (design §13 compatibility).
func NormalizeSharedNetwork(options option.EBPFSharedNetworkOptions) (option.EBPFSharedNetworkOptions, error) {
	engine := strings.TrimSpace(strings.ToLower(options.Engine))
	if options.XDP.Mode == "" {
		options.XDP.Mode = "auto"
	}
	switch strings.ToLower(strings.TrimSpace(options.XDP.Mode)) {
	case "auto", "skb", "native", "offload":
		options.XDP.Mode = strings.ToLower(strings.TrimSpace(options.XDP.Mode))
	default:
		return options, E.New("shared_network.xdp.mode must be auto|skb|native|offload")
	}
	if options.XDP.Enabled && engine != EngineV3 {
		return options, E.New("shared_network.xdp requires engine=v3")
	}
	switch engine {
	case "", EngineV2:
		options.Engine = EngineV2
		return options, nil
	case EngineV3:
		options.Engine = EngineV3
		// xdp.enabled is an explicit experimental opt-in: startup probes the
		// kernel/driver capability and only reports it. The AF_XDP host
		// adapter (umem/XSK rings) is not wired yet, so the live packet path
		// remains TC in this release; probing never affects forwarding.
	default:
		return options, E.New("shared_network.engine must be v2 or v3, got ", options.Engine)
	}

	// v3 defaults: socket_assign, no default QUIC drop, failure_mode=proxy.
	if options.DataPlane == "" {
		options.DataPlane = "socket_assign"
	}
	if options.DataPlane != "socket_assign" && options.DataPlane != "token" {
		return options, E.New("shared_network.data_plane must be socket_assign or token")
	}
	if options.Engine == EngineV3 && options.DataPlane != "socket_assign" {
		return options, E.New("shared_network.engine=v3 requires data_plane=socket_assign")
	}
	if options.FailureMode == "" {
		options.FailureMode = "proxy"
	}
	if options.FailureMode != "proxy" {
		return options, E.New("shared_network.failure_mode only supports proxy in v3")
	}
	if options.DropUDP443 == nil {
		// explicit default false
		f := false
		options.DropUDP443 = &f
	}
	po := options.PolicyOffload
	if po.DNSIPHint == "" {
		po.DNSIPHint = "safe"
	}
	switch po.DNSIPHint {
	case "off", "safe", "strong":
	default:
		return options, E.New("policy_offload.dns_ip_hint must be off|safe|strong")
	}
	// Keep the effective policy identical across the kernel constructor,
	// Lifecycle, and the in-process audit model.  An enabled block with no
	// sub-flags means "safe defaults" (static rules + exact-flow learning), as
	// documented by shared_network.Start.  Normalizing it here prevents the
	// kernel from learning flows that Lifecycle later refuses to mirror.
	if po.Enabled && !po.StaticRules && !po.ExactFlowLearning && !po.FakeIP && !po.MACSourcePolicy {
		po.StaticRules = true
		po.ExactFlowLearning = true
	}
	// When policy_offload block is present but enabled omitted, treat zero-value
	// as disabled unless any sub-feature is set by caller later. Explicit enabled
	// is required for production sinks.
	options.PolicyOffload = po
	return options, nil
}

// IsV3 reports whether shared_network should use the v3 engine.
func IsV3(options option.EBPFSharedNetworkOptions) bool {
	return strings.EqualFold(strings.TrimSpace(options.Engine), EngineV3)
}
