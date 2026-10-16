//go:build !smart_policy_zig

package group

// The Go Smart implementation is the production policy owner. Keeping this
// constructor nil ensures selection, confirmation, cooldown, and incumbent
// state all remain in the Smart host rather than being mirrored in an ABI.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

// The Zig Smart experiment is opt-in with smart_policy_zig. The release tag
// smart_zig remains available to the independent adaptive/eBPF policy kernel.
func smartPolicyBackendRequired() bool { return false }

func smartPolicyBackendName() string { return "go-reference" }

type smartPolicyBackendConfig struct {
	Exploration          float64
	SwitchMargin         float64
	SwitchConfirm        int
	SwitchConfirmWindow  int64
	SwitchCooldown       int64
	SiteStickiness       int64
	SwitchMinImprovement int64
	SelectionMode        uint8
	MinSamples           int
}
