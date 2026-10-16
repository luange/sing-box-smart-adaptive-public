package group

// The Go Smart implementation is the production policy owner. Keeping this
// constructor nil ensures selection, confirmation, cooldown, and incumbent
// state all remain in the Smart host rather than being mirrored in an ABI.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

// The adaptive_zig/smart_zig build tags are unrelated to Smart; they select
// only the separate adaptive/eBPF policy kernel.
func smartPolicyBackendRequired() bool { return false }

func smartPolicyBackendName() string { return "go" }

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
