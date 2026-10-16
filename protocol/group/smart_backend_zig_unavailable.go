//go:build smart_policy_zig && !cgo

package group

// A smart_policy_zig build without cgo cannot link the Zig ABI. Keep this
// opt-in experiment compileable, but fail Smart construction rather than
// silently mixing it with the Go policy owner.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

func smartPolicyBackendRequired() bool { return true }

func smartPolicyBackendName() string { return "zig-unavailable" }

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
