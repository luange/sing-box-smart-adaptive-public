//go:build smart_zig && !cgo

package group

// A smart_zig build without cgo cannot link the Zig ABI. Keep this variant
// compileable so tooling can inspect the package, but fail Smart construction
// rather than silently selecting through the duplicate Go policy backend.
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
