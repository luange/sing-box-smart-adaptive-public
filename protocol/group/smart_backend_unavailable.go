//go:build production_smart && !smart_zig

package group

// A production_smart build without smart_zig must not silently run the
// duplicate Go policy path. Smart remains buildable for tooling, but
// constructing a Smart outbound fails closed with a clear production error.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

func smartPolicyBackendRequired() bool { return true }

func smartPolicyBackendName() string { return "unavailable" }

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
