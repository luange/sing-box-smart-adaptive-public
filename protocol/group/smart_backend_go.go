//go:build !smart_zig && !production_smart

package group

// The reference Go state machine is kept for ordinary upstream development and
// conformance tests. Packaged releases add smart_zig; production_smart is an
// explicit fail-closed profile used to prove that a missing Zig library cannot
// silently select through this duplicate policy implementation.
func newSmartPolicyBackend(_ smartPolicyBackendConfig) smartPolicyBackend { return nil }

// Non-production builds remain useful on platforms where the Zig ABI is not
// available. Release workflows reject this profile before packaging.
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
