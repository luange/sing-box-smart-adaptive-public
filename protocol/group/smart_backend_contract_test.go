package group

import "testing"

// Every binary exposes its policy ownership in SmartStatus. This contract
// prevents a release build from silently changing from the Zig kernel to the
// duplicate Go selector when cgo, the static library, or an ABI changes.
func TestSmartPolicyBackendBuildContract(t *testing.T) {
	name := smartPolicyBackendName()
	if name == "" {
		t.Fatal("Smart policy backend name is empty")
	}
	if smartPolicyBackendRequired() && name == "go-reference" {
		t.Fatalf("required Smart build selected the Go reference backend: %q", name)
	}
	if !smartPolicyBackendRequired() && name != "go-reference" {
		t.Fatalf("optional Smart build selected unexpected backend %q", name)
	}
}

// The Zig kernel must keep exposing prune/adopt/observe as interface
// implementations, not just ABI exports: a refactor that drops one of these
// methods would turn provider refreshes and dial confirmations into silent
// no-ops while compile and existing tests stay green.
func TestSmartPolicyBackendImplementsLifecycle(t *testing.T) {
	backend := newSmartPolicyBackend(smartPolicyBackendConfig{})
	if backend == nil {
		t.Skip("no policy backend in this build")
	}
	if _, ok := backend.(smartPolicyIncumbent); !ok {
		t.Fatal("policy backend lost smartPolicyIncumbent (SetSelected)")
	}
	if _, ok := backend.(smartPolicyAdopter); !ok {
		t.Fatal("policy backend lost smartPolicyAdopter (AdoptSelected)")
	}
	if _, ok := backend.(smartPolicyPruner); !ok {
		t.Fatal("policy backend lost smartPolicyPruner (Prune)")
	}
}
