package group

import "testing"

// Every binary exposes the single Go policy owner in SmartStatus. Smart must
// not silently switch to a second policy implementation based on build tags.
func TestSmartPolicyBackendBuildContract(t *testing.T) {
	name := smartPolicyBackendName()
	if name != "go" {
		t.Fatalf("Smart policy owner = %q, want go", name)
	}
	if smartPolicyBackendRequired() {
		t.Fatal("Go Smart must not require an external policy backend")
	}
}
