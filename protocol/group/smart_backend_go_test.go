package group

import "testing"

func TestProductionSmartPolicyHasSingleGoOwner(t *testing.T) {
	if smartPolicyBackendRequired() {
		t.Fatal("production Smart must not require a second policy backend")
	}
	if backend := newSmartPolicyBackend(smartPolicyBackendConfig{}); backend != nil {
		t.Fatal("Go Smart must not create a second policy state owner")
	}
	if name := smartPolicyBackendName(); name != "go" {
		t.Fatalf("Smart policy owner = %q, want go", name)
	}
}
