//go:build !smart_policy_zig

package group

import "testing"

func TestProductionSmartPolicyHasSingleGoOwner(t *testing.T) {
	if smartPolicyBackendRequired() {
		t.Fatal("production Smart must not require a second policy backend")
	}
	if backend := newSmartPolicyBackend(smartPolicyBackendConfig{}); backend != nil {
		t.Fatal("production Smart unexpectedly created an external policy state owner")
	}
}
