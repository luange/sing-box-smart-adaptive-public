package v3

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestNormalizeXDPDefaultsToAuto(t *testing.T) {
	got, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{Engine: EngineV3})
	if err != nil {
		t.Fatal(err)
	}
	if got.XDP.Mode != "auto" {
		t.Fatalf("xdp mode = %q, want auto", got.XDP.Mode)
	}
}

func TestNormalizeXDPRejectsV2(t *testing.T) {
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Engine: EngineV2,
		XDP:    option.EBPFXDPOptions{Enabled: true},
	})
	if err == nil {
		t.Fatal("xdp enabled on v2 must be rejected")
	}
}

func TestNormalizeXDPRejectsUnknownMode(t *testing.T) {
	_, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Engine: EngineV3,
		XDP:    option.EBPFXDPOptions{Mode: "driver"},
	})
	if err == nil {
		t.Fatal("unknown xdp mode must be rejected")
	}
}

func TestNormalizeXDPAcceptsEnabledAsExperimental(t *testing.T) {
	o, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Engine: EngineV3,
		XDP:    option.EBPFXDPOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	// xdp.enabled is now an experimental opt-in: startup probes hardware
	// capability and reports it while the TC dataplane stays live.
	if !o.XDP.Enabled {
		t.Fatal("xdp.enabled must survive normalization")
	}
}

func TestNormalizePolicyOffloadSafeDefaults(t *testing.T) {
	got, err := NormalizeSharedNetwork(option.EBPFSharedNetworkOptions{
		Enabled: true,
		Engine:  EngineV3,
		PolicyOffload: option.EBPFPolicyOffloadOptions{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.PolicyOffload.StaticRules || !got.PolicyOffload.ExactFlowLearning {
		t.Fatalf("enabled policy_offload did not apply safe defaults: %+v", got.PolicyOffload)
	}
}
