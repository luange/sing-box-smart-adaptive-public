//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestNormalizeUDPNATCapacitiesDefaults(t *testing.T) {
	data, dns, warnings := normalizeUDPNATCapacities(0, 0)
	if data != 1024 || dns != 1024 || len(warnings) != 0 {
		t.Fatalf("unexpected defaults: data=%d dns=%d warnings=%v", data, dns, warnings)
	}
}

func TestNormalizeUDPNATCapacitiesClamp(t *testing.T) {
	data, dns, warnings := normalizeUDPNATCapacities(1, 9000)
	if data != 64 || dns != 8192 || len(warnings) != 2 {
		t.Fatalf("unexpected clamp: data=%d dns=%d warnings=%v", data, dns, warnings)
	}
}

func TestNormalizeUDPNATCapacitiesCustom(t *testing.T) {
	data, dns, warnings := normalizeUDPNATCapacities(768, 256)
	if data != 768 || dns != 256 || len(warnings) != 0 {
		t.Fatalf("unexpected custom values: data=%d dns=%d warnings=%v", data, dns, warnings)
	}
}
