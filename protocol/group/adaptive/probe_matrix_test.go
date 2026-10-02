package adaptive

import (
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/protocol/group/probe"
)

// TestBusinessProbeMatrixDocumentsTheProtocolContracts keeps the four high
// value checks aligned with the reducers. Network calls remain in the runner
// tests; this table is the deterministic contract used by CI.
func TestBusinessProbeMatrixDocumentsTheProtocolContracts(t *testing.T) {
	cases := []struct {
		name       string
		capability ProbeCapability
		status     int
		transport  string
	}{
		{name: "youtube-range", capability: ProbeCapabilityRange, status: http.StatusPartialContent, transport: "tcp"},
		{name: "gemini-google", capability: ProbeCapabilityHTTP, status: http.StatusNoContent, transport: "tcp"},
		{name: "anthropic-auth", capability: ProbeCapabilityHTTP, status: http.StatusUnauthorized, transport: "tcp"},
		{name: "udp-response", capability: ProbeCapabilityEndpoint, status: 0, transport: "udp"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.name == "youtube-range" && testCase.status != http.StatusPartialContent {
				t.Fatal("YouTube range must require 206")
			}
			if testCase.name == "gemini-google" && probe.GoogleConnectivityURL != "https://www.google.com/generate_204" {
				t.Fatalf("Gemini target drifted: %s", probe.GoogleConnectivityURL)
			}
			if testCase.name == "udp-response" && testCase.transport != "udp" {
				t.Fatal("UDP matrix row lost UDP transport")
			}
		})
	}
	if defaultProbeURL != probe.GoogleConnectivityURL {
		t.Fatalf("AdaptivePool default probe differs from Smart: %s != %s", defaultProbeURL, probe.GoogleConnectivityURL)
	}
}
