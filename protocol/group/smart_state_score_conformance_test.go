package group

import (
	"math"
	"testing"

	"github.com/sagernet/sing-box/smart-engine/conformance"
)

// smartScoreForProfile is a fourth hand-maintained copy of the scoring.zig
// formula (host-side estimate score). This test pins it to the conformance
// reference mirror of the Zig kernel across a matrix of estimate shapes and
// all three traffic profiles, so any drift on either side fails here instead
// of silently reordering nodes.
func TestSmartScoreForProfileMatchesReference(t *testing.T) {
	type estimateShape struct {
		name        string
		reliability float64
		connectMS   float64
		firstByteMS float64
		jitterMS    float64
		throughput  float64
		samples     float64
		state       string
		hasConnect  bool
		hasFirst    bool
		hasThrough  bool
	}
	shapes := []estimateShape{
		{"healthy measured", 0.99, 5, 5, 1, 100_000_000, 10, "healthy", true, true, true},
		{"healthy typical", 0.5, 300, 800, 40, 0, 4, "healthy", true, true, false},
		{"unmeasured cold", 0, 0, 0, 0, 0, 0, "unknown", false, false, false},
		{"half-open recovery", 0.9, 20, 20, 1, 0, 4, "half_open", true, true, false},
		{"suspect", 0.8, 60, 90, 5, 0, 4, "suspect", true, true, false},
		{"zero connect ms edge", 0.9, 0, 20, 1, 0, 4, "healthy", true, true, false},
		{"warming", 0.95, 45, 70, 3, 0, 1, "warming", true, true, false},
	}
	total := 14.0
	exploration := 0.12
	for _, shape := range shapes {
		estimate := smartEstimate{
			Reliability:    shape.reliability,
			ConnectMS:      shape.connectMS,
			ConnectP95MS:   shape.connectMS,
			FirstByteMS:    shape.firstByteMS,
			FirstByteP95MS: shape.firstByteMS,
			ThroughputBPS:  shape.throughput,
			JitterMS:       shape.jitterMS,
			Samples:        shape.samples,
			State:          shape.state,
			HasConnect:     shape.hasConnect,
			HasFirstByte:   shape.hasFirst,
			HasThroughput:  shape.hasThrough,
		}
		candidate := conformance.Candidate{
			ID:            1,
			Reliability:   shape.reliability,
			ConnectMS:     shape.connectMS,
			FirstByteMS:   shape.firstByteMS,
			JitterMS:      shape.jitterMS,
			ThroughputBPS: shape.throughput,
			Samples:       shape.samples,
			Weight:        1,
			State:         stateStringToKernelState(shape.state),
			Eligible:      1,
		}
		for profile := smartProfileInteractive; profile <= smartProfileUDP; profile++ {
			got := smartScoreForProfile(estimate, profile, exploration, total)
			want := conformance.ScoreProfile(conformance.Config{Exploration: exploration}, candidate, total, int(profile))
			if math.Abs(got-want) > 1e-9 {
				t.Fatalf("%s profile=%d: got=%v want=%v", shape.name, profile, got, want)
			}
		}
	}
}

// stateStringToKernelState maps the host estimate state strings onto the
// kernel candidate.state values used by scoring.zig (only 5 contributes a
// score change: the half-open bounded-trial penalty).
func stateStringToKernelState(state string) uint64 {
	switch state {
	case "healthy":
		return 1
	case "half_open":
		return 5
	case "suspect":
		return 3
	case "warming":
		return 2
	default:
		return 0
	}
}
