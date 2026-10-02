//go:build smart_zig && cgo

package conformance

import "testing"

func TestZigMatchesReferenceTransitions(t *testing.T) {
	config := Config{SwitchMargin: .05, SwitchConfirmSamples: 2, SwitchConfirmMS: 1000, SwitchCooldownMS: 2000}
	engine := newZigEngine(config)
	if engine == nil || engine.ptr == nil {
		t.Fatal("smart_engine_create returned nil")
	}
	defer engine.close()
	candidates := []Candidate{{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}, {ID: 2, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1}}
	var reference state
	for _, now := range []uint64{0, 1000, 2000, 2500} {
		wantCandidates := candidates
		if now == 0 {
			wantCandidates = candidates[:1]
		}
		want := choose(&reference, config, wantCandidates, now)
		got := engine.choose(wantCandidates, now)
		if got.SelectedID != want.SelectedID || got.Switched != want.Switched || got.Reason != want.Reason {
			t.Fatalf("at %d: got id=%d switched=%d reason=%d, want id=%d switched=%d reason=%d", now, got.SelectedID, got.Switched, got.Reason, want.SelectedID, want.Switched, want.Reason)
		}
		// A policy result is only a proposal. Mirror the host callback after a
		// real dial succeeds so the next transition compares the same incumbent.
		if now == 0 || got.Switched != 0 {
			engine.setSelected(got.SelectedID, now)
		}
	}
}

// TestZigMatchesReferenceScores pins the Zig kernel score to the Go reference
// formula bit-for-bit across a matrix of candidate shapes (weights, unknown
// latencies, sample counts, health states). A single eligible candidate makes
// choose() return that candidate's raw score.
func TestZigMatchesReferenceScores(t *testing.T) {
	config := Config{Exploration: 0.12, SwitchMargin: .05, SwitchConfirmSamples: 2, SwitchConfirmMS: 1000, SwitchCooldownMS: 2000}
	engine := newZigEngine(config)
	if engine == nil || engine.ptr == nil {
		t.Fatal("smart_engine_create returned nil")
	}
	defer engine.close()
	matrix := []Candidate{
		{ID: 1, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, JitterMS: 1, Samples: 10, Weight: 1, State: 1, Eligible: 1},
		{ID: 1, Reliability: .5, ConnectMS: 300, FirstByteMS: 800, JitterMS: 40, Samples: 4, Weight: 1, State: 1, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: .5, State: 1, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1e-9, State: 1, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 0, State: 1, Eligible: 1},
		{ID: 1, Reliability: .5, ConnectMS: 0, FirstByteMS: 0, JitterMS: 0, Samples: 0, Weight: 1, State: 0, Eligible: 1},
		{ID: 1, Reliability: -1, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 3, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 5, Eligible: 1},
		{ID: 1, Reliability: .9, ConnectMS: 20, FirstByteMS: 20, JitterMS: 1, Samples: 4, Weight: 1, State: 1, Eligible: 1, ThroughputBPS: 50_000_000},
	}
	for i, candidate := range matrix {
		engine.setSelected(0, 0)
		got := engine.choose([]Candidate{candidate}, 0)
		want := score(config, candidate, totalSamplesOf(candidate))
		if got.SelectedID != 1 || got.Reason != 0 {
			t.Fatalf("case %d: id=%d reason=%d", i, got.SelectedID, got.Reason)
		}
		if got.Score != want {
			t.Fatalf("case %d: got score=%v, want %v", i, got.Score, want)
		}
	}
}

func totalSamplesOf(candidate Candidate) float64 {
	if candidate.Samples > 0 {
		return candidate.Samples
	}
	return 0
}

// TestZigMatchesReferenceScoresWithCompetition extends the pin to a
// two-candidate field where the reference must pick the same winner.
func TestZigMatchesReferenceScoresWithCompetition(t *testing.T) {
	config := Config{Exploration: 0.12, SwitchMargin: .05, SwitchConfirmSamples: 2, SwitchConfirmMS: 1000, SwitchCooldownMS: 2000}
	engine := newZigEngine(config)
	if engine == nil || engine.ptr == nil {
		t.Fatal("smart_engine_create returned nil")
	}
	defer engine.close()
	fast := Candidate{ID: 2, Reliability: .99, ConnectMS: 5, FirstByteMS: 5, JitterMS: 1, Samples: 10, Weight: 1, State: 1, Eligible: 1}
	slow := Candidate{ID: 1, Reliability: .5, ConnectMS: 300, FirstByteMS: 800, JitterMS: 40, Samples: 4, Weight: 1, State: 1, Eligible: 1}
	total := fast.Samples + slow.Samples
	wantFast, wantSlow := score(config, fast, total), score(config, slow, total)
	got := engine.choose([]Candidate{slow, fast}, 0)
	if got.SelectedID != 2 {
		t.Fatalf("winner=%d score=%v", got.SelectedID, got.Score)
	}
	if got.Score != wantFast {
		t.Fatalf("winner score got=%v want=%v (slow=%v)", got.Score, wantFast, wantSlow)
	}
}
