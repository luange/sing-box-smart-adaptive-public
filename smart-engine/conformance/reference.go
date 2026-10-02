package conformance

import "math"

// This file is the Go reference mirror of smart-engine/src/scoring.zig and
// the cold-start ranking/confirmation flow of policy.zig (interactive
// profile). Any change to the Zig kernel formula MUST be mirrored here; the
// conformance tests pin the two implementations to identical scores.

type Candidate struct {
	ID, State, Eligible                                                                           uint64
	Reliability, ConnectMS, FirstByteMS, JitterMS, ThroughputBPS, Samples, Weight, CandidateOrder float64
}

type Config struct {
	Exploration, SwitchMargin float64
	// 0 = fixed primary/backup, 1 = Surge A/B/C dispersion.
	SelectionMode                     uint8
	SwitchConfirmSamples              uint32
	SwitchConfirmMS, SwitchCooldownMS uint64
	MinSamples                        uint32
}

type Decision struct {
	SelectedID uint64
	Score      float64
	Switched   uint8
	Reason     uint8
}

type state struct {
	selected, challenge, since, cooldown uint64
	count                                uint32
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func normalizedCost(value, ceiling float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, -1) {
		return .5
	}
	if math.IsInf(value, 1) {
		return 1
	}
	if !(value > 0) {
		return .5
	}
	return math.Max(0, math.Min(1, math.Log1p(value)/math.Log1p(ceiling)))
}

func normalizedReliability(value float64) float64 {
	if !isFinite(value) {
		return .5
	}
	return math.Max(0, math.Min(1, value))
}

func weightOf(weight float64) float64 {
	if !(weight > 0) || !isFinite(weight) {
		return 1
	}
	if weight < 0.01 {
		return 0.01
	}
	return weight
}

// Traffic profiles mirror scoring.zig TrafficProfile.
const (
	ProfileInteractive = 0
	ProfileBulk        = 1
	ProfileUDP         = 2
)

func score(c Config, candidate Candidate, total float64) float64 {
	return scoreProfile(c, candidate, total, ProfileInteractive)
}

// ScoreProfile is the exported view of the profile-aware reference score
// used by host-side drift pins.
func ScoreProfile(c Config, candidate Candidate, total float64, profile int) float64 {
	return scoreProfile(c, candidate, total, profile)
}

func scoreProfile(c Config, candidate Candidate, total float64, profile int) float64 {
	samples := 0.0
	if candidate.Samples > 0 && isFinite(candidate.Samples) {
		samples = candidate.Samples
	}
	exploration := 0.0
	if c.Exploration > 0 && isFinite(c.Exploration) {
		exploration = c.Exploration
	}
	reliability := normalizedReliability(candidate.Reliability)
	connect := normalizedCost(candidate.ConnectMS, 5000)
	first := normalizedCost(candidate.FirstByteMS, 10000)
	jitter := .5
	if candidate.ConnectMS > 0 && isFinite(candidate.ConnectMS) &&
		candidate.JitterMS >= 0 && isFinite(candidate.JitterMS) {
		jitter = math.Min(1, candidate.JitterMS/1000)
	}
	var reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = .30, .25, .30, 0.0, .10
	const confidenceWeight = .05
	switch profile {
	case ProfileBulk:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = .30, .15, .20, .30, 0
	case ProfileUDP:
		reliabilityWeight, connectWeight, firstByteWeight, throughputWeight, jitterWeight = .50, .25, 0, 0, .20
	}
	throughputCost := .60
	if candidate.ThroughputBPS > 0 && isFinite(candidate.ThroughputBPS) {
		throughputCost = 1 - math.Min(1, math.Log1p(candidate.ThroughputBPS)/math.Log1p(64*1024*1024))
	}
	confidence := 0.0
	if samples < 3 {
		confidence = 1 - samples/3
	}
	base := reliabilityWeight*(1-reliability) + connectWeight*connect + firstByteWeight*first +
		throughputWeight*throughputCost + jitterWeight*jitter + confidenceWeight*confidence
	if candidate.State == 5 {
		base += 0.20
	}
	if samples > 0 && total > 0 {
		exploration *= math.Sqrt(math.Log(total+2) / (samples + 1))
	}
	return math.Max(0, base-exploration) / weightOf(candidate.Weight)
}

func choose(s *state, c Config, candidates []Candidate, now uint64) Decision {
	// Mirrors policy.zig's pre-ranked candidate block: when the host provides a
	// 1-based candidate order, it decides before any scoring/FSM logic, with
	// fixed mode retaining a usable incumbent.
	var orderedCandidate *Candidate
	bestOrder := math.Inf(1)
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID == 0 || candidate.Eligible == 0 || candidate.State == 4 {
			continue
		}
		if candidate.CandidateOrder > 0 && isFinite(candidate.CandidateOrder) && candidate.CandidateOrder < bestOrder {
			orderedCandidate = candidate
			bestOrder = candidate.CandidateOrder
		}
	}
	if orderedCandidate != nil {
		if c.SelectionMode == 0 && s.selected != 0 {
			for i := range candidates {
				incumbent := &candidates[i]
				if incumbent.ID == s.selected && incumbent.ID != 0 &&
					incumbent.Eligible != 0 && incumbent.State != 4 {
					score := bestOrder
					if isFinite(incumbent.CandidateOrder) && incumbent.CandidateOrder > 0 {
						score = incumbent.CandidateOrder
					}
					return Decision{SelectedID: incumbent.ID, Score: score, Switched: 0, Reason: 1}
				}
			}
		}
		switched := uint8(0)
		if s.selected != 0 && s.selected != orderedCandidate.ID {
			switched = 1
		}
		return Decision{SelectedID: orderedCandidate.ID, Score: bestOrder, Switched: switched, Reason: 0}
	}
	d := Decision{Score: 100, Reason: 3}
	var best *Candidate
	bestScore, total := math.Inf(1), 0.0
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID != 0 && candidate.Eligible != 0 && candidate.State != 4 {
			if candidate.Samples > 0 && isFinite(candidate.Samples) {
				total += candidate.Samples
			}
		}
	}
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.ID == 0 || candidate.Eligible == 0 || candidate.State == 4 {
			continue
		}
		value := score(c, *candidate, total)
		if isFinite(value) && (best == nil || value < bestScore) {
			best, bestScore = candidate, value
		}
	}
	if best == nil {
		return d
	}
	d.SelectedID, d.Score = best.ID, bestScore
	if s.selected == 0 || s.selected == best.ID {
		s.selected, d.Reason = best.ID, 0
		return d
	}
	for i := range candidates {
		if candidates[i].ID != s.selected {
			continue
		}
		currentScore := score(c, candidates[i], total)
		improvement := 0.0
		if currentScore > 0 {
			improvement = (currentScore - bestScore) / currentScore
		}
		if improvement < c.SwitchMargin || now < s.cooldown {
			d.SelectedID, d.Score, d.Reason = s.selected, currentScore, 1
			return d
		}
		break
	}
	if s.challenge != best.ID || s.since == 0 {
		s.challenge, s.count, s.since = best.ID, 1, now
		d.SelectedID, d.Reason = s.selected, 1
		return d
	}
	s.count++
	if s.count < c.SwitchConfirmSamples || now-s.since < c.SwitchConfirmMS {
		d.SelectedID, d.Reason = s.selected, 1
		return d
	}
	s.selected, s.cooldown = best.ID, now+c.SwitchCooldownMS
	s.challenge, s.count, s.since = 0, 0, 0
	d.SelectedID, d.Switched, d.Reason = best.ID, 1, 2
	return d
}
