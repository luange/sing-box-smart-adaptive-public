package adaptive

import (
	"strings"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// NodeCapabilityProfile is a process-local view of partial node availability.
// Unknown paths stay fail-open so a missing probe never hard-kills a family.
type NodeCapabilityProfile struct {
	TCP4      PathCapability `json:"tcp4"`
	TCP6      PathCapability `json:"tcp6"`
	DNSUDPv4  PathCapability `json:"dns_udp4"`
	DNSUDPv6  PathCapability `json:"dns_udp6"`
	DataUDPv4 PathCapability `json:"data_udp4"`
	DataUDPv6 PathCapability `json:"data_udp6"`
	Endpoint  PathCapability `json:"endpoint"`
	// ThroughputOK is true when the node has at least one trusted service
	// throughput sample above a conservative floor.
	ThroughputOK  bool    `json:"throughput_ok"`
	ThroughputBPS float64 `json:"throughput_bps,omitempty"`
}

// Path capability states exposed to operators. These are intentionally finer
// than a bare available bool so "never probed" is not shown as verified OK.
const (
	PathStateUnknown         = "unknown"
	PathStateHealthy         = "healthy"
	PathStateDegraded        = "degraded"
	PathStateUnreachable     = "unreachable"
	PathStateOpen            = "open"
	PathStateCooldown        = "cooldown"
	PathStateCooldownReady   = "cooldown_ready"
	PathStateHalfOpen        = "half_open"
	PathStateRecoveryPending = "recovery_pending"
)

type PathCapability struct {
	Path                string    `json:"path,omitempty"`
	Available           bool      `json:"available"`
	Known               bool      `json:"known"`
	State               string    `json:"state,omitempty"`
	Health              string    `json:"health,omitempty"`
	Breaker             string    `json:"breaker,omitempty"`
	SmoothedDelayMs     uint32    `json:"smoothed_delay_ms,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	RecoverySuccesses   int       `json:"recovery_successes,omitempty"`
	BackoffMs           uint32    `json:"backoff_ms,omitempty"`
	OpenUntil           time.Time `json:"open_until,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	LastFailure         string    `json:"last_failure,omitempty"`
}

func (s *HealthStore) BuildCapabilityProfile(handle NodeHandle, now time.Time) NodeCapabilityProfile {
	if now.IsZero() && s != nil && s.clock != nil {
		now = s.clock.Now()
	}
	profile := NodeCapabilityProfile{
		TCP4:      s.pathCapability(handle, "tcp/ipv4", now),
		TCP6:      s.pathCapability(handle, "tcp/ipv6", now),
		DNSUDPv4:  s.pathCapability(handle, "udp_dns/ipv4", now),
		DNSUDPv6:  s.pathCapability(handle, "udp_dns/ipv6", now),
		DataUDPv4: s.pathCapability(handle, "udp_data/ipv4", now),
		DataUDPv6: s.pathCapability(handle, "udp_data/ipv6", now),
		Endpoint:  s.pathCapability(handle, "", now),
	}
	return profile
}

func (s *HealthStore) pathCapability(handle NodeHandle, path string, now time.Time) PathCapability {
	cap := PathCapability{Path: path, Available: true, State: PathStateUnknown}
	if s == nil {
		return cap
	}
	if now.IsZero() && s.clock != nil {
		now = s.clock.Now()
	}
	var status HealthStatus
	if path == "" {
		status = s.EndpointHandle(handle)
	} else {
		status = s.StatusHandle(handle, DomainTransport, path, "")
	}
	cap.Health = string(status.Health)
	cap.Breaker = string(status.Breaker)
	cap.SmoothedDelayMs = durationMillis32(status.RankingDelay())
	cap.ConsecutiveFailures = status.ConsecutiveFailures
	cap.RecoverySuccesses = status.RecoverySuccesses
	cap.BackoffMs = uint32(max(0, status.Backoff.Milliseconds()))
	cap.OpenUntil = status.CooldownUntil
	cap.Reason = status.Reason
	if status.Health != HealthUnknown || status.Successes > 0 || status.Failures > 0 || status.Breaker != BreakerClosed && status.Breaker != "" {
		cap.Known = true
	}
	cap.State, cap.Available = classifyPathCapability(status, now)
	if !cap.Available {
		if status.Reason != "" {
			cap.LastFailure = status.Reason
		} else if status.Breaker != BreakerClosed && status.Breaker != "" {
			cap.LastFailure = string(status.Breaker)
		} else {
			cap.LastFailure = string(status.Health)
		}
	} else if cap.State == PathStateRecoveryPending {
		cap.LastFailure = "recovery_pending"
	}
	return cap
}

// classifyPathCapability is read-only: it never advances breaker state.
// Available mirrors whether a new attempt may be considered (same idea as
// availableReadOnly for a single path record).
func classifyPathCapability(status HealthStatus, now time.Time) (state string, available bool) {
	switch status.Breaker {
	case BreakerOpen:
		if status.CooldownUntil.IsZero() || now.Before(status.CooldownUntil) {
			return PathStateOpen, false
		}
		// Cooldown elapsed; dial path may half-open on acquire, but evidence is
		// not yet re-validated.
		return PathStateCooldownReady, true
	case BreakerCooldown:
		if status.CooldownUntil.IsZero() || now.Before(status.CooldownUntil) {
			return PathStateCooldown, false
		}
		return PathStateCooldownReady, true
	case BreakerHalfOpen:
		if status.RecoverySuccesses < 2 {
			// Token-free half-open after first success remains dialable so the
			// confirmation attempt is not starved; surface recovery_pending.
			return PathStateRecoveryPending, true
		}
		return PathStateHalfOpen, true
	}
	switch status.Health {
	case HealthHealthy:
		return PathStateHealthy, true
	case HealthDegraded:
		return PathStateDegraded, true
	case HealthUnreachable:
		return PathStateUnreachable, false
	default:
		return PathStateUnknown, true
	}
}

// RequiredPathKnownBlocked reports whether the service path is known-bad under
// dual-stack policy. Used by status/Explain; Plan uses CanAttemptHandleReadOnly
// (same transportPathEligible rule) without rebuilding a full portrait.
func (s *HealthStore) RequiredPathKnownBlocked(handle NodeHandle, service ServiceContext, now time.Time) bool {
	if s == nil {
		return false
	}
	if now.IsZero() && s.clock != nil {
		now = s.clock.Now()
	}
	return !s.transportPathEligible(handle, RequiredPathForService(service), now)
}

// dualStackFamilyPaths returns the concrete v4/v6 ledger keys for an aggregate
// health path. ok is false for concrete family paths and unknown keys.
func dualStackFamilyPaths(path string) (familyA, familyB string, ok bool) {
	switch path {
	case N.NetworkTCP, "tcp/any": // N.NetworkTCP == "tcp"
		return "tcp/ipv4", "tcp/ipv6", true
	case "udp_dns/any":
		return "udp_dns/ipv4", "udp_dns/ipv6", true
	case N.NetworkUDP, "udp/any", "udp_data/any": // N.NetworkUDP == "udp"
		return "udp_data/ipv4", "udp_data/ipv6", true
	default:
		return "", "", false
	}
}

// transportPathEligible reports whether the transport health path may still be
// attempted. Dual-stack aggregates follow aggregateDualStackCapability; a
// collapsed */any ledger entry only blocks when no family is known-good.
func (s *HealthStore) transportPathEligible(handle NodeHandle, path string, now time.Time) bool {
	if s == nil {
		return true
	}
	if now.IsZero() && s.clock != nil {
		now = s.clock.Now()
	}
	if familyA, familyB, isDual := dualStackFamilyPaths(path); isDual {
		a := s.pathCapability(handle, familyA, now)
		b := s.pathCapability(handle, familyB, now)
		agg := aggregateDualStackCapability(path, a, b)
		if agg.Known && !agg.Available {
			// Both concrete families confirmed bad.
			return false
		}
		if (a.Known && a.Available) || (b.Known && b.Available) {
			// At least one family still usable — do not let a collapsed any-key
			// failure eliminate the node.
			return true
		}
		// Both unknown, or one bad + one unknown: fall through to the aggregate
		// ledger key so dual-stack dials that only wrote tcp/any still count.
	}
	cap := s.pathCapability(handle, path, now)
	return !cap.Known || cap.Available
}

// PeekAvailable is the preferred read-only availability entry point for
// status/plan callers. Prefer this over CanAttemptHandle, which may advance
// breaker labels on open expiry.
func (s *HealthStore) PeekAvailable(handle NodeHandle, service ServiceContext, now time.Time) bool {
	return s.CanAttemptHandleReadOnly(handle, service, now)
}

// ExplainExclusion returns a stable, non-sensitive reason when a candidate is
// filtered from a service plan. Empty means the candidate is eligible.
func (s *HealthStore) ExplainExclusion(handle NodeHandle, service ServiceContext, now time.Time) string {
	if s == nil {
		return ""
	}
	if now.IsZero() {
		now = s.clock.Now()
	}
	if !s.CanAttemptHandleReadOnly(handle, service, now) {
		endpoint := s.EndpointHandle(handle)
		if endpoint.Health == HealthUnreachable || endpoint.Breaker == BreakerOpen || endpoint.Breaker == BreakerCooldown || endpoint.Breaker == BreakerHalfOpen {
			return exclusionLabel("endpoint", endpoint)
		}
		if service.ID != "" {
			serviceStatus := s.StatusHandle(handle, DomainService, "", service.ID)
			if serviceStatus.Health == HealthUnreachable || serviceStatus.Breaker == BreakerOpen || serviceStatus.Breaker == BreakerCooldown || serviceStatus.Breaker == BreakerHalfOpen {
				return exclusionLabel("service:"+service.ID, serviceStatus)
			}
		}
		// Prefer dual-stack / capability reason over a single aggregate key.
		if s.RequiredPathKnownBlocked(handle, service, now) {
			profile := s.BuildCapabilityProfile(handle, now)
			if ok, reason := profile.SupportsService(service); !ok && reason != "" {
				return reason
			}
		}
		path := serviceHealthTransport(service)
		transport := s.StatusHandle(handle, DomainTransport, path, "")
		if transport.Health == HealthUnreachable || transport.Breaker == BreakerOpen || transport.Breaker == BreakerCooldown || transport.Breaker == BreakerHalfOpen {
			return exclusionLabel(path, transport)
		}
		return "path_unavailable"
	}
	return ""
}

// ExplainAllPathExclusions summarizes every known-bad path for status views.
// Unknown paths are omitted (fail-open).
func (s *HealthStore) ExplainAllPathExclusions(handle NodeHandle, now time.Time) []string {
	if s == nil {
		return nil
	}
	if now.IsZero() && s.clock != nil {
		now = s.clock.Now()
	}
	profile := s.BuildCapabilityProfile(handle, now)
	paths := []PathCapability{
		profile.Endpoint, profile.TCP4, profile.TCP6,
		profile.DNSUDPv4, profile.DNSUDPv6, profile.DataUDPv4, profile.DataUDPv6,
	}
	var reasons []string
	for _, path := range paths {
		if !path.Known || path.Available {
			continue
		}
		label := path.Path
		if label == "" {
			label = "endpoint"
		}
		detail := path.LastFailure
		if detail == "" {
			detail = path.State
		}
		if detail == "" {
			detail = "unavailable"
		}
		reasons = append(reasons, exclusionLabel(label, HealthStatus{Reason: detail, Health: HealthState(path.Health), Breaker: BreakerState(path.Breaker)}))
	}
	return reasons
}

func exclusionLabel(scope string, status HealthStatus) string {
	reason := status.Reason
	if reason == "" {
		if status.Breaker != BreakerClosed && status.Breaker != "" {
			reason = string(status.Breaker)
		} else {
			reason = string(status.Health)
		}
	}
	// Never include raw URLs or payloads; reason fields are already sanitized.
	reason = strings.TrimSpace(reason)
	if len(reason) > 96 {
		reason = reason[:96]
	}
	return scope + ":" + reason
}

// RequiredPathForService returns the health path that must be usable for this
// dial. Unknown/empty paths fail open.
func RequiredPathForService(service ServiceContext) string {
	return serviceHealthTransport(service)
}

// ProfileSupportsService reports whether the capability profile is known-bad
// for the service path. Unknown remains eligible (fail-open).
func (p NodeCapabilityProfile) SupportsService(service ServiceContext) (bool, string) {
	path := RequiredPathForService(service)
	cap := p.capabilityForPath(path)
	if !cap.Known {
		return true, ""
	}
	if !cap.Available {
		if cap.LastFailure != "" {
			return false, path + ":" + cap.LastFailure
		}
		if cap.State != "" {
			return false, path + ":" + cap.State
		}
		return false, path + ":unavailable"
	}
	if service.Mode == ModeBulk && p.ThroughputBPS > 0 && !p.ThroughputOK {
		// Soft signal only; bulk mode still ranks by throughput elsewhere.
		return true, ""
	}
	return true, ""
}

func (p NodeCapabilityProfile) capabilityForPath(path string) PathCapability {
	switch path {
	case "tcp/ipv4":
		return p.TCP4
	case "tcp/ipv6":
		return p.TCP6
	case "udp_dns/ipv4":
		return p.DNSUDPv4
	case "udp_dns/ipv6":
		return p.DNSUDPv6
	case "udp_data/ipv4":
		return p.DataUDPv4
	case "udp_data/ipv6":
		return p.DataUDPv6
	case N.NetworkTCP, "tcp/any":
		// Dual-stack aggregate: never let one known-bad family poison an
		// unknown peer family. Block only when BOTH families are known-bad.
		return aggregateDualStackCapability(path, p.TCP4, p.TCP6)
	case N.NetworkUDP, "udp/any", "udp_data/any":
		return aggregateDualStackCapability(path, p.DataUDPv4, p.DataUDPv6)
	case "udp_dns/any":
		return aggregateDualStackCapability(path, p.DNSUDPv4, p.DNSUDPv6)
	default:
		return PathCapability{Path: path, Available: true, State: PathStateUnknown}
	}
}

// aggregateDualStackCapability implements fail-open dual-stack policy:
//   - any known-good family => available
//   - both families known-bad => unavailable
//   - one known-bad + one unknown => available (unknown fail-open)
//   - both unknown => available unknown
func aggregateDualStackCapability(path string, familyA, familyB PathCapability) PathCapability {
	if familyA.Known && familyA.Available {
		return PathCapability{Path: path, Available: true, Known: true, State: familyA.State, SmoothedDelayMs: familyA.SmoothedDelayMs}
	}
	if familyB.Known && familyB.Available {
		return PathCapability{Path: path, Available: true, Known: true, State: familyB.State, SmoothedDelayMs: familyB.SmoothedDelayMs}
	}
	bothKnownBad := familyA.Known && !familyA.Available && familyB.Known && !familyB.Available
	if bothKnownBad {
		failure := familyA.LastFailure
		if failure == "" {
			failure = familyB.LastFailure
		}
		if failure == "" {
			failure = "all_families_unavailable"
		}
		return PathCapability{
			Path: path, Available: false, Known: true,
			State: PathStateUnreachable, LastFailure: failure,
		}
	}
	// One bad + one unknown, or both unknown: keep the node eligible so the
	// concrete destination family can still succeed.
	return PathCapability{Path: path, Available: true, Known: false, State: PathStateUnknown}
}
