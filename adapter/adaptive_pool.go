package adapter

import (
	"context"
	"errors"
	"time"
)

var (
	ErrAdaptiveCapabilityUnavailable = errors.New("adaptive capability probe is unavailable")
	ErrAdaptiveCapabilityBusy        = errors.New("adaptive capability probe is already running")
)

type AdaptiveCandidateStatus struct {
	NodeID                string    `json:"node_id"`
	EndpointID            string    `json:"endpoint_id,omitempty"`
	EndpointConflictCount int       `json:"endpoint_conflict_count,omitempty"`
	NodeSlot              uint64    `json:"node_slot"`
	NodeVersion           uint64    `json:"node_version"`
	Tag                   string    `json:"tag"`
	Weight                float64   `json:"weight,omitempty"`
	WeightRule            string    `json:"weight_rule,omitempty"`
	WeightRuleExact       bool      `json:"weight_rule_exact,omitempty"`
	Aliases               []string  `json:"aliases,omitempty"`
	IdentityStable        bool      `json:"identity_stable"`
	State                 string    `json:"state"`
	Health                string    `json:"health"`
	Breaker               string    `json:"breaker"`
	LastProbeAt           time.Time `json:"last_probe_at,omitempty"`
	LastProbeDelay        uint32    `json:"last_probe_delay,omitempty"`
	SmoothedDelay         uint32    `json:"smoothed_delay,omitempty"`
	DelaySamples          int       `json:"delay_samples,omitempty"`
	BackoffMs             uint32    `json:"backoff_ms,omitempty"`
	ConsecutiveFailures   int       `json:"consecutive_failures,omitempty"`
	ThroughputBPS         float64   `json:"throughput_bps,omitempty"`
	ThroughputSamples     uint64    `json:"throughput_samples,omitempty"`
	Successes             uint64    `json:"successes,omitempty"`
	Failures              uint64    `json:"failures,omitempty"`
	RecoverySuccesses     int       `json:"recovery_successes,omitempty"`
	EvidenceWeight        float64   `json:"evidence_weight,omitempty"`
	OpenUntil             time.Time `json:"open_until,omitempty"`
	Reason                string    `json:"reason,omitempty"`
	HealthPriority        int       `json:"health_priority,omitempty"`
	ObservedDelay         uint32    `json:"observed_delay,omitempty"`
	WeightedDelay         uint32    `json:"weighted_delay,omitempty"`
	SelectionScore        uint64    `json:"selection_score,omitempty"`
	DominantEvidence      string    `json:"dominant_evidence,omitempty"`
	FilterReason          string    `json:"filter_reason,omitempty"`
	FilterReasons         []string  `json:"filter_reasons,omitempty"`
	LastFailure           string    `json:"last_failure,omitempty"`
	LastFailureService    string    `json:"last_failure_service,omitempty"`
	LastFailurePath       string    `json:"last_failure_path,omitempty"`
	LastSelectionReason   string    `json:"last_selection_reason,omitempty"`
	LastSelectionService  string    `json:"last_selection_service,omitempty"`
	// ServiceMemories keeps recent per-service selection/failure notes so one
	// service cannot erase another service's last outcome in the UI.
	ServiceMemories []AdaptiveServiceMemory   `json:"service_memories,omitempty"`
	Capabilities    *AdaptiveNodeCapabilities `json:"capabilities,omitempty"`
	Paths           []AdaptivePathStatus      `json:"paths,omitempty"`
}

// AdaptiveServiceMemory is a per-service selection or failure snapshot.
type AdaptiveServiceMemory struct {
	ServiceID       string    `json:"service_id,omitempty"`
	Path            string    `json:"path,omitempty"`
	SelectionReason string    `json:"selection_reason,omitempty"`
	Failure         string    `json:"failure,omitempty"`
	SelectedAt      time.Time `json:"selected_at,omitempty"`
	FailedAt        time.Time `json:"failed_at,omitempty"`
}

// AdaptiveNodeCapabilities is the partial-availability portrait used by
// operators and by path-aware selection.
type AdaptiveNodeCapabilities struct {
	TCP4          AdaptivePathCapability `json:"tcp4"`
	TCP6          AdaptivePathCapability `json:"tcp6"`
	DNSUDPv4      AdaptivePathCapability `json:"dns_udp4"`
	DNSUDPv6      AdaptivePathCapability `json:"dns_udp6"`
	DataUDPv4     AdaptivePathCapability `json:"data_udp4"`
	DataUDPv6     AdaptivePathCapability `json:"data_udp6"`
	Endpoint      AdaptivePathCapability `json:"endpoint"`
	ThroughputOK  bool                   `json:"throughput_ok"`
	ThroughputBPS float64                `json:"throughput_bps,omitempty"`
	// Known marks whether at least one path has real evidence.
	Known bool `json:"known"`
}

type AdaptivePathCapability struct {
	Known     bool   `json:"known"`
	Available bool   `json:"available"`
	State     string `json:"state"`
}

type AdaptivePathStatus struct {
	Path                string    `json:"path"`
	Health              string    `json:"health"`
	Breaker             string    `json:"breaker"`
	LastUpdated         time.Time `json:"last_updated,omitempty"`
	LastDelay           uint32    `json:"last_delay,omitempty"`
	SmoothedDelay       uint32    `json:"smoothed_delay,omitempty"`
	DelaySamples        int       `json:"delay_samples,omitempty"`
	BackoffMs           uint32    `json:"backoff_ms,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	Successes           uint64    `json:"successes,omitempty"`
	Failures            uint64    `json:"failures,omitempty"`
	RecoverySuccesses   int       `json:"recovery_successes,omitempty"`
	OpenUntil           time.Time `json:"open_until,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	HealthPriority      int       `json:"health_priority"`
	ObservedDelay       uint32    `json:"observed_delay,omitempty"`
	WeightedDelay       uint32    `json:"weighted_delay,omitempty"`
	SelectionScore      uint64    `json:"selection_score"`
	DominantEvidence    string    `json:"dominant_evidence,omitempty"`
}

type AdaptiveSwitchAudit struct {
	ServiceID     string    `json:"service_id"`
	SessionID     string    `json:"session_id,omitempty"`
	OldNodeID     string    `json:"old_node_id,omitempty"`
	OldTag        string    `json:"old_tag,omitempty"`
	NewNodeID     string    `json:"new_node_id,omitempty"`
	NewTag        string    `json:"new_tag,omitempty"`
	Reason        string    `json:"reason"`
	Failure       string    `json:"failure,omitempty"`
	FailureSource string    `json:"failure_source,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
}

type AdaptiveServiceLease struct {
	ServiceID  string    `json:"service_id"`
	AffinityID string    `json:"affinity_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	Mode       string    `json:"mode"`
	NodeID     string    `json:"node_id"`
	Tag        string    `json:"tag,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type AdaptivePoolStatus struct {
	Shadow                          bool                      `json:"shadow"`
	Generation                      uint64                    `json:"generation"`
	CandidateCount                  int                       `json:"candidate_count"`
	AliasCount                      int                       `json:"alias_count"`
	DuplicatesSuppressed            int                       `json:"duplicates_suppressed"`
	EndpointConflictCount           int                       `json:"endpoint_conflict_count"`
	StableIdentityCount             int                       `json:"stable_identity_count"`
	ProbeQueueDepth                 int                       `json:"probe_queue_depth"`
	ProbeOwnerEpoch                 uint64                    `json:"probe_owner_epoch"`
	ProbeOwnerGeneration            uint64                    `json:"probe_owner_generation"`
	ProbeAcceptedTotal              uint64                    `json:"probe_accepted_total"`
	ProbeCoalescedTotal             uint64                    `json:"probe_coalesced_total"`
	ProbeDeferredTotal              uint64                    `json:"probe_deferred_total"`
	ProbeRejectedTotal              uint64                    `json:"probe_rejected_total"`
	ProbeCompletedTotal             uint64                    `json:"probe_completed_total"`
	ProbeSchedulerStalledTotal      uint64                    `json:"probe_scheduler_stalled_total"`
	CapabilityEnabled               bool                      `json:"capability_enabled"`
	CapabilityRunning               bool                      `json:"capability_running"`
	CapabilityCyclesStarted         uint64                    `json:"capability_cycles_started"`
	CapabilityCyclesCompleted       uint64                    `json:"capability_cycles_completed"`
	CapabilityInitFailures          uint64                    `json:"capability_init_failures"`
	CapabilityRefreshFailures       uint64                    `json:"capability_refresh_failures"`
	CapabilityViewFailures          uint64                    `json:"capability_view_failures"`
	CapabilitySuiteFailures         uint64                    `json:"capability_suite_failures"`
	CapabilityLastFailureStage      string                    `json:"capability_last_failure_stage,omitempty"`
	CapabilityTargetGeneration      uint64                    `json:"capability_target_generation"`
	ExitIdentityBaselines           uint64                    `json:"exit_identity_baselines"`
	ExitIdentityChangesTotal        uint64                    `json:"exit_identity_changes_total"`
	ExitIdentitySaturatedNodes      uint64                    `json:"exit_identity_saturated_nodes"`
	ExitIdentityIPv4Baselines       uint64                    `json:"exit_identity_ipv4_baselines"`
	ExitIdentityIPv6Baselines       uint64                    `json:"exit_identity_ipv6_baselines"`
	ExitIdentityDualStackNodes      uint64                    `json:"exit_identity_dual_stack_nodes"`
	AIIPv6Policy                    string                    `json:"ai_ipv6_policy,omitempty"`
	AIIPv6BlockedTotal              uint64                    `json:"ai_ipv6_blocked_total"`
	StateEntries                    int                       `json:"state_entries"`
	StateEvictions                  uint64                    `json:"state_evictions"`
	StatePersistenceFailures        uint64                    `json:"state_persistence_failures"`
	MissedObservations              uint64                    `json:"missed_observations"`
	ObservationStaleTotal           uint64                    `json:"observation_stale_total"`
	ObservationDuplicateTotal       uint64                    `json:"observation_duplicate_total"`
	ObservationBackpressureTotal    uint64                    `json:"observation_backpressure_total"`
	ObservationReducerFailureTotal  uint64                    `json:"observation_reducer_failure_total"`
	ObservationIdentityFailureTotal uint64                    `json:"observation_identity_failure_total"`
	ObservationPanicTotal           uint64                    `json:"observation_panic_total"`
	ObservationPermitBusyTotal      uint64                    `json:"observation_permit_busy_total"`
	BusinessTLSFailuresTotal        uint64                    `json:"business_tls_failures_total"`
	TransportFailuresTotal          uint64                    `json:"transport_failures_total"`
	SelectionSwitchesTotal          uint64                    `json:"selection_switches_total"`
	Mode                            string                    `json:"mode"`
	Pinned                          string                    `json:"pinned,omitempty"`
	ActiveLeases                    int                       `json:"active_leases"`
	LeaseEvictions                  uint64                    `json:"lease_evictions"`
	BulkSequence                    uint64                    `json:"bulk_sequence"`
	ControlRevision                 uint64                    `json:"control_revision"`
	ServiceOverrideCount            int                       `json:"service_override_count"`
	ActiveBindingCount              int                       `json:"active_binding_count"`
	RetiredBindingCount             uint64                    `json:"retired_binding_count"`
	DeltaAppliedTotal               uint64                    `json:"delta_applied_total"`
	DeltaFallbackTotal              uint64                    `json:"delta_fallback_total"`
	UpdatedAt                       time.Time                 `json:"updated_at,omitempty"`
	Candidates                      []AdaptiveCandidateStatus `json:"candidates"`
	RecentSwitches                  []AdaptiveSwitchAudit     `json:"recent_switches,omitempty"`
	ServiceLeases                   []AdaptiveServiceLease    `json:"service_leases,omitempty"`
}

type AdaptivePoolGroup interface {
	URLTestGroup
	AdaptiveStatus() AdaptivePoolStatus
	TriggerAdaptiveProbe(context.Context) error
	TriggerAdaptiveCapabilityProbe(context.Context) error
	SelectAdaptiveOutbound(string) bool
	ClearAdaptiveSelection()
}

type AdaptivePoolRevisioned interface {
	SelectAdaptiveOutboundAt(string, uint64) bool
	ClearAdaptiveSelectionAt(uint64) bool
	AdaptiveSelectionRevision() uint64
}

type AdaptiveServiceOverride struct {
	ServiceID string    `json:"service_id"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AdaptivePoolServiceControl interface {
	SetAdaptiveServiceOverride(serviceID, mode string, ttl time.Duration, expectedRevision uint64) error
	ClearAdaptiveServiceOverride(serviceID string, expectedRevision uint64) error
	AdaptiveServiceOverrides() []AdaptiveServiceOverride
}
