package adapter

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// SpliceCapableConn is an optional extension for eBPF sockmap splice.
type SpliceCapableConn interface {
	// SpliceReady returns underlying TCP after framing is done; nil = not ready.
	SpliceReady() *net.TCPConn
}

// ConnectionSplicer is registered by eBPF inbound when outbound_offload.splice is on.
type ConnectionSplicer interface {
	TrySpliceTCP(
		ctx context.Context,
		inboundType string,
		dialer N.Dialer,
		local net.Conn,
		remote net.Conn,
		metadata InboundContext,
		onClose N.CloseHandlerFunc,
	) bool
}

// VerdictLearner is registered by eBPF inbound when outbound_offload.verdict.mode != off.
type VerdictLearner interface {
	MaybeLearnTCP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
	MaybeLearnUDP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort)
}

// DirectOffload is registered by eBPF inbound whenever the TC bypass surface is up.
// Route calls it after selecting a DIRECT/ebpf leaf so destination IPs are promoted
// into kernel bypass without waiting for dial-time learn.
type DirectOffload interface {
	NoteRoutedDirect(metadata InboundContext, outbound Outbound)
}

// SmartCandidateStatus is a snapshot of one smart leaf candidate.
type SmartCandidateStatus struct {
	Tag string `json:"tag"`
	// EndpointID is a stable, opaque identity shared by subscription aliases
	// that resolve to the same endpoint. It is intentionally not a URL so
	// credentials and provider-specific options never reach the API surface.
	EndpointID string `json:"endpoint_id,omitempty"`
	// Role is the decision role for the current context. The first eligible
	// healthy candidate is primary; other eligible candidates are backups.
	// It is diagnostic only and never overrides a manual pin.
	Role            string  `json:"role,omitempty"`
	State           string  `json:"state"`
	Score           float64 `json:"score"`
	Weight          float64 `json:"weight,omitempty"`
	WeightRule      string  `json:"weight_rule,omitempty"`
	WeightExact     bool    `json:"weight_rule_exact,omitempty"`
	StandbyOnly     bool    `json:"standby_only,omitempty"`
	Reliability     float64 `json:"reliability"`
	ConnectMS       float64 `json:"connect_ms,omitempty"`
	ConnectP95MS    float64 `json:"connect_p95_ms,omitempty"`
	FirstByteMS     float64 `json:"first_byte_ms,omitempty"`
	FirstByteP95MS  float64 `json:"first_byte_p95_ms,omitempty"`
	ThroughputBPS   float64 `json:"throughput_bps,omitempty"`
	RetransmitRatio float64 `json:"tcp_retransmit_ratio,omitempty"`
	Samples         float64 `json:"samples"`
	Reason          string  `json:"reason,omitempty"`
}

// SmartContextStatus is a bounded snapshot for one network/site/transport
// selection context. It prevents an unrelated TCP or UDP context from hiding
// the evidence used for the current decision in dashboards.
type SmartContextStatus struct {
	Network                   string                 `json:"network,omitempty"`
	Site                      string                 `json:"site,omitempty"`
	Transport                 string                 `json:"transport,omitempty"`
	Phase                     string                 `json:"phase,omitempty"`
	Selected                  string                 `json:"selected,omitempty"`
	SelectedEndpointID        string                 `json:"selected_endpoint_id,omitempty"`
	ZigSelectedEndpointID     string                 `json:"zig_selected_endpoint_id,omitempty"`
	ActualDialEndpointID      string                 `json:"actual_dial_endpoint_id,omitempty"`
	SelectionGeneration       uint64                 `json:"selection_generation,omitempty"`
	LastFailureType           string                 `json:"last_failure_type,omitempty"`
	CircuitState              string                 `json:"circuit_state,omitempty"`
	SelectionMismatchTotal    uint64                 `json:"selection_mismatch_total,omitempty"`
	UnobservedConnectionTotal uint64                 `json:"unobserved_connection_total,omitempty"`
	Reason                    string                 `json:"reason,omitempty"`
	UpdatedAt                 time.Time              `json:"updated_at,omitempty"`
	CandidateCount            int                    `json:"candidate_count"`
	CandidateDetailsCount     int                    `json:"candidate_details_count"`
	CandidateDetailsTruncated bool                   `json:"candidate_details_truncated"`
	StateCounts               map[string]int         `json:"state_counts"`
	Candidates                []SmartCandidateStatus `json:"candidates"`
}

// SmartGroupStatus is exported for clash/API status surfaces.
type SmartGroupStatus struct {
	Mode uint8 `json:"mode"`
	// PolicyBackend identifies the compiled selection kernel. Production
	// releases must report "zig"; "unavailable" is a fail-closed build and
	// "go-reference" is reserved for explicit development builds.
	PolicyBackend             string                   `json:"policy_backend,omitempty"`
	PolicyBackendRequired     bool                     `json:"policy_backend_required"`
	PolicyBackendAvailable    bool                     `json:"policy_backend_available"`
	Selected                  string                   `json:"selected,omitempty"`
	SelectedEndpointID        string                   `json:"selected_endpoint_id,omitempty"`
	ZigSelectedEndpointID     string                   `json:"zig_selected_endpoint_id,omitempty"`
	ActualDialEndpointID      string                   `json:"actual_dial_endpoint_id,omitempty"`
	SelectionGeneration       uint64                   `json:"selection_generation,omitempty"`
	LastFailureType           string                   `json:"last_failure_type,omitempty"`
	CircuitState              string                   `json:"circuit_state,omitempty"`
	SelectionMismatchTotal    uint64                   `json:"selection_mismatch_total,omitempty"`
	UnobservedConnectionTotal uint64                   `json:"unobserved_connection_total,omitempty"`
	Pinned                    string                   `json:"pinned,omitempty"`
	Network                   string                   `json:"network,omitempty"`
	Site                      string                   `json:"site,omitempty"`
	Phase                     string                   `json:"phase,omitempty"`
	Reason                    string                   `json:"reason,omitempty"`
	UpdatedAt                 time.Time                `json:"updated_at,omitempty"`
	CandidateCount            int                      `json:"candidate_count"`
	ProbeEndpointsTotal       int                      `json:"probe_endpoints_total"`
	ProbeEndpointsAttempted   int                      `json:"probe_endpoints_attempted"`
	ProbeCoveragePercent      float64                  `json:"probe_coverage_percent"`
	CandidateDetailsCount     int                      `json:"candidate_details_count"`
	CandidateDetailsTruncated bool                     `json:"candidate_details_truncated"`
	StateCounts               map[string]int           `json:"state_counts"`
	TemporaryOverride         string                   `json:"temporary_override,omitempty"`
	OverrideExpiresAt         *time.Time               `json:"override_expires_at,omitempty"`
	OverrideRemainingSeconds  int64                    `json:"override_remaining_seconds,omitempty"`
	OverrideReason            string                   `json:"override_reason,omitempty"`
	SwitchesTotal             uint64                   `json:"switches_total,omitempty"`
	PerformanceSwitches       uint64                   `json:"performance_switches,omitempty"`
	FailureFailovers          uint64                   `json:"failure_failovers,omitempty"`
	ColdStarts                uint64                   `json:"cold_starts,omitempty"`
	RecentSwitches            []SmartSwitchAudit       `json:"recent_switches,omitempty"`
	SwitchesForceAll          uint64                   `json:"switches_force_all,omitempty"`
	SwitchesSelective         uint64                   `json:"switches_selective,omitempty"`
	ConnectionsInterrupted    uint64                   `json:"connections_interrupted,omitempty"`
	ConnectionsKept           uint64                   `json:"connections_kept,omitempty"`
	StreamFailureWakes        uint64                   `json:"stream_failure_wakes,omitempty"`
	ProbeTargets              []SmartProbeTargetStatus `json:"probe_targets,omitempty"`
	Candidates                []SmartCandidateStatus   `json:"candidates"`
	Contexts                  []SmartContextStatus     `json:"contexts,omitempty"`
}

type SmartProbeTargetStatus struct {
	TargetHost             string `json:"target_host"`
	Attempts               uint64 `json:"attempts"`
	Successes              uint64 `json:"successes"`
	Failures               uint64 `json:"failures"`
	Timeouts               uint64 `json:"timeouts"`
	HTTPFailures           uint64 `json:"http_failures"`
	TargetHTTPFailures     uint64 `json:"target_http_failures"`
	ProxyHandshakeFailures uint64 `json:"proxy_handshake_failures"`
	DNSFailures            uint64 `json:"dns_failures"`
	TLSFailures            uint64 `json:"tls_failures"`
	TransportFailures      uint64 `json:"transport_failures"`
	LastFailureClass       string `json:"last_failure_class,omitempty"`
	LastFailureStage       string `json:"last_failure_stage,omitempty"`
	LastHTTPStatus         int    `json:"last_http_status,omitempty"`
}

type SmartSwitchAudit struct {
	Network            string    `json:"network,omitempty"`
	Site               string    `json:"site,omitempty"`
	Transport          string    `json:"transport,omitempty"`
	Previous           string    `json:"previous,omitempty"`
	PreviousEndpointID string    `json:"previous_endpoint_id,omitempty"`
	Current            string    `json:"current"`
	CurrentEndpointID  string    `json:"current_endpoint_id,omitempty"`
	Category           string    `json:"category"`
	Reason             string    `json:"reason"`
	PreviousState      string    `json:"previous_state,omitempty"`
	CurrentState       string    `json:"current_state,omitempty"`
	PreviousScore      float64   `json:"previous_score,omitempty"`
	CurrentScore       float64   `json:"current_score,omitempty"`
	OccurredAt         time.Time `json:"occurred_at"`
}

// LoadBalanceGroup is implemented by protocol/group loadbalance outbound.
type LoadBalanceGroup interface {
	OutboundGroup
	URLTest(ctx context.Context) (map[string]uint16, error)
}

// SmartGroup is implemented by protocol/group smart outbound.
type SmartGroup interface {
	URLTestGroup
	SmartStatus() SmartGroupStatus
	SelectOutbound(tag string) bool
	ClearSelection()
	SelectTemporaryOutbound(tag string, ttl time.Duration, reason string) bool
	ClearTemporarySelection()
}

// WithDashboardProbe marks a control-plane delay check.  Group outbounds use
// this marker to keep the check advisory: it may measure the incumbent, but it
// must not commit a new selection, open a circuit, or interrupt live flows.
func WithDashboardProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, dashboardProbeContextKey{}, true)
}

// IsDashboardProbe reports whether an operation was initiated by a dashboard
// delay request rather than by real traffic or the periodic scheduler.
func IsDashboardProbe(ctx context.Context) bool {
	value, _ := ctx.Value(dashboardProbeContextKey{}).(bool)
	return value
}

type dashboardProbeContextKey struct{}

// PreMatchOutboundGroup lets groups pick a stable leaf for transparent pre-match
// without advancing consumptive selection (retry/hedge/observation stay on L4).
type PreMatchOutboundGroup interface {
	OutboundGroup
	SelectPreMatchOutbound(metadata *InboundContext, selectOutbound func(Outbound) (Outbound, PreMatchAction)) (Outbound, PreMatchAction)
}

// PreMatchDisabledOutbound keeps transparent flows on the L4 outbound path.
// Groups use it when resolving to a leaf would bypass retry or observation.
type PreMatchDisabledOutbound interface {
	DisablePreMatch()
}

// SelectorGroup is implemented by selector outbound (stable Selected leaf).
type SelectorGroup interface {
	Selected() Outbound
}

// OutboundWithEndpointIdentity carries a credential-free, stable identity for
// provider members. The display tag may change when a provider is reordered or
// when a duplicate is suffixed, but Smart health/profile state must continue
// to refer to the same network endpoint.
type OutboundWithEndpointIdentity interface {
	Outbound
	EndpointIdentity() string
}

// OutboundWithDialIdentity carries the identity that must remain distinct for
// actual authentication/data-plane outcomes.  It may differ from
// EndpointIdentity when two credentials share the same network path.  Probe
// and RTT state can share the endpoint identity, while dial success, breaker,
// quarantine and retry diversity use this stronger identity.
type OutboundWithDialIdentity interface {
	Outbound
	DialIdentity() string
}

// DirectOffloadHub fans out NoteRoutedDirect to all eBPF inbounds that registered.
type DirectOffloadHub struct {
	access   sync.Mutex
	offloads []DirectOffload
}

func NewDirectOffloadHub() *DirectOffloadHub {
	return &DirectOffloadHub{}
}

func (h *DirectOffloadHub) Add(offload DirectOffload) {
	if h == nil || offload == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for _, existing := range h.offloads {
		if existing == offload {
			return
		}
	}
	h.offloads = append(h.offloads, offload)
}

func (h *DirectOffloadHub) Remove(offload DirectOffload) {
	if h == nil || offload == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for i, existing := range h.offloads {
		if existing == offload {
			h.offloads = append(h.offloads[:i], h.offloads[i+1:]...)
			return
		}
	}
}

func (h *DirectOffloadHub) NoteRoutedDirect(metadata InboundContext, outbound Outbound) {
	if h == nil {
		return
	}
	h.access.Lock()
	snapshot := append([]DirectOffload(nil), h.offloads...)
	h.access.Unlock()
	for _, offload := range snapshot {
		offload.NoteRoutedDirect(metadata, outbound)
	}
}

// VerdictLearnerHub fans out dial-time DIRECT learn to every eBPF inbound.
// ConnectionManager resolves a single VerdictLearner from context — the hub.
type VerdictLearnerHub struct {
	access   sync.Mutex
	learners []VerdictLearner
}

func NewVerdictLearnerHub() *VerdictLearnerHub {
	return &VerdictLearnerHub{}
}

func (h *VerdictLearnerHub) Add(learner VerdictLearner) {
	if h == nil || learner == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for _, existing := range h.learners {
		if existing == learner {
			return
		}
	}
	h.learners = append(h.learners, learner)
}

// Len reports how many learners are currently registered (test/observability).
func (h *VerdictLearnerHub) Len() int {
	if h == nil {
		return 0
	}
	h.access.Lock()
	defer h.access.Unlock()
	return len(h.learners)
}

func (h *VerdictLearnerHub) Remove(learner VerdictLearner) {
	if h == nil || learner == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for i, existing := range h.learners {
		if existing == learner {
			h.learners = append(h.learners[:i], h.learners[i+1:]...)
			return
		}
	}
}

func (h *VerdictLearnerHub) MaybeLearnTCP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort) {
	if h == nil {
		return
	}
	h.access.Lock()
	snapshot := append([]VerdictLearner(nil), h.learners...)
	h.access.Unlock()
	for _, learner := range snapshot {
		learner.MaybeLearnTCP(ctx, dialer, metadata, remote)
	}
}

func (h *VerdictLearnerHub) MaybeLearnUDP(ctx context.Context, dialer N.Dialer, metadata InboundContext, remote netip.AddrPort) {
	if h == nil {
		return
	}
	h.access.Lock()
	snapshot := append([]VerdictLearner(nil), h.learners...)
	h.access.Unlock()
	for _, learner := range snapshot {
		learner.MaybeLearnUDP(ctx, dialer, metadata, remote)
	}
}

// ConnectionSplicerHub fans out sockmap splice attempts. First success wins
// (one connection cannot be spliced twice). Fail-open when all return false.
type ConnectionSplicerHub struct {
	access   sync.Mutex
	splicers []ConnectionSplicer
}

func NewConnectionSplicerHub() *ConnectionSplicerHub {
	return &ConnectionSplicerHub{}
}

func (h *ConnectionSplicerHub) Add(splicer ConnectionSplicer) {
	if h == nil || splicer == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for _, existing := range h.splicers {
		if existing == splicer {
			return
		}
	}
	h.splicers = append(h.splicers, splicer)
}

// Len reports how many splicers are currently registered (test/observability).
func (h *ConnectionSplicerHub) Len() int {
	if h == nil {
		return 0
	}
	h.access.Lock()
	defer h.access.Unlock()
	return len(h.splicers)
}

func (h *ConnectionSplicerHub) Remove(splicer ConnectionSplicer) {
	if h == nil || splicer == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for i, existing := range h.splicers {
		if existing == splicer {
			h.splicers = append(h.splicers[:i], h.splicers[i+1:]...)
			return
		}
	}
}

func (h *ConnectionSplicerHub) TrySpliceTCP(
	ctx context.Context,
	inboundType string,
	dialer N.Dialer,
	local net.Conn,
	remote net.Conn,
	metadata InboundContext,
	onClose N.CloseHandlerFunc,
) bool {
	if h == nil {
		return false
	}
	h.access.Lock()
	snapshot := append([]ConnectionSplicer(nil), h.splicers...)
	h.access.Unlock()
	for _, splicer := range snapshot {
		if splicer.TrySpliceTCP(ctx, inboundType, dialer, local, remote, metadata, onClose) {
			return true
		}
	}
	return false
}

// NoteRealOutbound records the leaf actually dialed by a group (smart/selector/
// urltest/loadbalance/adaptive). Shared Extended pointer keeps history/trackers in sync.
func NoteRealOutbound(ctx context.Context, leaf Outbound) {
	if leaf == nil {
		return
	}
	if metadata := ContextFrom(ctx); metadata != nil {
		metadata.AppendRealOutbound(leaf.Tag())
	}
}
