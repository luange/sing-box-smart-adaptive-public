package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	GroupCommonOption
	Default                   string `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	GroupCommonOption
	URL                       string             `json:"url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

type GroupCommonOption struct {
	Outbounds       []string                   `json:"outbounds" reference:"outbound"`
	Providers       []string                   `json:"providers" reference:"provider"`
	Exclude         *badoption.Regexp          `json:"exclude,omitempty"`
	Include         *badoption.Regexp          `json:"include,omitempty"`
	ExcludeNodes    badoption.Listable[string] `json:"exclude_nodes,omitempty"`
	NodeWeights     []NodeWeightOptions        `json:"node_weights,omitempty"`
	UseAllProviders bool                       `json:"use_all_providers,omitempty"`
}

type NodeWeightOptions struct {
	Match  string  `json:"match"`
	Weight float64 `json:"weight"`
}

type LoadBalanceOutboundOptions struct {
	GroupCommonOption
	URL         string             `json:"url,omitempty"`
	Interval    badoption.Duration `json:"interval,omitempty"`
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`
	TTL         badoption.Duration `json:"ttl,omitempty"`
	// Persistent keeps the same target host on the same available member when
	// possible, matching Surge's persistent load-balance mode.  It is
	// deliberately separate from Strategy so legacy strategy names remain
	// accepted without changing their compatibility semantics.
	Persistent                bool   `json:"persistent,omitempty"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
	Strategy                  string `json:"strategy,omitempty"`
}

type SmartOutboundOptions struct {
	GroupCommonOption
	URL string `json:"url,omitempty"`
	// ProbeFallbackURL overrides the automatic second target. Set an empty
	// string explicitly to disable fallback for a deliberately single-target
	// installation; omission chooses a different built-in target from URL.
	ProbeFallbackURL *string `json:"probe_fallback_url,omitempty"`
	// StandbyNodes uses the exclude_nodes keyword / =exact syntax. Matching
	// members remain available as the last dial attempt, but cannot become a
	// cold primary while a normal-priority member is available.
	StandbyNodes badoption.Listable[string] `json:"standby_nodes,omitempty"`
	// ApplicationFeatureLibrary points to a private Panabit .pdb package or an
	// extracted directory containing dict.so and dpi.so. sing-box reads the
	// dictionary and SNI/Host tables as data; vendor code is never executed.
	ApplicationFeatureLibrary string `json:"application_feature_library,omitempty"`
	// Mode selects Smart's primary policy: 1 (default) uses A/B/C ordering and
	// stable dispersion; 0 keeps one healthy primary until it becomes unusable.
	Mode *uint8 `json:"mode,omitempty" enum:"0,1"`
	// SelectionMode is the legacy string option; new configurations should use Mode.
	SelectionMode     string             `json:"selection_mode,omitempty" schema:"omit"`
	ProbeInterval     badoption.Duration `json:"probe_interval,omitempty"`
	ProbeCycleTimeout badoption.Duration `json:"probe_cycle_timeout,omitempty"`
	ProbeTimeout      badoption.Duration `json:"probe_timeout,omitempty"`
	ProbeConcurrency  int                `json:"probe_concurrency,omitempty"`
	// DashboardProbeBudget bounds how many candidates one panel-triggered
	// group delay test probes. 0 (default) = full probe, matching native
	// sing-box panel behavior; a positive value keeps the anti-thrash bound
	// for deployments that must not let a dashboard burst the node pool.
	DashboardProbeBudget int                `json:"dashboard_probe_budget,omitempty"`
	MaxAttempts          int                `json:"max_attempts,omitempty"`
	AttemptTimeout       badoption.Duration `json:"attempt_timeout,omitempty"`
	// EstablishedStallTimeout bounds passive first-response observation after
	// a successful dial and first write. Smart does not generate traffic.
	EstablishedStallTimeout badoption.Duration `json:"established_stall_timeout,omitempty"`
	SiteStickiness          badoption.Duration `json:"site_stickiness,omitempty"`
	// These performance gates apply to mode 1 after a business context has
	// successfully dialed its incumbent. Mode 0 is failure-only by design.
	SwitchConfirm        badoption.Duration `json:"switch_confirm,omitempty"`
	SwitchConfirmSamples int                `json:"switch_confirm_samples,omitempty"`
	SwitchCooldown       badoption.Duration `json:"switch_cooldown,omitempty"`
	SwitchMargin         *float64           `json:"switch_margin,omitempty"`
	// SwitchMinImprovement is the minimum absolute p95 latency gain required
	// for a mode-1 performance-driven switch. Omit/zero uses the 250ms default;
	// mode 0 retains its incumbent until unavailable, and hard failures in both
	// modes still fail over immediately.
	SwitchMinImprovement badoption.Duration `json:"switch_min_improvement,omitempty"`
	Exploration          *float64           `json:"exploration,omitempty"`
	MinSamples           int                `json:"min_samples,omitempty"`
	// PassiveThroughputFloorBPS is an advisory lower bound for real-traffic
	// throughput observations in bulk profiles. It never performs a probe or
	// fetches a resource, and never makes a reachable candidate ineligible;
	// Bulk scoring and status reporting use the signal after the configured
	// number of observations.
	PassiveThroughputFloorBPS uint64                      `json:"passive_throughput_floor_bps,omitempty"`
	PassiveThroughputSamples  int                         `json:"passive_throughput_samples,omitempty"`
	BreakerFailures           int                         `json:"breaker_failures,omitempty"`
	BreakerCooldown           badoption.Duration          `json:"breaker_cooldown,omitempty"`
	HalfLife                  badoption.Duration          `json:"half_life,omitempty"`
	HistoryRetention          badoption.Duration          `json:"history_retention,omitempty"`
	MaxHistoryEntries         int                         `json:"max_history_entries,omitempty"`
	InterruptConnections      bool                        `json:"interrupt_exist_connections,omitempty"`
	InterruptPolicy           SmartInterruptPolicyOptions `json:"interrupt_policy,omitempty"`
}

type SmartInterruptPolicyOptions struct {
	Mode              string             `json:"mode,omitempty"`
	IdleThreshold     badoption.Duration `json:"idle_threshold,omitempty"`
	LongConnectionAge badoption.Duration `json:"long_connection_age,omitempty"`
	GracePeriod       badoption.Duration `json:"grace_period,omitempty"`
}
