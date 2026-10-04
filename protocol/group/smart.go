package group

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/common/nodeweight"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/trafficfamily"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultSmartProbeInterval = 10 * time.Minute
	// The built-in hostname uses the configured bootstrap DNS path. Sites that
	// need literal-IP bootstrap may set url explicitly; both forms receive an
	// independent second target unless probe_fallback_url disables it.
	defaultSmartProbeURL          = "https://www.gstatic.com/generate_204"
	defaultSmartProbeFallbackURL  = "https://cp.cloudflare.com/generate_204"
	defaultSmartProbeCycleTimeout = 30 * time.Second
	defaultSmartProbeTimeout      = 5 * time.Second
	defaultSmartProbeConcurrency  = 2
	// A control-plane refresh is advisory. Keep it below the cold-start
	// baseline so opening a dashboard cannot compete with a live stream.
	defaultSmartDashboardProbeBudget  = 2
	defaultSmartUDPProbeTimeout       = 2 * time.Second
	defaultSmartUDPProbeTargetCount   = 2
	defaultSmartRecoveryProbeTimeout  = 2 * time.Second
	defaultSmartRecoveryProbeCooldown = 10 * time.Second
	defaultSmartAttemptTimeout        = 4 * time.Second
	// A real data-plane connection failure is stronger evidence than a
	// background probe result.  Quarantine only the affected site/transport
	// briefly so the next request fails over immediately without making one
	// remote service outage poison the endpoint globally.
	defaultSmartDataPlaneFailureQuarantine = 30 * time.Second
	defaultSmartSiteFailureTTL             = time.Hour
	defaultSmartEstablishedStallTimeout    = 10 * time.Second
	minSmartEstablishedStallTimeout        = 5 * time.Second
	maxSmartEstablishedStallTimeout        = 2 * time.Minute
	defaultSmartSiteStickiness             = 30 * time.Minute
	// Stable-primary defaults: performance evidence may only replace an
	// incumbent after a sustained, material improvement.  Hard protocol/data
	// plane failures bypass these gates and fail over immediately.
	defaultSmartSwitchConfirm        = 5 * time.Minute
	defaultSmartSwitchConfirmSamples = 4
	defaultSmartSwitchCooldown       = 20 * time.Minute
	defaultSmartMinSwitchImprovement = 250 * time.Millisecond
	defaultSmartHedgeDelay           = 450 * time.Millisecond
	minSmartHedgeDelay               = 250 * time.Millisecond
	// Give a healthy, already-established path a little more time for its
	// first byte before starting a competing dial.  This reduces Safari/Google
	// asset bursts that otherwise create needless hedges; hard dial failures
	// still advance immediately through the normal retry path.
	maxSmartHedgeDelay       = 900 * time.Millisecond
	defaultSmartSwitchMargin = 0.25
	smartSwitchAuditLimit    = 128
	// Active probes already rotate through the catalog. Keep the score bonus
	// small so exploration does not displace a proven path during real traffic.
	// Cold-start URLTest/recovery probes provide exploration.  Once an
	// incumbent exists, an exploration bonus must not displace it merely for a
	// small latency difference.
	defaultSmartExploration = 0.0
	defaultSmartMinSamples  = 3
	// Passive bulk quality is advisory only and consumes bytes observed on real
	// connections. 512 KiB/s is a diagnostic floor, not a reachability gate:
	// access links, response sizes and service congestion vary too widely for an
	// absolute rate to make a node circuit-open.
	defaultSmartPassiveThroughputFloorBPS = 512 * 1024
	defaultSmartPassiveThroughputSamples  = 2
	defaultSmartMaxAttempts               = 3
	defaultSmartBreakerFailures           = 5
	defaultSmartBreakerCooldown           = 2 * time.Minute
	// A half-open circuit is a recovery lease, not a normal serving state.
	// Cap leases per Smart group so a burst of site/transport contexts cannot
	// put a large fraction of the catalog back into service simultaneously.
	defaultSmartMaxHalfOpenProbes = 4
	defaultSmartHalfLife          = 30 * time.Minute
	// Homelab/router default: 48h + 4k is enough for site stickiness without
	// multi-hundred-MB metric maps (5 groups × 50k was a common RSS blow-up).
	defaultSmartHistoryRetention  = 48 * time.Hour
	defaultSmartMaxHistoryEntries = 4096
	smartStatusCandidateLimit     = 32
	smartStatusContextLimit       = 32
	smartNetworkFingerprintTTL    = 2 * time.Second
	// Background profiling follows traffic demand. A cold/idle group only
	// samples a small rotating subset; real traffic wakes a larger bounded
	// cycle. This keeps large catch-all groups from consuming the same probe
	// budget as an actively routed regional group.
	defaultSmartActivityWindow       = 15 * time.Minute
	defaultSmartIdleProbeInterval    = 30 * time.Minute
	defaultSmartColdCoverageInterval = 5 * time.Minute
	defaultSmartColdProbeBudget      = 4
	defaultSmartActiveProbeBudget    = 16
	// Status is a control-plane view, not a per-connection accounting stream.
	// Coalesce identical updates briefly so browser asset fan-out does not make
	// every dial clone the full candidate snapshot under statusAccess.
	smartStatusMinPublishInterval = 200 * time.Millisecond
	// Surge's use-score is useful for choosing which large catalogs to refresh,
	// not for overriding health ranking. Keep the decay implicit and bounded so
	// it cannot become another long-lived per-site state table.
	smartUseScoreDecayWindow = 2 * time.Hour
)

// smartSelectionMode selects between A/B/C tier dispersion and an explicit
// fixed-primary policy. Spread is the default; fixed keeps one healthy primary
// until it becomes unusable.
type smartSelectionMode uint8

const (
	smartSelectionFixed  smartSelectionMode = 0
	smartSelectionSpread smartSelectionMode = 1
)

func normalizeSmartSelectionMode(mode *uint8, legacyValue string) (smartSelectionMode, error) {
	if mode != nil {
		if legacyValue != "" {
			return smartSelectionSpread, E.New("smart mode and legacy selection_mode cannot both be set")
		}
		switch *mode {
		case uint8(smartSelectionFixed):
			return smartSelectionFixed, nil
		case uint8(smartSelectionSpread):
			return smartSelectionSpread, nil
		default:
			return smartSelectionSpread, E.New("invalid smart mode: ", *mode, " (want 0 or 1)")
		}
	}
	switch strings.ToLower(strings.TrimSpace(legacyValue)) {
	case "fixed", "adaptive", "unified", "primary_backup", "primary-backup":
		return smartSelectionFixed, nil
	case "", "spread", "scatter", "balanced", "balance", "random":
		return smartSelectionSpread, nil
	default:
		return smartSelectionSpread, E.New("invalid legacy smart selection_mode: ", legacyValue)
	}
}

// smartPhase makes cold-start behavior explicit.  A group is usable from the
// first successful dial/basic probe; only the later profiling and steady
// phases may make performance-driven changes.  Hard failures always fail over
// immediately regardless of phase.
type smartPhase uint32

const (
	smartPhaseCold smartPhase = iota
	smartPhaseBaseline
	smartPhaseProfiling
	smartPhaseSteady
)

func (p smartPhase) String() string {
	switch p {
	case smartPhaseBaseline:
		return "baseline"
	case smartPhaseProfiling:
		return "profiling"
	case smartPhaseSteady:
		return "steady"
	default:
		return "cold"
	}
}

func sniffOrDomain(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return ""
	}
	if metadata.SniffHost != "" {
		return metadata.SniffHost
	}
	return metadata.Domain
}

// normalizeSmartHostname canonicalizes the host obtained from SNI/Host or a
// destination FQDN before it reaches traffic-family and public-suffix logic.
// Sniffers may include a port, a trailing root dot, mixed case, or Unicode;
// treating those spellings as different sites would fragment the portrait and
// make stable dispersion appear unstable.
func normalizeSmartHostname(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else if strings.Count(host, ":") == 1 {
		// SplitHostPort rejects an unbracketed hostname with a non-numeric or
		// missing port in some sniffing paths. Only strip the suffix when it is
		// unambiguously a host:port form.
		if index := strings.LastIndexByte(host, ':'); index > 0 && index < len(host)-1 {
			if _, err := strconv.ParseUint(host[index+1:], 10, 16); err == nil {
				host = host[:index]
			}
		}
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}
	return host
}

func RegisterSmart(registry *outbound.Registry) {
	outbound.Register[option.SmartOutboundOptions](registry, C.TypeSmart, NewSmart)
}

var (
	_ adapter.SmartGroup            = (*Smart)(nil)
	_ adapter.DashboardURLTestGroup = (*Smart)(nil)
	_ adapter.PreMatchOutboundGroup = (*Smart)(nil)
)

var errSmartNoCandidates = errors.New("smart group has no leaf candidates")

const (
	smartProbeRequestNormal uint32 = 1 << iota
	smartProbeRequestDashboard
)

// smartDashboardProbeKey marks a ranking/probe operation initiated by a
// dashboard delay request. Dashboard probes are advisory: they may refresh
// latency counters, but they must never become a hidden selection command or
// open/close a circuit that can evict a manual pin. The marker is carried
func withSmartDashboardProbe(ctx context.Context) context.Context {
	return adapter.WithDashboardProbe(ctx)
}

func isSmartDashboardProbe(ctx context.Context) bool {
	return adapter.IsDashboardProbe(ctx)
}

type smartProbePurpose uint8

const (
	smartProbeBackground smartProbePurpose = iota
	smartProbeDashboard
	smartProbeRecovery
	smartProbeTransportCoverage
)

type smartProbePolicy struct {
	advisory           bool
	force              bool
	retryAfterInflight bool
	publishLatest      bool
	allowPenalty       bool
}

func (purpose smartProbePurpose) policy() smartProbePolicy {
	switch purpose {
	case smartProbeDashboard:
		return smartProbePolicy{advisory: true}
	case smartProbeRecovery:
		return smartProbePolicy{force: true, retryAfterInflight: true, publishLatest: true, allowPenalty: true}
	case smartProbeTransportCoverage:
		return smartProbePolicy{publishLatest: true, allowPenalty: true}
	default:
		return smartProbePolicy{publishLatest: true, allowPenalty: true}
	}
}

func smartProbePurposeFromContext(ctx context.Context) smartProbePurpose {
	if isSmartDashboardProbe(ctx) {
		return smartProbeDashboard
	}
	return smartProbeBackground
}

type smartProbeRequest struct {
	purpose     smartProbePurpose
	endpointKey string
	profileKey  string
	timeout     time.Duration
	ttl         time.Duration
}

// executeProbe is Smart's only entry into the shared active-probe registry.
// The purpose controls evidence permissions while the registry controls
// cadence and concurrency. A dashboard measurement therefore cannot acquire
// recovery semantics merely because it happens to call the same URLTest code.
func (s *Smart) executeProbe(ctx context.Context, request smartProbeRequest, probe func(context.Context) (uint16, error)) (uint16, error, bool) {
	if s == nil || s.probeRegistry == nil {
		return 0, errSharedNodeProbeFailed, false
	}
	policy := request.purpose.policy()
	return s.probeRegistry.executeProbe(ctx, nodeProfileProbeRequest{
		EndpointKey:        request.endpointKey,
		ProfileKey:         request.profileKey,
		Timeout:            request.timeout,
		TTL:                request.ttl,
		Force:              policy.force,
		RetryAfterInflight: policy.retryAfterInflight,
	}, probe)
}

type smartAffinity struct {
	Candidate string
	ExpiresAt time.Time
}

type smartUseScore struct {
	Score    float64
	LastUsed time.Time
}

type smartRank struct {
	outbound             adapter.Outbound
	identity             string
	dialIdentity         string
	probeKey             string
	policyID             uint64
	selectionGeneration  uint64
	weight               nodeweight.Match
	status               adapter.SmartCandidateStatus
	profile              smartTrafficProfile
	estimate             smartEstimate
	scoreEstimate        smartEstimate
	eligible             bool
	passiveThroughputLow bool
	activeProbeDegraded  bool
	standbyOnly          bool
	incumbent            bool
	siteTainted          bool
	siteSuccesses        float64
	siteDelayMS          float64
	surgeBand            uint8
	surgeOrder           uint64
}

// smartCandidateMetadata is built when providers refresh, not while ranking
// each new connection. Path identity/probe key are shared for network probing;
// dial identity/profile/policy are credential-aware for real data-plane health
// and retry diversity. These immutable fields change only on catalog refresh.
type smartCandidateMetadata struct {
	identity     string
	dialIdentity string
	profileID    string
	probeKey     string
	policyID     uint64
	weight       nodeweight.Match
	standbyOnly  bool
}

// smartEndpointID returns the safe, stable identity exposed by Smart status
// and switch audit records. Structured provider identities are already
// content-addressed (endpoint:<sha256>); legacy/static candidates use the
// policy hash so a raw tag, URL, or credential can never leak through the API.
func smartEndpointID(identity string, policyID uint64) string {
	if strings.HasPrefix(identity, "endpoint:") {
		return identity
	}
	if policyID != 0 {
		return "policy:" + strconv.FormatUint(policyID, 16)
	}
	return ""
}

func (s *Smart) buildCandidateMetadata(tag, identity string) smartCandidateMetadata {
	return s.buildCandidateMetadataWithDialIdentity(tag, identity, identity)
}

func (s *Smart) buildCandidateMetadataWithDialIdentity(tag, identity, dialIdentity string) smartCandidateMetadata {
	probeIdentity := identity
	if probeIdentity == "" {
		probeIdentity = tag
	}
	if dialIdentity == "" {
		dialIdentity = probeIdentity
	}
	metadata := smartCandidateMetadata{
		identity:     probeIdentity,
		dialIdentity: dialIdentity,
		profileID:    tag,
		// An active URL test traverses the authenticated proxy path. Its result
		// therefore belongs to DialIdentity, while registry admission remains
		// serialized by the credential-free endpoint identity.
		probeKey:    nodeProfileKey(dialIdentity, s.probeProfileLink(N.NetworkTCP), 0),
		weight:      s.nodeWeights.Explain(tag),
		standbyOnly: s.standbyNodes.Match(tag),
	}
	if dialIdentity != "" && dialIdentity != tag {
		metadata.profileID = "dial:" + dialIdentity
	}
	// Every candidate must have a stable policy identity. Provider-backed aliases
	// with the same credential share one Zig state; distinct credentials remain
	// separate even when they use the same network path. Static/test candidates
	// use their stable tag and must not be silently omitted from Zig-only builds.
	policyIdentity := metadata.dialIdentity
	if identity == "" {
		// Provider duplicate resolvers append " #deadbeef" or " (2)" to a
		// display tag. Treat those generated aliases as one policy candidate so
		// equal lines do not create a false performance challenge.
		policyIdentity = smartLineFamily(tag)
	}
	if policyIdentity == "" {
		policyIdentity = tag
	}
	if policyIdentity != "" {
		metadata.policyID = smartPolicyID(policyIdentity)
	}
	return metadata
}

type smartRanking struct {
	ranks                    []smartRank
	candidates               []adapter.Outbound
	policyUnavailable        bool
	statusKey                string
	policySelectedEndpointID string
	snapshotSelected         string
	snapshotSelectedAt       time.Time
	snapshotGeneration       uint64
	snapshotValid            bool
	rankBuffer               *[]smartRank
	candidateBuffer          *[]adapter.Outbound
}

type smartDialAttempt struct {
	rankIndex    int
	attemptIndex int
	rank         smartRank
	candidate    adapter.Outbound
	reserved     bool
}

type smartDialResult struct {
	attempt           smartDialAttempt
	conn              net.Conn
	err               error
	elapsed           time.Duration
	hadPriorFailure   bool
	observedTransport string
}

var smartRankPool = sync.Pool{New: func() any {
	buffer := make([]smartRank, 0, 64)
	return &buffer
}}

var smartCandidatePool = sync.Pool{New: func() any {
	buffer := make([]adapter.Outbound, 0, 64)
	return &buffer
}}

func acquireSmartRanking(candidateCount int) *smartRanking {
	rankBuffer := smartRankPool.Get().(*[]smartRank)
	ranks := *rankBuffer
	if cap(ranks) < candidateCount {
		ranks = make([]smartRank, 0, candidateCount)
	}
	candidateBuffer := smartCandidatePool.Get().(*[]adapter.Outbound)
	candidates := *candidateBuffer
	if cap(candidates) < candidateCount {
		candidates = make([]adapter.Outbound, 0, candidateCount)
	}
	return &smartRanking{
		ranks:              ranks[:0],
		candidates:         candidates[:0],
		policyUnavailable:  false,
		snapshotSelected:   "",
		snapshotSelectedAt: time.Time{},
		snapshotGeneration: 0,
		statusKey:          "",
		snapshotValid:      false,
		rankBuffer:         rankBuffer,
		candidateBuffer:    candidateBuffer,
	}
}

func (r *smartRanking) Release() {
	if r == nil {
		return
	}
	clear(r.ranks)
	clear(r.candidates)
	r.policyUnavailable = false
	r.snapshotSelected = ""
	r.snapshotSelectedAt = time.Time{}
	r.snapshotGeneration = 0
	r.statusKey = ""
	r.policySelectedEndpointID = ""
	r.snapshotValid = false
	if cap(r.ranks) <= 4096 {
		*r.rankBuffer = r.ranks[:0]
		smartRankPool.Put(r.rankBuffer)
	}
	if cap(r.candidates) <= 4096 {
		*r.candidateBuffer = r.candidates[:0]
		smartCandidatePool.Put(r.candidateBuffer)
	}
	r.ranks = nil
	r.candidates = nil
	r.rankBuffer = nil
	r.candidateBuffer = nil
}

type smartFingerprintCache struct {
	value     string
	expiresAt int64
}

type smartControlState struct {
	access          sync.Mutex
	pinned          string
	pinnedEndpoint  string
	pinnedDial      string
	temporary       string
	temporaryUntil  time.Time
	temporaryReason string
}

type Smart struct {
	outbound.Adapter
	ctx        context.Context
	outbound   adapter.OutboundManager
	connection adapter.ConnectionManager
	network    adapter.NetworkManager
	logger     log.ContextLogger
	tags       []string

	provider              adapter.ProviderManager
	providerAccess        sync.Mutex
	providerRevision      uint64
	providers             map[string]adapter.Provider
	providerHandles       map[string]*list.Element[adapter.ProviderUpdateCallback]
	providerObserver      adapter.ProviderManagerObserver
	providerManagerHandle *list.Element[adapter.ProviderManagerUpdateCallback]
	outboundsCache        map[string][]adapter.Outbound
	providerTags          []string
	// providerRebuild* coalesce callback bursts without sacrificing the final
	// snapshot. A provider may publish several callbacks while its own refresh
	// is still assembling; only the currently running rebuild is allowed to call
	// provider code, and a trailing pass always consumes the newest revision.
	providerRebuildAccess  sync.Mutex
	providerRebuildRunning bool
	providerRebuildPending bool
	providerRebuildTag     string
	exclude                *regexp.Regexp
	include                *regexp.Regexp
	manualExclude          *nodefilter.Matcher
	standbyNodes           *nodefilter.Matcher
	nodeWeights            *nodeweight.Matcher
	useAllProviders        bool

	access                 sync.RWMutex
	candidates             []adapter.Outbound
	candidateByTag         map[string]adapter.Outbound
	candidateMetadataByTag map[string]smartCandidateMetadata
	control                *smartControlState
	lastSelected           map[string]string
	lastSelectedAt         map[string]time.Time
	affinity               map[string]smartAffinity
	switchChallenges       map[string]smartSwitchChallenge
	performanceCooldown    map[string]time.Time
	useScores              map[string]smartUseScore
	probeLastAt            map[string]time.Time
	probeAttemptAt         map[string]time.Time
	udpProbeLastAt         map[string]time.Time
	halfOpen               map[string]struct{}
	halfOpenActive         int
	// selectionGeneration is keyed by the dashboard context (network/site/
	// transport). It changes only when the canonical EndpointID changes, so
	// provider aliases do not look like a data-plane switch.
	selectionGeneration map[string]uint64
	zigSelectedEndpoint map[string]string
	actualDialEndpoint  map[string]string
	circuitState        map[string]string
	latest              common.TypedValue[adapter.Outbound]
	fingerprint         atomic.Pointer[smartFingerprintCache]
	fingerprintLock     sync.Mutex

	statusAccess       sync.RWMutex
	status             adapter.SmartGroupStatus
	statusContexts     map[string]adapter.SmartContextStatus
	statusContextOrder []string
	statusLastAt       time.Time
	statusLastContext  string
	statusLastSelected string
	statusLastReason   string
	statusLastPhase    string

	store                      *smartStore
	policyBackend              smartPolicyBackend
	policyBackendAccess        sync.RWMutex
	probeURL                   string
	probeFallbackURL           string
	probeTargetAccess          sync.Mutex
	probeTargetCounters        [2]adapter.SmartProbeTargetStatus
	probeInterval              time.Duration
	probeCycleTimeout          time.Duration
	probeTimeout               time.Duration
	probeConcurrency           int
	selectionMode              smartSelectionMode
	dashboardProbeBudget       int
	familyProbeEnabled         bool
	maxAttempts                int
	attemptTimeout             time.Duration
	establishedStallTimeout    time.Duration
	siteStickiness             time.Duration
	switchConfirm              time.Duration
	switchConfirmSamples       int
	switchCooldown             time.Duration
	switchMargin               float64
	switchMinImprovement       time.Duration
	exploration                float64
	minSamples                 int
	passiveThroughputFloorBPS  uint64
	passiveThroughputSamples   int
	halfLife                   time.Duration
	breakerFailures            int
	breakerCooldown            time.Duration
	maxHistoryEntries          int
	interruptGroup             *interrupt.Group
	interruptMode              string
	interruptIdle              time.Duration
	interruptLongAge           time.Duration
	interruptGrace             time.Duration
	switchesTotal              atomic.Uint64
	performanceSwitches        atomic.Uint64
	failureFailovers           atomic.Uint64
	coldStarts                 atomic.Uint64
	switchAuditAccess          sync.Mutex
	switchAudit                []adapter.SmartSwitchAudit
	switchesForceAll           atomic.Uint64
	switchesSelective          atomic.Uint64
	connectionsInterrupted     atomic.Uint64
	connectionsKept            atomic.Uint64
	streamFailureWakes         atomic.Uint64
	selectionMismatchTotal     atomic.Uint64
	unobservedConnectionTotal  atomic.Uint64
	lastFailureType            atomic.Pointer[string]
	recoveryProbeUntilUnixNano atomic.Int64
	probing                    atomic.Bool
	probeCursor                atomic.Uint64
	udpProbeCursor             atomic.Uint64
	phase                      atomic.Uint32
	phaseInitialized           atomic.Bool
	successfulProbeCycles      atomic.Uint32
	lastActivityUnixNano       atomic.Int64
	closing                    atomic.Bool
	cancel                     context.CancelFunc
	worker                     sync.WaitGroup
	lifecycleAccess            sync.Mutex
	postStarted                bool
	retired                    bool
	workerStarted              bool
	probeRegistry              *nodeProfileRegistry
	releaseProbeRegistry       func()
	probeStartupDelay          time.Duration
	probeNow                   chan struct{}
	manualProbeBudget          atomic.Int32
	probeRequestMode           atomic.Uint32
	families                   *trafficfamily.Resolver
}

type smartSwitchChallenge struct {
	Candidate string
	Since     time.Time
	Count     int
}

func NewSmart(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SmartOutboundOptions) (adapter.Outbound, error) {
	applicationCatalog, catalogStats, err := trafficfamily.LoadApplicationCatalog(options.ApplicationFeatureLibrary)
	if err != nil {
		return nil, E.Cause(err, "load smart application feature library")
	}
	if applicationCatalog != nil && logger != nil {
		logger.Info("smart application feature library: applications=", catalogStats.Applications,
			", sni=", catalogStats.SNI, ", host=", catalogStats.Host,
			", invalid=", catalogStats.Invalid, ", ambiguous=", catalogStats.Ambiguous)
	}
	manualExclude, err := nodefilter.New([]string(options.ExcludeNodes))
	if err != nil {
		return nil, err
	}
	standbyNodes, err := nodefilter.New([]string(options.StandbyNodes))
	if err != nil {
		return nil, E.Cause(err, "smart standby_nodes")
	}
	weightRules := make([]nodeweight.Rule, len(options.NodeWeights))
	for index, rule := range options.NodeWeights {
		weightRules[index] = nodeweight.Rule{Match: rule.Match, Weight: rule.Weight}
	}
	nodeWeights, err := nodeweight.New(weightRules)
	if err != nil {
		return nil, err
	}
	probeURL := normalizeSmartProbeURL(options.URL)
	probeFallbackURL, err := normalizeSmartProbeFallbackURL(probeURL, options.ProbeFallbackURL)
	if err != nil {
		return nil, err
	}
	selectionMode, err := normalizeSmartSelectionMode(options.Mode, options.SelectionMode)
	if err != nil {
		return nil, err
	}
	probeInterval := time.Duration(options.ProbeInterval)
	if probeInterval <= 0 {
		probeInterval = defaultSmartProbeInterval
	}
	probeCycleTimeout := time.Duration(options.ProbeCycleTimeout)
	if probeCycleTimeout <= 0 {
		probeCycleTimeout = defaultSmartProbeCycleTimeout
	}
	probeTimeout := time.Duration(options.ProbeTimeout)
	if probeTimeout <= 0 {
		probeTimeout = defaultSmartProbeTimeout
	}
	probeConcurrency := options.ProbeConcurrency
	if probeConcurrency <= 0 {
		probeConcurrency = defaultSmartProbeConcurrency
	}
	if probeConcurrency > 4 {
		probeConcurrency = 4
	}
	// 0 (default) restores the native full group probe for panels; a positive
	// bound keeps the dashboard anti-thrash budget.
	dashboardProbeBudget := options.DashboardProbeBudget
	if dashboardProbeBudget < 0 {
		dashboardProbeBudget = 0
	}
	if probeCycleTimeout < probeTimeout {
		probeCycleTimeout = probeTimeout
	}
	maxAttempts := options.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	attemptTimeout := time.Duration(options.AttemptTimeout)
	if attemptTimeout <= 0 {
		attemptTimeout = defaultSmartAttemptTimeout
	}
	establishedStallTimeout := time.Duration(options.EstablishedStallTimeout)
	if establishedStallTimeout <= 0 {
		establishedStallTimeout = defaultSmartEstablishedStallTimeout
	}
	if establishedStallTimeout < minSmartEstablishedStallTimeout || establishedStallTimeout > maxSmartEstablishedStallTimeout {
		return nil, E.New("smart established_stall_timeout must be between 5s and 2m")
	}
	siteStickiness := time.Duration(options.SiteStickiness)
	if siteStickiness <= 0 {
		siteStickiness = defaultSmartSiteStickiness
	}
	switchConfirm := time.Duration(options.SwitchConfirm)
	if switchConfirm <= 0 {
		switchConfirm = defaultSmartSwitchConfirm
	}
	if switchConfirm < 5*time.Second {
		return nil, E.New("smart switch_confirm must be at least 5s")
	}
	switchConfirmSamples := options.SwitchConfirmSamples
	if switchConfirmSamples <= 0 {
		switchConfirmSamples = defaultSmartSwitchConfirmSamples
	}
	switchCooldown := time.Duration(options.SwitchCooldown)
	if switchCooldown <= 0 {
		switchCooldown = defaultSmartSwitchCooldown
	}
	switchMargin := defaultSmartSwitchMargin
	if options.SwitchMargin != nil {
		switchMargin = max(0, *options.SwitchMargin)
	}
	if switchMargin >= 1 {
		return nil, E.New("smart switch_margin must be less than 1")
	}
	switchMinImprovement := time.Duration(options.SwitchMinImprovement)
	if switchMinImprovement == 0 {
		switchMinImprovement = defaultSmartMinSwitchImprovement
	}
	if switchMinImprovement < 0 {
		return nil, E.New("smart switch_min_improvement must not be negative")
	}
	exploration := defaultSmartExploration
	if options.Exploration != nil {
		exploration = max(0, *options.Exploration)
	}
	minSamples := options.MinSamples
	if minSamples <= 0 {
		minSamples = defaultSmartMinSamples
	}
	passiveThroughputFloorBPS := options.PassiveThroughputFloorBPS
	if passiveThroughputFloorBPS == 0 {
		passiveThroughputFloorBPS = defaultSmartPassiveThroughputFloorBPS
	}
	passiveThroughputSamples := options.PassiveThroughputSamples
	if passiveThroughputSamples <= 0 {
		passiveThroughputSamples = defaultSmartPassiveThroughputSamples
	}
	if passiveThroughputSamples < 2 {
		return nil, E.New("smart passive_throughput_samples must be at least 2")
	}
	breakerFailures := options.BreakerFailures
	if breakerFailures <= 0 {
		breakerFailures = defaultSmartBreakerFailures
	}
	breakerCooldown := time.Duration(options.BreakerCooldown)
	if breakerCooldown <= 0 {
		breakerCooldown = defaultSmartBreakerCooldown
	}
	halfLife := time.Duration(options.HalfLife)
	if halfLife <= 0 {
		halfLife = defaultSmartHalfLife
	}
	historyRetention := time.Duration(options.HistoryRetention)
	if historyRetention <= 0 {
		historyRetention = defaultSmartHistoryRetention
	}
	maxHistoryEntries := options.MaxHistoryEntries
	if maxHistoryEntries <= 0 {
		maxHistoryEntries = defaultSmartMaxHistoryEntries
	}
	interruptMode := options.InterruptPolicy.Mode
	if interruptMode == "" {
		if options.InterruptConnections {
			interruptMode = "all"
		} else {
			// A Smart switch is an endpoint migration, not a load-balance hint:
			// close old business connections by default so one logical service
			// cannot keep using two egress IPs after the decision changes.
			interruptMode = "all"
		}
	}
	if interruptMode != "none" && interruptMode != "selective" && interruptMode != "all" {
		return nil, E.New("invalid smart interrupt_policy.mode: ", interruptMode)
	}
	interruptIdle := time.Duration(options.InterruptPolicy.IdleThreshold)
	if interruptIdle <= 0 {
		interruptIdle = 10 * time.Second
	}
	if interruptIdle < 5*time.Second {
		return nil, E.New("smart interrupt_policy.idle_threshold must be at least 5s")
	}
	interruptLongAge := time.Duration(options.InterruptPolicy.LongConnectionAge)
	if interruptLongAge <= 0 {
		interruptLongAge = 30 * time.Second
	}
	if interruptLongAge < 15*time.Second {
		return nil, E.New("smart interrupt_policy.long_connection_age must be at least 15s")
	}
	interruptGrace := time.Duration(options.InterruptPolicy.GracePeriod)
	if interruptGrace <= 0 {
		interruptGrace = 3 * time.Second
	}
	if options.InterruptPolicy.Mode != "" && options.InterruptConnections && logger != nil {
		logger.Warn("smart interrupt_policy overrides deprecated interrupt_exist_connections")
	}
	store := newSmartStore(halfLife, breakerFailures, breakerCooldown)
	store.setBounds(historyRetention, maxHistoryEntries)
	policyBackend := newSmartPolicyBackend(smartPolicyBackendConfig{
		Exploration: exploration, SwitchMargin: switchMargin,
		SwitchConfirm: switchConfirmSamples, SwitchConfirmWindow: switchConfirm.Milliseconds(),
		SwitchCooldown: switchCooldown.Milliseconds(), SiteStickiness: siteStickiness.Milliseconds(),
		SwitchMinImprovement: switchMinImprovement.Milliseconds(),
		MinSamples:           minSamples,
		SelectionMode:        uint8(selectionMode),
	})
	if policyBackend == nil && smartPolicyBackendRequired() {
		return nil, E.New("smart Zig policy backend unavailable; refusing Go policy fallback")
	}
	if logger != nil {
		if policyBackend == nil {
			logger.Warn("smart policy backend unavailable; using reference Go policy")
		} else {
			logger.Info("smart policy backend: zig, mode: ", uint8(selectionMode))
		}
	}
	outboundManager := service.FromContext[adapter.OutboundManager](ctx)
	probeRegistry, releaseProbeRegistry := acquireSmartProfileRegistry(ctx, outboundManager)
	smart := &Smart{
		Adapter:    outbound.NewAdapter(C.TypeSmart, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:        ctx,
		outbound:   outboundManager,
		connection: service.FromContext[adapter.ConnectionManager](ctx),
		network:    service.FromContext[adapter.NetworkManager](ctx),
		logger:     logger,
		tags:       options.Outbounds,

		provider:        service.FromContext[adapter.ProviderManager](ctx),
		providers:       make(map[string]adapter.Provider),
		providerHandles: make(map[string]*list.Element[adapter.ProviderUpdateCallback]),
		outboundsCache:  make(map[string][]adapter.Outbound),
		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		manualExclude:   manualExclude,
		standbyNodes:    standbyNodes,
		nodeWeights:     nodeWeights,
		useAllProviders: options.UseAllProviders,

		candidateByTag:         make(map[string]adapter.Outbound),
		candidateMetadataByTag: make(map[string]smartCandidateMetadata),
		control:                &smartControlState{},
		lastSelected:           make(map[string]string),
		lastSelectedAt:         make(map[string]time.Time),
		affinity:               make(map[string]smartAffinity),
		switchChallenges:       make(map[string]smartSwitchChallenge),
		performanceCooldown:    make(map[string]time.Time),
		useScores:              make(map[string]smartUseScore),
		probeLastAt:            make(map[string]time.Time),
		probeAttemptAt:         make(map[string]time.Time),
		udpProbeLastAt:         make(map[string]time.Time),
		halfOpen:               make(map[string]struct{}),
		selectionGeneration:    make(map[string]uint64),
		zigSelectedEndpoint:    make(map[string]string),
		actualDialEndpoint:     make(map[string]string),
		circuitState:           make(map[string]string),
		store:                  store,
		policyBackend:          policyBackend,

		probeURL:                  probeURL,
		probeFallbackURL:          probeFallbackURL,
		probeInterval:             probeInterval,
		probeCycleTimeout:         probeCycleTimeout,
		probeTimeout:              probeTimeout,
		probeConcurrency:          probeConcurrency,
		familyProbeEnabled:        true,
		maxAttempts:               maxAttempts,
		attemptTimeout:            attemptTimeout,
		establishedStallTimeout:   establishedStallTimeout,
		siteStickiness:            siteStickiness,
		switchConfirm:             switchConfirm,
		switchConfirmSamples:      switchConfirmSamples,
		switchCooldown:            switchCooldown,
		switchMargin:              switchMargin,
		switchMinImprovement:      switchMinImprovement,
		exploration:               exploration,
		minSamples:                minSamples,
		passiveThroughputFloorBPS: passiveThroughputFloorBPS,
		passiveThroughputSamples:  passiveThroughputSamples,
		halfLife:                  halfLife,
		breakerFailures:           breakerFailures,
		breakerCooldown:           breakerCooldown,
		maxHistoryEntries:         maxHistoryEntries,
		interruptGroup:            interrupt.NewGroup(),
		interruptMode:             interruptMode,
		interruptIdle:             interruptIdle,
		interruptLongAge:          interruptLongAge,
		interruptGrace:            interruptGrace,
		probeRegistry:             probeRegistry,
		releaseProbeRegistry:      releaseProbeRegistry,
		probeStartupDelay:         probeRegistry.registerSmartScheduler(),
		probeNow:                  make(chan struct{}, 1),
		families:                  trafficfamily.NewResolverWithCatalog(applicationCatalog),
	}
	return smart, nil
}

// normalizeSmartProbeURL supplies the built-in probe when omitted and
// canonicalizes its legacy spelling. Explicit operator targets are preserved.
func normalizeSmartProbeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultSmartProbeURL
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "www.gstatic.com") {
		return trimmed
	}
	return defaultSmartProbeURL
}

func normalizeSmartProbeFallbackURL(primary string, configured *string) (string, error) {
	if configured != nil {
		fallback := strings.TrimSpace(*configured)
		if fallback == "" {
			return "", nil
		}
		parsed, err := url.Parse(fallback)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return "", E.New("smart probe_fallback_url must be an HTTPS URL")
		}
		if fallback == primary {
			return "", E.New("smart probe_fallback_url must differ from url")
		}
		return fallback, nil
	}
	if primary == defaultSmartProbeURL {
		return defaultSmartProbeFallbackURL, nil
	}
	return defaultSmartProbeURL, nil
}

// probeURLWithFallback keeps each target's hostname and SNI intact. A failed
// primary receives only part of the cycle deadline, reserving time for the
// independent fallback even when the first URL hangs until its timeout.
func (s *Smart) probeURLWithFallback(ctx context.Context, candidate adapter.Outbound, family string, shared bool) (uint16, error) {
	return s.probeTargetsWithFallback(ctx, func(probeCtx context.Context, target string) (uint16, error) {
		if family != "" {
			return urltest.URLTestWithNetwork(probeCtx, target, candidate, smartProbeNetwork(family))
		}
		if shared && s.probeRegistry != nil {
			return s.probeRegistry.probe(probeCtx, target, candidate)
		}
		return urltest.URLTest(probeCtx, target, candidate)
	})
}

func (s *Smart) probeTargetsWithFallback(ctx context.Context, probe func(context.Context, string) (uint16, error)) (uint16, error) {
	urls := []string{s.probeURL}
	if s.probeFallbackURL != "" && s.probeFallbackURL != s.probeURL {
		urls = append(urls, s.probeFallbackURL)
	}
	var lastErr error
	for index, target := range urls {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		attemptCtx, cancel := smartProbeAttemptContext(ctx, len(urls)-index, s.probeTimeout)
		var observation urltest.ProbeObservation
		observed := false
		attemptCtx = urltest.WithProbeObserver(attemptCtx, func(value urltest.ProbeObservation) {
			observation = value
			observed = true
		})
		delay, err := probe(attemptCtx, target)
		cancel()
		if err == nil && observed && observation.Stage == "target_response" && !smartProbeHTTPStatusAccepted(target, observation.HTTPStatus) {
			err = smartProbeTargetStatusError{Status: observation.HTTPStatus}
		}
		if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return 0, ctx.Err()
		}
		s.noteProbeTargetObservation(index, target, err, observation)
		if err == nil {
			return delay, nil
		}
		lastErr = err
	}
	return 0, lastErr
}

type smartProbeTargetStatusError struct{ Status int }

func (e smartProbeTargetStatusError) Error() string {
	return "probe target HTTP status: " + strconv.Itoa(e.Status)
}

func smartProbeUpstreamHTTPStatus(err error) int {
	if err == nil {
		return 0
	}
	message := strings.ToLower(err.Error())
	const marker = "unexpected http response status:"
	index := strings.Index(message, marker)
	if index < 0 {
		return 0
	}
	fields := strings.Fields(message[index+len(marker):])
	if len(fields) == 0 {
		return 0
	}
	status, _ := strconv.Atoi(fields[0])
	return status
}

func smartProbeTargetIncident(err error) bool {
	var targetStatus smartProbeTargetStatusError
	if errors.As(err, &targetStatus) {
		return true
	}
	switch smartProbeUpstreamHTTPStatus(err) {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusUnavailableForLegalReasons:
		// A CONNECT upstream may refuse the health target while the same node
		// carries ordinary business. This is target scope, not node evidence.
		return true
	default:
		return false
	}
}

func smartProbeHTTPStatusAccepted(target string, status int) bool {
	if status == 0 {
		return true // Embedded probes without an HTTP observer keep their contract.
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	switch {
	case strings.HasSuffix(parsed.Path, "generate_204"):
		return status == http.StatusNoContent
	case parsed.Path == "/cdn-cgi/trace":
		return status == http.StatusOK
	default:
		return status >= http.StatusOK && status < http.StatusMultipleChoices
	}
}

func smartProbeAttemptContext(ctx context.Context, remainingTargets int, configuredTimeout time.Duration) (context.Context, context.CancelFunc) {
	if deadline, loaded := ctx.Deadline(); loaded {
		if remainingTargets <= 1 {
			return ctx, func() {}
		}
		remaining := time.Until(deadline)
		return context.WithTimeout(ctx, max(time.Millisecond, remaining/time.Duration(remainingTargets)))
	}
	if configuredTimeout <= 0 {
		configuredTimeout = defaultSmartProbeTimeout
	}
	return context.WithTimeout(ctx, configuredTimeout)
}

func smartProbeFailureClass(err error) string {
	if err == nil {
		return ""
	}
	var targetStatus smartProbeTargetStatusError
	if errors.As(err, &targetStatus) {
		return "target_http_status"
	}
	var networkError net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &networkError) && networkError.Timeout():
		return "timeout"
	case strings.Contains(strings.ToLower(err.Error()), "unexpected http response status"):
		return "upstream_http_status"
	case strings.Contains(strings.ToLower(err.Error()), "tls"), strings.Contains(strings.ToLower(err.Error()), "certificate"):
		return "tls"
	default:
		return "transport"
	}
}

func smartProbeTargetHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func (s *Smart) noteProbeTargetResult(index int, target string, err error) {
	s.noteProbeTargetObservation(index, target, err, urltest.ProbeObservation{})
}

func (s *Smart) noteProbeTargetObservation(index int, target string, err error, observation urltest.ProbeObservation) {
	if index < 0 || index >= len(s.probeTargetCounters) {
		return
	}
	s.probeTargetAccess.Lock()
	stat := &s.probeTargetCounters[index]
	stat.TargetHost = smartProbeTargetHost(target)
	stat.Attempts++
	if observation.HTTPStatus != 0 {
		stat.LastHTTPStatus = observation.HTTPStatus
	} else if status := smartProbeUpstreamHTTPStatus(err); status != 0 {
		stat.LastHTTPStatus = status
	}
	if err == nil {
		stat.Successes++
	} else {
		stat.Failures++
		stat.LastFailureClass = smartProbeFailureClass(err)
		stat.LastFailureStage = observation.Stage
		if stat.LastFailureStage == "" {
			stat.LastFailureStage = "unknown"
		}
		switch stat.LastFailureStage {
		case "dns":
			stat.DNSFailures++
		case "proxy_handshake":
			stat.ProxyHandshakeFailures++
		}
		switch stat.LastFailureClass {
		case "timeout":
			stat.Timeouts++
		case "target_http_status":
			stat.TargetHTTPFailures++
			stat.HTTPFailures++
		case "upstream_http_status":
			stat.HTTPFailures++
		case "tls":
			stat.TLSFailures++
		default:
			stat.TransportFailures++
		}
	}
	s.probeTargetAccess.Unlock()
}

func (s *Smart) probeTargetSnapshot() [2]adapter.SmartProbeTargetStatus {
	s.probeTargetAccess.Lock()
	result := s.probeTargetCounters
	s.probeTargetAccess.Unlock()
	result[0].TargetHost = smartProbeTargetHost(s.probeURL)
	result[1].TargetHost = smartProbeTargetHost(s.probeFallbackURL)
	return result
}

func (s *Smart) probeProfileLink(transport string) string {
	// A result obtained through a fallback target cannot be reused by another
	// group that has the same primary but a different fallback contract.
	if s.probeFallbackURL == "" {
		return s.probeURL + "\x00" + transport
	}
	return s.probeURL + "\x00" + s.probeFallbackURL + "\x00" + transport
}

func (s *Smart) Start() error {
	var (
		providerTags []string
		resolved     = make(map[string]adapter.Provider)
	)
	if s.useAllProviders {
		for _, provider := range s.provider.Providers() {
			if provider == nil || provider.Tag() == "" {
				continue
			}
			tag := provider.Tag()
			if _, exists := resolved[tag]; exists {
				continue
			}
			providerTags = append(providerTags, tag)
			resolved[tag] = provider
		}
	} else {
		s.providerAccess.Lock()
		configuredTags := append([]string(nil), s.providerTags...)
		s.providerAccess.Unlock()
		for index, tag := range configuredTags {
			if _, exists := resolved[tag]; exists {
				continue
			}
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", index, " not found: ", tag)
			}
			providerTags = append(providerTags, tag)
			resolved[tag] = provider
		}
	}
	s.providerAccess.Lock()
	if s.providerHandles == nil {
		s.providerHandles = make(map[string]*list.Element[adapter.ProviderUpdateCallback])
	}
	s.providerTags = providerTags
	s.providerRevision++
	for _, tag := range providerTags {
		s.providers[tag] = resolved[tag]
		s.providerHandles[tag] = nil
	}
	useAll := s.useAllProviders
	manager := s.provider
	s.providerAccess.Unlock()
	for _, tag := range providerTags {
		s.attachSmartProviderCallback(tag, resolved[tag])
	}
	if useAll {
		if observer, ok := manager.(adapter.ProviderManagerObserver); ok {
			handle := observer.RegisterProviderCallback(s.onProviderManagerUpdated)
			s.providerAccess.Lock()
			if s.closing.Load() {
				s.providerAccess.Unlock()
				if handle != nil {
					observer.UnregisterProviderCallback(handle)
				}
			} else {
				s.providerObserver = observer
				s.providerManagerHandle = handle
				s.providerAccess.Unlock()
			}
		}
	}
	if len(s.tags)+len(providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}
	if err := s.rebuildCandidates(""); err != nil {
		if !errors.Is(err, errSmartNoCandidates) || len(providerTags) == 0 {
			return err
		}
		s.setWarmingStatus("waiting for provider candidates")
		if s.logger != nil {
			s.logger.Info("smart group waiting for provider candidates")
		}
	}
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil {
		var restored bool
		if store, ok := cacheFile.(adapter.SelectedRecordStore); ok {
			if record, loaded := store.LoadSelectedRecord(s.Tag()); loaded {
				if pinned := s.resolveSmartSelectionRecord(record); pinned != "" {
					restored = s.SelectOutbound(pinned)
				}
			}
		}
		if !restored {
			if pinned := cacheFile.LoadSelected(s.Tag()); pinned != "" {
				s.SelectOutbound(pinned)
			}
		}
	}
	return nil
}

func (s *Smart) attachSmartProviderCallback(tag string, provider adapter.Provider) {
	if provider == nil {
		return
	}
	handle := provider.RegisterCallback(s.onProviderUpdated)
	s.providerAccess.Lock()
	if s.closing.Load() || s.providers[tag] != provider {
		s.providerAccess.Unlock()
		if handle != nil {
			provider.UnregisterCallback(handle)
		}
		return
	}
	s.providerHandles[tag] = handle
	s.providerAccess.Unlock()
}

// onProviderManagerUpdated keeps use_all_providers in sync with dynamic
// manager membership. Provider callbacks are attached outside providerAccess;
// an implementation may synchronously publish from RegisterCallback.
func (s *Smart) onProviderManagerUpdated() {
	if s == nil || !s.useAllProviders || s.closing.Load() {
		return
	}
	desired := make(map[string]adapter.Provider)
	var desiredTags []string
	for _, provider := range s.provider.Providers() {
		if provider == nil || provider.Tag() == "" {
			continue
		}
		tag := provider.Tag()
		if _, exists := desired[tag]; exists {
			continue
		}
		desired[tag] = provider
		desiredTags = append(desiredTags, tag)
	}
	var removedProviders []adapter.Provider
	var removedHandles []*list.Element[adapter.ProviderUpdateCallback]
	var added []struct {
		tag      string
		provider adapter.Provider
	}
	s.providerAccess.Lock()
	if s.closing.Load() {
		s.providerAccess.Unlock()
		return
	}
	changed := len(desiredTags) != len(s.providerTags)
	for tag, provider := range s.providers {
		if desiredProvider, exists := desired[tag]; exists && desiredProvider == provider {
			continue
		}
		removedProviders = append(removedProviders, provider)
		removedHandles = append(removedHandles, s.providerHandles[tag])
		delete(s.providers, tag)
		delete(s.providerHandles, tag)
		delete(s.outboundsCache, tag)
		changed = true
	}
	for _, tag := range desiredTags {
		if _, exists := s.providers[tag]; exists {
			continue
		}
		provider := desired[tag]
		s.providers[tag] = provider
		s.providerHandles[tag] = nil
		added = append(added, struct {
			tag      string
			provider adapter.Provider
		}{tag: tag, provider: provider})
		changed = true
	}
	s.providerTags = desiredTags
	if changed {
		s.providerRevision++
	}
	s.providerAccess.Unlock()
	for index, provider := range removedProviders {
		if provider != nil && removedHandles[index] != nil {
			provider.UnregisterCallback(removedHandles[index])
		}
	}
	for _, item := range added {
		s.attachSmartProviderCallback(item.tag, item.provider)
	}
	if changed && !s.closing.Load() {
		_ = s.onProviderUpdated("")
	}
}

func (s *Smart) PostStart() error {
	s.lifecycleAccess.Lock()
	s.postStarted = true
	s.startWorkerLocked()
	s.lifecycleAccess.Unlock()
	return nil
}

func (s *Smart) stopWorker() {
	s.lifecycleAccess.Lock()
	s.retired = true
	if s.cancel != nil {
		s.cancel()
	}
	s.lifecycleAccess.Unlock()
}

func (s *Smart) startWorkerLocked() {
	if !s.postStarted || s.retired || s.workerStarted {
		return
	}
	workerCtx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.workerStarted = true
	s.worker.Add(1)
	go s.run(workerCtx)
}

func (s *Smart) Close() error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}
	s.stopWorker()
	s.unregisterProviderCallbacks()
	// Bound wait: in-flight URL tests + shared probe slots can stall each group
	// for several seconds. Five smart groups closed serially would otherwise
	// exceed FatalStopTimeout (10s) and crash with "sing-box did not close!".
	s.waitWorkerStop(2 * time.Second)
	s.access.Lock()
	clear(s.candidateByTag)
	clear(s.lastSelected)
	clear(s.lastSelectedAt)
	clear(s.affinity)
	clear(s.switchChallenges)
	clear(s.performanceCooldown)
	clear(s.useScores)
	clear(s.probeLastAt)
	clear(s.probeAttemptAt)
	clear(s.udpProbeLastAt)
	clear(s.halfOpen)
	s.halfOpenActive = 0
	clear(s.selectionGeneration)
	clear(s.zigSelectedEndpoint)
	clear(s.actualDialEndpoint)
	clear(s.circuitState)
	s.candidates = nil
	s.candidateByTag = make(map[string]adapter.Outbound)
	s.candidateMetadataByTag = nil
	s.lastSelected = make(map[string]string)
	s.lastSelectedAt = make(map[string]time.Time)
	s.affinity = make(map[string]smartAffinity)
	s.switchChallenges = make(map[string]smartSwitchChallenge)
	s.performanceCooldown = make(map[string]time.Time)
	s.useScores = make(map[string]smartUseScore)
	s.probeLastAt = make(map[string]time.Time)
	s.probeAttemptAt = make(map[string]time.Time)
	s.udpProbeLastAt = make(map[string]time.Time)
	s.halfOpen = make(map[string]struct{})
	s.halfOpenActive = 0
	s.selectionGeneration = make(map[string]uint64)
	s.zigSelectedEndpoint = make(map[string]string)
	s.actualDialEndpoint = make(map[string]string)
	s.circuitState = make(map[string]string)
	s.access.Unlock()
	s.providerAccess.Lock()
	clear(s.providers)
	clear(s.outboundsCache)
	s.providers = make(map[string]adapter.Provider)
	s.outboundsCache = make(map[string][]adapter.Outbound)
	s.providerHandles = make(map[string]*list.Element[adapter.ProviderUpdateCallback])
	s.providerAccess.Unlock()
	s.store.clear()
	s.closePolicyBackend()
	if s.releaseProbeRegistry != nil {
		s.releaseProbeRegistry()
		s.releaseProbeRegistry = nil
	}
	return nil
}

// policyBackendEnabled snapshots only whether the optional policy kernel is
// available. Calls into the backend itself must use the helpers below so
// Smart.Close cannot destroy a Zig engine while another goroutine is inside
// its C ABI.
func (s *Smart) policyBackendEnabled() bool {
	s.policyBackendAccess.RLock()
	enabled := s.policyBackend != nil
	s.policyBackendAccess.RUnlock()
	return enabled
}

func (s *Smart) resetPolicyBackend() {
	s.policyBackendAccess.RLock()
	if s.policyBackend != nil {
		s.policyBackend.Reset()
	}
	s.policyBackendAccess.RUnlock()
}

func (s *Smart) closePolicyBackend() {
	s.policyBackendAccess.Lock()
	if s.policyBackend != nil {
		s.policyBackend.Close()
		s.policyBackend = nil
	}
	s.policyBackendAccess.Unlock()
}

func (s *Smart) observePolicyBackend(key string, id uint64, success bool, elapsed time.Duration, now time.Time) bool {
	s.policyBackendAccess.RLock()
	if s.policyBackend == nil {
		s.policyBackendAccess.RUnlock()
		return false
	}
	s.policyBackend.Observe(key, id, success, elapsed, now)
	s.policyBackendAccess.RUnlock()
	return true
}

func (s *Smart) choosePolicyBackend(key string, candidates []smartPolicyCandidate, profile smartTrafficProfile, now time.Time) (smartPolicyDecision, bool) {
	s.policyBackendAccess.RLock()
	if s.policyBackend == nil {
		s.policyBackendAccess.RUnlock()
		return smartPolicyDecision{}, false
	}
	decision := s.policyBackend.Choose(key, candidates, profile, now)
	s.policyBackendAccess.RUnlock()
	return decision, true
}

func (s *Smart) setPolicyBackendSelected(key string, id uint64, now time.Time) {
	if s == nil || key == "" || id == 0 {
		return
	}
	s.policyBackendAccess.RLock()
	if incumbent, ok := s.policyBackend.(smartPolicyIncumbent); ok {
		incumbent.SetSelected(key, id, now)
	}
	s.policyBackendAccess.RUnlock()
}

func (s *Smart) prunePolicyBackend(ids []uint64) {
	if s == nil {
		return
	}
	s.policyBackendAccess.RLock()
	if pruner, ok := s.policyBackend.(smartPolicyPruner); ok {
		pruner.Prune(ids)
	}
	s.policyBackendAccess.RUnlock()
}

func (s *Smart) adoptPolicyBackendSelected(key string, id uint64, now time.Time) {
	if s == nil || key == "" || id == 0 {
		return
	}
	s.policyBackendAccess.RLock()
	if adopter, ok := s.policyBackend.(smartPolicyAdopter); ok {
		adopter.AdoptSelected(key, id, now)
	}
	s.policyBackendAccess.RUnlock()
}

func (s *Smart) recordZigSelectedEndpoint(statusKey string, endpointID string) uint64 {
	if s == nil || statusKey == "" || endpointID == "" {
		return 0
	}
	s.access.Lock()
	if s.zigSelectedEndpoint == nil {
		s.zigSelectedEndpoint = make(map[string]string)
	}
	if previous := s.zigSelectedEndpoint[statusKey]; previous != endpointID {
		if s.selectionGeneration == nil {
			s.selectionGeneration = make(map[string]uint64)
		}
		generation := s.selectionGeneration[statusKey]
		if generation == 0 {
			generation = 1
		} else if previous != "" {
			generation++
		}
		s.selectionGeneration[statusKey] = generation
	}
	s.zigSelectedEndpoint[statusKey] = endpointID
	generation := s.selectionGeneration[statusKey]
	s.access.Unlock()
	return generation
}

// recordActualDial is the data-plane half of the Smart proof. It records the
// canonical endpoint that actually accepted a new connection and compares it
// with the last endpoint returned by Zig. A mismatch is observable (and
// counted) instead of being silently hidden by a provider alias or an
// in-flight selection race.
func (s *Smart) recordActualDial(statusKey, endpointID string, dialGeneration uint64) {
	s.recordActualDialWithChecks(statusKey, endpointID, dialGeneration, true, true)
}

// recordActualDialForAttempt records the endpoint that won a concrete dial
// attempt. A retry/hedge can intentionally complete on a different member
// than the point-in-time Zig ranking. markSelectedWithSnapshot commits failure
// failover selections before this method is called; when it retains a newer
// incumbent (or a healthy hedge), the attempt is still valid but must not be
// reported as a control/data mismatch.
func (s *Smart) recordActualDialForAttempt(statusKey, endpointID string, dialGeneration uint64, selectionCommitted bool) {
	s.recordActualDialWithChecks(statusKey, endpointID, dialGeneration, selectionCommitted, false)
}

func (s *Smart) recordActualDialWithChecks(statusKey, endpointID string, dialGeneration uint64, checkEndpoint, checkGeneration bool) {
	if s == nil || statusKey == "" || endpointID == "" {
		return
	}
	s.access.Lock()
	if s.actualDialEndpoint == nil {
		s.actualDialEndpoint = make(map[string]string)
	}
	if s.selectionGeneration == nil {
		s.selectionGeneration = make(map[string]uint64)
	}
	currentGeneration := s.selectionGeneration[statusKey]
	zigEndpoint := s.zigSelectedEndpoint[statusKey]
	s.actualDialEndpoint[statusKey] = endpointID
	s.access.Unlock()
	if (checkEndpoint && zigEndpoint != "" && zigEndpoint != endpointID) ||
		(checkGeneration && dialGeneration != 0 && currentGeneration != 0 && dialGeneration != currentGeneration) {
		s.selectionMismatchTotal.Add(1)
		if s.logger != nil {
			s.logger.Warn("smart control/data selection mismatch: zig_selected_endpoint=", zigEndpoint,
				" actual_dial_endpoint=", endpointID, " selection_generation=", currentGeneration,
				" dial_generation=", dialGeneration)
		}
	}
}

func (s *Smart) recordUnobservedConnection(statusKey, endpointID string) {
	if s == nil {
		return
	}
	s.unobservedConnectionTotal.Add(1)
	if s.logger != nil {
		s.logger.Error("smart managed connection bypassed observation wrapper: context=", statusKey, " endpoint=", endpointID)
	}
}

func (s *Smart) noteFailureType(statusKey, failureType string) {
	if s == nil || failureType == "" {
		return
	}
	s.access.Lock()
	if s.circuitState == nil {
		s.circuitState = make(map[string]string)
	}
	state := "suspect"
	if failureType == "protocol" || failureType == "hard_transport" {
		state = "open"
	}
	s.circuitState[statusKey] = state
	s.access.Unlock()
	value := failureType
	s.lastFailureType.Store(&value)
}

// waitWorkerStop waits for the probe worker up to timeout after cancel.
// Stragglers must honor s.closing / cancelled ctx and not touch cleared maps.
func (s *Smart) waitWorkerStop(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.worker.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		if s.logger != nil {
			s.logger.Warn("smart probe worker did not stop within ", timeout, "; continuing close for high availability")
		}
	}
}

func (s *Smart) unregisterProviderCallbacks() {
	s.providerAccess.Lock()
	providers := make(map[string]adapter.Provider, len(s.providers))
	handles := make(map[string]*list.Element[adapter.ProviderUpdateCallback], len(s.providerHandles))
	for tag, provider := range s.providers {
		providers[tag] = provider
	}
	for tag, handle := range s.providerHandles {
		handles[tag] = handle
	}
	observer := s.providerObserver
	managerHandle := s.providerManagerHandle
	s.providerObserver = nil
	s.providerManagerHandle = nil
	clear(s.providerHandles)
	s.providerAccess.Unlock()
	if observer != nil && managerHandle != nil {
		observer.UnregisterProviderCallback(managerHandle)
	}
	for tag, handle := range handles {
		if provider := providers[tag]; provider != nil && handle != nil {
			provider.UnregisterCallback(handle)
		}
	}
}

func (s *Smart) currentPhase() smartPhase {
	if s == nil {
		return smartPhaseCold
	}
	return smartPhase(s.phase.Load())
}

func (s *Smart) setPhase(phase smartPhase) {
	if s == nil {
		return
	}
	for {
		current := smartPhase(s.phase.Load())
		if phase <= current {
			return
		}
		if s.phase.CompareAndSwap(uint32(current), uint32(phase)) {
			return
		}
	}
}

func (s *Smart) noteProbeCycle(successes int) {
	if s == nil || successes <= 0 || s.closing.Load() {
		return
	}
	// The first successful basic probe publishes a usable baseline immediately.
	// A second completed cycle enters profiling; the steady phase is reached
	// after the third cycle or earlier through real-traffic samples below.
	successful := s.successfulProbeCycles.Add(1)
	switch {
	case successful >= 3:
		s.setPhase(smartPhaseSteady)
	case successful >= 2:
		s.setPhase(smartPhaseProfiling)
	default:
		s.setPhase(smartPhaseBaseline)
	}
}

func (s *Smart) performanceSwitchAllowed() bool {
	// Embedded users of Smart (and unit-test fixtures) may not run the worker.
	// Preserve the historical reference-policy behavior for those callers; the
	// production lifecycle always starts in cold phase before PostStart probes.
	if !s.phaseInitialized.Load() {
		return true
	}
	return s.currentPhase() >= smartPhaseProfiling
}

// stableAffinityIndex implements stable same-tier context dispersion. It first
// applies the hard health tier and near-tie
// score boundary as ranking, then uses rendezvous hashing over canonical
// endpoint identities. The result is pseudo-random across independent
// contexts but stable for one context, so keep-alive traffic does not bounce
// between lines.
// Node weights have already been applied to the confidence-adjusted score;
// applying them again here would double-count a priority rule.
func (s *Smart) stableAffinityIndex(ranks []smartRank, key, preferredTag string) int {
	if s == nil || len(ranks) == 0 || key == "" {
		return -1
	}
	best := -1
	bestTier := int(^uint(0) >> 1)
	for index := range ranks {
		if !ranks[index].eligible {
			continue
		}
		tier := smartHealthTier(ranks[index].status.State)
		if tier < bestTier {
			best = index
			bestTier = tier
		}
	}
	if best < 0 {
		return -1
	}
	// Do not hash a cold catalog before the first usable portraits exist. The
	// initial ranked line is the primary/backup bootstrap path; once every
	// candidate in the best health tier has the normal minimum evidence, the
	// same stable affinity policy can safely disperse near-tied lines. This
	// keeps cold-start failover deterministic and avoids picking an unobserved
	// candidate merely because its hash happens to be higher.
	minimumSamples := float64(max(1, s.minSamples))
	for index := range ranks {
		if !ranks[index].eligible || smartHealthTier(ranks[index].status.State) != bestTier {
			continue
		}
		if ranks[index].status.Samples < minimumSamples {
			return -1
		}
	}
	bestScore := ranks[best].status.Score
	threshold := bestScore * (1 + s.switchMargin)
	if bestScore == 0 {
		threshold = 0.05
	}
	isInPool := func(index int) bool {
		return ranks[index].eligible && smartHealthTier(ranks[index].status.State) == bestTier && ranks[index].status.Score <= threshold
	}
	// Preserve the incumbent when it is still inside the eligible candidate pool. This
	// makes score refreshes and provider alias changes non-disruptive; a failed
	// or materially degraded incumbent is deliberately rehashed to a backup.
	if preferredTag != "" {
		for index := range ranks {
			matches := ranks[index].identity == preferredTag
			if !matches && ranks[index].outbound != nil {
				matches = ranks[index].outbound.Tag() == preferredTag
			}
			if matches && isInPool(index) {
				return index
			}
		}
	}

	seen := make(map[string]struct{}, len(ranks))
	selected := -1
	var selectedMetric uint64
	for index := range ranks {
		if !isInPool(index) {
			continue
		}
		identity := ranks[index].identity
		if identity == "" && ranks[index].policyID != 0 {
			identity = strconv.FormatUint(ranks[index].policyID, 16)
		}
		if identity == "" && ranks[index].outbound != nil {
			identity = ranks[index].outbound.Tag()
		}
		if identity == "" {
			continue
		}
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(identity))
		metric := hash.Sum64()
		if selected < 0 || metric < selectedMetric {
			selected = index
			selectedMetric = metric
		}
	}
	if selected >= 0 {
		return selected
	}
	return best
}

// applySurgeOrdering implements Surge's per-request A/B/C candidate ordering.
// The returned slice is the dial failover order and the same 1-based order is
// passed to Zig, so control-plane selection and the actual data plane cannot
// disagree. Hard-open candidates remain ineligible and sort last.
func (s *Smart) applySurgeOrdering(ranks []smartRank, selectionKey, preferredTag string, now time.Time) {
	if len(ranks) == 0 {
		return
	}
	hasNormal := false
	for _, rank := range ranks {
		if rank.eligible && rank.status.State != "open" && !rank.standbyOnly {
			hasNormal = true
			break
		}
	}
	minScore := 0.0
	bestAdjustment := 1.0
	for index := range ranks {
		rank := &ranks[index]
		if !rank.eligible || rank.status.State == "open" || rank.status.Score <= 0 || (hasNormal && rank.standbyOnly) {
			continue
		}
		if minScore == 0 || rank.status.Score < minScore {
			minScore = rank.status.Score
			bestAdjustment = 1 / math.Max(rank.status.Weight, 0.01)
		}
	}
	threshold := 50 * bestAdjustment
	requestSeed := uint64(now.UnixNano())
	for index := range ranks {
		rank := &ranks[index]
		switch {
		case !rank.eligible || rank.status.State == "open":
			rank.surgeBand = 4
		case hasNormal && rank.standbyOnly:
			rank.surgeBand = 3
		case rank.activeProbeDegraded:
			// Unknown first-byte cost is represented by score zero. It must not
			// erase an actual failed active probe for a backup candidate.
			rank.surgeBand = 2
		case rank.status.Score == 0 || minScore == 0 || rank.status.Score-minScore <= threshold:
			rank.surgeBand = 0
		default:
			rank.surgeBand = 1
		}
		if rank.siteTainted && rank.surgeBand == 0 {
			rank.surgeBand = 1
		}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(selectionKey))
		var encoded [16]byte
		binary.LittleEndian.PutUint64(encoded[:8], requestSeed)
		binary.LittleEndian.PutUint64(encoded[8:], rank.policyID)
		_, _ = hash.Write(encoded[:])
		rank.surgeOrder = hash.Sum64()
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].surgeBand != ranks[j].surgeBand {
			return ranks[i].surgeBand < ranks[j].surgeBand
		}
		return ranks[i].surgeOrder < ranks[j].surgeOrder
	})

	// Surge evaluates the best successful site record after A/B/C have been
	// concatenated.  The 70% gate therefore uses the complete eligible policy
	// count, not only tier A. A successful record may promote a B/C policy when
	// the coverage/tolerance gate says that real site traffic is authoritative.
	eligibleCount, successCount, preferred := 0, 0, -1
	bestDelay := 0.0
	for index := range ranks {
		if !ranks[index].eligible || ranks[index].status.State == "open" {
			continue
		}
		if hasNormal && ranks[index].standbyOnly {
			continue
		}
		eligibleCount++
		if ranks[index].siteTainted || ranks[index].siteSuccesses <= 0 || ranks[index].siteDelayMS <= 0 {
			continue
		}
		successCount++
		if preferred < 0 || ranks[index].siteDelayMS < bestDelay {
			preferred, bestDelay = index, ranks[index].siteDelayMS
		}
	}
	if preferred >= 0 && eligibleCount > 0 {
		adjustment := 1 / math.Max(ranks[preferred].status.Weight, 0.01)
		coverageEnough := float64(successCount) >= 0.7*float64(eligibleCount)
		allowed := minScore + adjustment*(float64(successCount*successCount)*40+50)
		if coverageEnough || minScore == 0 || adjustment*bestDelay <= allowed {
			ranks[preferred].status.Reason = "spread site affinity"
			moveSmartRankFirst(ranks, preferred)
		}
	}
	// Generated provider aliases for one canonical policy are one endpoint, not
	// independent Surge lines. Keep the alias that already owns established
	// connections so Go and Zig cannot display/dial different names for the same
	// credential after a provider refresh.
	if preferredTag != "" {
		if preferredIndex := smartRankIndex(ranks, preferredTag); preferredIndex > 0 && ranks[preferredIndex].policyID != 0 && ranks[preferredIndex].policyID == ranks[0].policyID {
			ranks[preferredIndex].status.Reason = "equivalent subscription line retained"
			moveSmartRankFirst(ranks, preferredIndex)
		}
	}
}

func (s *Smart) noteCandidateUse(candidate string, now time.Time) {
	if s == nil || candidate == "" {
		return
	}
	profileID := s.candidateProfileID(candidate)
	if profileID == "" {
		profileID = candidate
	}
	s.access.Lock()
	if s.useScores == nil {
		s.useScores = make(map[string]smartUseScore)
	}
	usage := s.useScores[profileID]
	if !usage.LastUsed.IsZero() {
		elapsed := now.Sub(usage.LastUsed)
		if elapsed >= smartUseScoreDecayWindow {
			usage.Score = 0
		} else if elapsed > 0 {
			usage.Score *= 1 - elapsed.Seconds()/smartUseScoreDecayWindow.Seconds()
		}
	}
	usage.Score++
	usage.LastUsed = now
	s.useScores[profileID] = usage
	if len(s.useScores) > defaultSmartMaxHistoryEntries {
		s.pruneUseScoresLocked(now)
	}
	s.access.Unlock()
}

func decayedSmartUseScore(usage smartUseScore, now time.Time) float64 {
	if usage.Score <= 0 || usage.LastUsed.IsZero() {
		return 0
	}
	elapsed := now.Sub(usage.LastUsed)
	switch {
	case elapsed <= 0:
		return usage.Score
	case elapsed >= smartUseScoreDecayWindow:
		return 0
	default:
		return usage.Score * (1 - elapsed.Seconds()/smartUseScoreDecayWindow.Seconds())
	}
}

func (s *Smart) noteCandidateProbe(candidate string, now time.Time) {
	if s == nil || candidate == "" {
		return
	}
	probeID := s.candidateProbeIdentity(candidate)
	if probeID == "" {
		probeID = candidate
	}
	s.noteProbeTimestamp(&s.probeLastAt, probeID, now)
}

func (s *Smart) noteCandidateAttempt(candidate string, now time.Time) {
	if s == nil || candidate == "" {
		return
	}
	probeID := s.candidateProbeIdentity(candidate)
	if probeID == "" {
		probeID = candidate
	}
	s.noteProbeTimestamp(&s.probeAttemptAt, probeID, now)
}

func (s *Smart) probeCoverageLocked() (attempted, total int) {
	seen := make(map[string]struct{}, len(s.candidates))
	for _, candidate := range s.candidates {
		if candidate == nil {
			continue
		}
		metadata := s.candidateMetadataByTag[candidate.Tag()]
		probeID := metadata.identity
		if probeID == "" {
			probeID = candidate.Tag()
		}
		if _, exists := seen[probeID]; exists {
			continue
		}
		seen[probeID] = struct{}{}
		total++
		if !s.probeAttemptAt[probeID].IsZero() || !s.udpProbeLastAt[probeID].IsZero() {
			attempted++
		}
	}
	return
}

func (s *Smart) probeCoverage() (attempted, total int) {
	if s == nil {
		return 0, 0
	}
	s.access.RLock()
	attempted, total = s.probeCoverageLocked()
	s.access.RUnlock()
	return
}

// noteUDPCandidateProbe keeps UDP coverage independent from TCP coverage. A
// candidate that was recently exercised by the TCP budget must still become
// eligible for the next UDP rotation, and vice versa.
func (s *Smart) noteUDPCandidateProbe(candidate string, now time.Time) {
	if s == nil || candidate == "" {
		return
	}
	probeID := s.candidateProbeIdentity(candidate)
	if probeID == "" {
		probeID = candidate
	}
	s.noteProbeTimestamp(&s.udpProbeLastAt, probeID, now)
}

func (s *Smart) noteProbeTimestamp(store *map[string]time.Time, profileID string, now time.Time) {
	if s == nil || store == nil || profileID == "" {
		return
	}
	s.access.Lock()
	if *store == nil {
		*store = make(map[string]time.Time)
	}
	(*store)[profileID] = now
	if len(*store) > defaultSmartMaxHistoryEntries {
		for key, lastProbe := range *store {
			if lastProbe.IsZero() || now.Sub(lastProbe) > 4*smartUseScoreDecayWindow {
				delete(*store, key)
			}
		}
		for len(*store) > defaultSmartMaxHistoryEntries {
			var oldestKey string
			var oldest time.Time
			for key, lastProbe := range *store {
				if oldestKey == "" || lastProbe.Before(oldest) {
					oldestKey, oldest = key, lastProbe
				}
			}
			if oldestKey == "" {
				break
			}
			delete(*store, oldestKey)
		}
	}
	s.access.Unlock()
}

func (s *Smart) pruneUseScoresLocked(now time.Time) {
	for key, usage := range s.useScores {
		if usage.LastUsed.IsZero() || now.Sub(usage.LastUsed) > 4*smartUseScoreDecayWindow {
			delete(s.useScores, key)
		}
	}
	for len(s.useScores) > defaultSmartMaxHistoryEntries {
		var oldestKey string
		var oldest time.Time
		for key, usage := range s.useScores {
			if oldestKey == "" || usage.LastUsed.Before(oldest) {
				oldestKey, oldest = key, usage.LastUsed
			}
		}
		if oldestKey == "" {
			break
		}
		delete(s.useScores, oldestKey)
	}
}

// selectProbeCandidates follows the useful part of Surge's periodic testing
// policy: refresh a small set of frequently used endpoints and fill the rest
// with the stalest entries. It is only used when a group is budgeted; a full
// explicit URLTest still covers the complete catalog.
func (s *Smart) selectProbeCandidates(candidates []adapter.Outbound, budget int, purpose smartProbePurpose) []adapter.Outbound {
	if s == nil || budget <= 0 || (purpose != smartProbeBackground && len(candidates) <= budget) {
		return candidates
	}
	type probeCandidate struct {
		candidate adapter.Outbound
		probeID   string
		usage     float64
		lastProbe time.Time
	}
	items := make([]probeCandidate, 0, len(candidates))
	seenProbeIDs := make(map[string]struct{}, len(candidates))
	now := time.Now()
	s.access.RLock()
	for _, candidate := range candidates {
		metadata := s.candidateMetadataByTag[candidate.Tag()]
		probeID := metadata.identity
		if probeID == "" {
			probeID = candidate.Tag()
		}
		profileID := metadata.profileID
		if profileID == "" {
			profileID = candidate.Tag()
		}
		// Provider refreshes can expose one physical endpoint under several
		// generated aliases.  The shared registry will single-flight those
		// aliases, but spending this cycle's budget on duplicates would starve
		// distinct endpoints from the stale/used rotation.
		if _, exists := seenProbeIDs[probeID]; exists {
			continue
		}
		seenProbeIDs[probeID] = struct{}{}
		usage := decayedSmartUseScore(s.useScores[profileID], now)
		items = append(items, probeCandidate{candidate: candidate, probeID: probeID, usage: usage, lastProbe: s.probeAttemptAt[probeID]})
	}
	s.access.RUnlock()
	if len(items) == 0 {
		return nil
	}
	cold := false
	if purpose == smartProbeBackground {
		tested := 0
		for _, item := range items {
			if !item.lastProbe.IsZero() {
				tested++
			}
		}
		cold = float64(tested)/float64(len(items)) < 0.7
		// A cycle has a hard deadline. Returning an entire cold catalog used
		// to repeatedly time out on its first slow members, starving the tail.
		// Reserve a small rotating cold batch even when the group is idle, and
		// never schedule more than its workers can finish at the probe timeout.
		budget = min(max(budget, defaultSmartColdProbeBudget), s.probeCycleCapacity(), len(items))
		if !cold {
			budget = min(budget, 12)
		}
	} else {
		budget = min(budget, len(items))
	}
	if budget <= 0 {
		return nil
	}
	cursor := s.probeCursor.Add(uint64(budget)) - uint64(budget)
	start := int(cursor % uint64(len(items)))
	rotation := make(map[string]int, len(items))
	for index, item := range items {
		rotation[item.probeID] = (index + len(items) - start) % len(items)
	}
	used := make([]probeCandidate, 0, len(items))
	for _, item := range items {
		if item.usage > 0 {
			used = append(used, item)
		}
	}
	sort.SliceStable(used, func(i, j int) bool {
		if used[i].usage != used[j].usage {
			return used[i].usage > used[j].usage
		}
		return rotation[used[i].probeID] < rotation[used[j].probeID]
	})
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].lastProbe.Equal(items[j].lastProbe) {
			if items[i].lastProbe.IsZero() {
				return true
			}
			if items[j].lastProbe.IsZero() {
				return false
			}
			return items[i].lastProbe.Before(items[j].lastProbe)
		}
		return rotation[items[i].probeID] < rotation[items[j].probeID]
	})
	selected := make([]adapter.Outbound, 0, budget)
	seen := make(map[string]struct{}, budget)
	usedBudget := min(len(used), max(1, budget/2))
	if cold {
		// Coverage comes before use-score while most endpoints are unknown.
		usedBudget = 0
	}
	for _, item := range used[:usedBudget] {
		selected = append(selected, item.candidate)
		seen[item.probeID] = struct{}{}
	}
	for _, item := range items {
		if len(selected) >= budget {
			break
		}
		if _, exists := seen[item.probeID]; exists {
			continue
		}
		selected = append(selected, item.candidate)
		seen[item.probeID] = struct{}{}
	}
	return selected
}

func (s *Smart) probeCycleCapacity() int {
	concurrency := s.probeConcurrency
	if concurrency <= 0 {
		concurrency = defaultSmartProbeConcurrency
	}
	cycle := s.probeCycleTimeout
	if cycle <= 0 {
		cycle = defaultSmartProbeCycleTimeout
	}
	perCandidate := s.probeTimeout
	if perCandidate <= 0 {
		perCandidate = defaultSmartProbeTimeout
	}
	return max(1, concurrency*max(1, int(cycle/perCandidate)))
}

// selectUDPProbeCandidates gives UDP health checks their own bounded coverage
// window. TCP probe timestamps and cursors must not starve UDP-only candidates;
// aliases of one EndpointProfile consume only one slot, while never-probed and
// least-recently-probed profiles rotate through the remaining budget.
func (s *Smart) selectUDPProbeCandidates(candidates []adapter.Outbound, budget int) []adapter.Outbound {
	if s == nil || len(candidates) == 0 {
		return nil
	}
	if budget <= 0 || budget > defaultSmartUDPProbeTargetCount {
		budget = defaultSmartUDPProbeTargetCount
	}
	type udpProbeCandidate struct {
		candidate adapter.Outbound
		probeID   string
		profileID string
		usage     float64
		lastProbe time.Time
		rotation  int
	}
	items := make([]udpProbeCandidate, 0, len(candidates))
	seenProbeIDs := make(map[string]struct{}, len(candidates))
	now := time.Now()
	s.access.RLock()
	for index, candidate := range candidates {
		if !common.Contains(candidate.Network(), N.NetworkUDP) {
			continue
		}
		metadata := s.candidateMetadataByTag[candidate.Tag()]
		probeID := metadata.identity
		if probeID == "" {
			probeID = candidate.Tag()
		}
		profileID := metadata.profileID
		if profileID == "" {
			profileID = candidate.Tag()
		}
		if _, exists := seenProbeIDs[probeID]; exists {
			continue
		}
		seenProbeIDs[probeID] = struct{}{}
		items = append(items, udpProbeCandidate{
			candidate: candidate,
			probeID:   probeID,
			profileID: profileID,
			usage:     decayedSmartUseScore(s.useScores[profileID], now),
			lastProbe: s.udpProbeLastAt[probeID],
			rotation:  index,
		})
	}
	cursor := s.udpProbeCursor.Load()
	s.access.RUnlock()
	if len(items) == 0 {
		return nil
	}
	// Equal timestamps (especially the initial zero timestamp) need a stable
	// rotating tie-breaker; otherwise a large group would probe the same first
	// two aliases forever.
	start := int(cursor % uint64(len(items)))
	for index := range items {
		items[index].rotation = (index + len(items) - start) % len(items)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].lastProbe.Equal(items[j].lastProbe) {
			if items[i].lastProbe.IsZero() {
				return true
			}
			if items[j].lastProbe.IsZero() {
				return false
			}
			return items[i].lastProbe.Before(items[j].lastProbe)
		}
		return items[i].rotation < items[j].rotation
	})
	used := make([]udpProbeCandidate, 0, len(items))
	for _, item := range items {
		if item.usage > 0 {
			used = append(used, item)
		}
	}
	sort.SliceStable(used, func(i, j int) bool {
		if used[i].usage != used[j].usage {
			return used[i].usage > used[j].usage
		}
		return used[i].rotation < used[j].rotation
	})
	if budget > len(items) {
		budget = len(items)
	}
	selected := make([]adapter.Outbound, 0, budget)
	seen := make(map[string]struct{}, budget)
	usedBudget := min(len(used), max(1, budget/2))
	for _, item := range used[:usedBudget] {
		selected = append(selected, item.candidate)
		seen[item.probeID] = struct{}{}
	}
	for _, item := range items {
		if len(selected) >= budget {
			break
		}
		if _, exists := seen[item.probeID]; exists {
			continue
		}
		selected = append(selected, item.candidate)
		seen[item.probeID] = struct{}{}
	}
	s.udpProbeCursor.Add(uint64(len(selected)))
	return selected
}

func (s *Smart) run(ctx context.Context) {
	defer s.worker.Done()
	if s.probeStartupDelay > 0 {
		timer := time.NewTimer(s.probeStartupDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	if ctx.Err() != nil || s.closing.Load() {
		return
	}
	s.phaseInitialized.Store(true)
	s.phase.Store(uint32(smartPhaseCold))
	s.successfulProbeCycles.Store(0)
	// Cold start once. Default cap 45s (was 2m) so multi-smart Close stays in HA
	// budget; catalogs rotate on probe_interval. Explicit probe_cycle_timeout
	// above 45s is honored when set.
	cold := 45 * time.Second
	if s.probeCycleTimeout > cold {
		cold = s.probeCycleTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, cold)
	_, _ = s.probeWithBudget(probeCtx, defaultSmartColdProbeBudget)
	cancel()
	nextInterval := s.nextProbeInterval(time.Now())
	probeTimer := time.NewTimer(nextInterval)
	defer probeTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-probeTimer.C:
			if s.closing.Load() {
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
			_, _ = s.probeWithBudget(probeCtx, s.scheduledProbeBudget(time.Now()))
			cancel()
			probeTimer.Reset(s.nextProbeInterval(time.Now()))
		case <-s.probeNow:
			if s.closing.Load() {
				return
			}
			requestMode := s.probeRequestMode.Swap(0)
			probeCtx, cancel := context.WithTimeout(ctx, s.probeCycleTimeout)
			budget := s.requestedProbeBudget(time.Now())
			if requestMode&smartProbeRequestNormal != 0 {
				// A real traffic wakeup outranks a coalesced dashboard request;
				// never let the dashboard's small budget restrict recovery.
				s.manualProbeBudget.Store(0)
			} else if manualBudget := int(s.manualProbeBudget.Swap(0)); manualBudget > 0 && manualBudget < budget {
				budget = manualBudget
			}
			if requestMode&smartProbeRequestNormal == 0 && requestMode&smartProbeRequestDashboard != 0 {
				probeCtx = withSmartDashboardProbe(probeCtx)
			}
			_, _ = s.probeWithBudget(probeCtx, budget)
			cancel()
			if !probeTimer.Stop() {
				select {
				case <-probeTimer.C:
				default:
				}
			}
			probeTimer.Reset(s.nextProbeInterval(time.Now()))
		}
	}
}

func (s *Smart) activeAt(now time.Time) bool {
	last := s.lastActivityUnixNano.Load()
	return last > 0 && now.Sub(time.Unix(0, last)) <= defaultSmartActivityWindow
}

func (s *Smart) nextProbeInterval(now time.Time) time.Duration {
	interval := s.probeInterval
	if interval <= 0 {
		interval = defaultSmartProbeInterval
	}
	if attempted, total := s.probeCoverage(); total > 0 && float64(attempted)/float64(total) < 0.9 {
		return min(interval, defaultSmartColdCoverageInterval)
	}
	if s.activeAt(now) {
		return interval
	}
	return max(interval, defaultSmartIdleProbeInterval)
}

func (s *Smart) scheduledProbeBudget(now time.Time) int {
	if s.activeAt(now) {
		return defaultSmartActiveProbeBudget
	}
	return 1
}

func (s *Smart) requestedProbeBudget(now time.Time) int {
	// The first real request after a restart must not promote a cold group to
	// the active budget. noteTrafficActivity records activity before waking the
	// worker, so checking activeAt alone turns the first request into a large
	// five-group probe burst and competes with the request being served. Keep
	// the cold budget until the group has completed at least one baseline cycle;
	// profiling/steady phases can use the larger activity-driven budget.
	if s.currentPhase() <= smartPhaseBaseline {
		return defaultSmartColdProbeBudget
	}
	if s.activeAt(now) {
		return defaultSmartActiveProbeBudget
	}
	return defaultSmartColdProbeBudget
}

func (s *Smart) noteTrafficActivity() {
	now := time.Now()
	// Surge's real traffic updates use-score and passive policy history; it does
	// not launch an active URL test merely because a foreground request arrived.
	// Starting a probe sweep here made the first browser request after idle
	// compete with the very path it was trying to measure.
	s.lastActivityUnixNano.Store(now.UnixNano())
}

func (s *Smart) requestProbe() {
	s.requestProbeWithBudget(0)
}

func (s *Smart) requestProbeWithBudget(budget int) {
	s.enqueueProbeRequest(smartProbeRequestNormal, budget)
}

func (s *Smart) requestDashboardProbeWithBudget(budget int) {
	s.enqueueProbeRequest(smartProbeRequestDashboard, budget)
}

func (s *Smart) enqueueProbeRequest(mode uint32, budget int) {
	if s == nil || s.closing.Load() {
		return
	}
	s.probeRequestMode.Or(mode)
	if budget > 0 {
		for {
			current := s.manualProbeBudget.Load()
			if current != 0 && current <= int32(budget) {
				break
			}
			if s.manualProbeBudget.CompareAndSwap(current, int32(budget)) {
				break
			}
		}
	}
	select {
	case s.probeNow <- struct{}{}:
	default:
	}
}

func (s *Smart) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (s *Smart) Now() string {
	selected := s.latest.Load()
	if selected == nil {
		return ""
	}
	tag := selected.Tag()
	s.access.RLock()
	_, loaded := s.candidateByTag[tag]
	s.access.RUnlock()
	if !loaded {
		return ""
	}
	return tag
}

func (s *Smart) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.Map(s.candidates, func(it adapter.Outbound) string { return it.Tag() })
}

// SelectPreMatchOutbound picks a stable leaf for transparent pre-match without
// advancing hedge/retry/selection state (those remain on the L4 path).
func (s *Smart) SelectPreMatchOutbound(metadata *adapter.InboundContext, selectOutbound func(adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction)) (adapter.Outbound, adapter.PreMatchAction) {
	leaf := s.preMatchLeaf(metadata)
	if leaf == nil {
		return nil, adapter.PreMatchContinue
	}
	return selectOutbound(leaf)
}

func (s *Smart) preMatchLeaf(metadata *adapter.InboundContext) adapter.Outbound {
	now := time.Now()
	pinned, temporary, _, _ := s.controlSnapshot(now)
	contextSelected := ""
	if metadata != nil {
		transport := smartTransportKey(metadata.Network, metadata.Destination)
		_, siteKey := resolveSmartSiteIdentity(s.families, metadata, metadata.Destination)
		if transport != "" && siteKey != "" {
			contextKey := smartBusinessSelectionKey(s.networkFingerprint(), siteKey, transport)
			s.access.RLock()
			contextSelected = s.lastSelected[contextKey]
			s.access.RUnlock()
		}
	}
	s.access.RLock()
	defer s.access.RUnlock()
	pick := func(tag string) adapter.Outbound {
		if tag == "" {
			return nil
		}
		return s.candidateByTag[tag]
	}
	if detour := pick(temporary); detour != nil {
		return detour
	}
	if detour := pick(pinned); detour != nil {
		return detour
	}
	if selected := pick(contextSelected); selected != nil {
		return selected
	}
	if selected := s.latest.Load(); selected != nil {
		if _, ok := s.candidateByTag[selected.Tag()]; ok {
			return selected
		}
	}
	if len(s.candidates) > 0 {
		return s.candidates[0]
	}
	_ = metadata
	return nil
}

func (s *Smart) SmartStatus() adapter.SmartGroupStatus {
	pinned, temporary, expiresAt, reason := s.controlSnapshot(time.Now())
	s.statusAccess.RLock()
	// Copy all slice/map fields while holding statusAccess. A shallow struct
	// copy would leave StateCounts and Candidates backed by the live maps/slices
	// that updateStatusSelected reuses on the next probe, allowing the dashboard
	// reader to race with a probe worker after the lock is released.
	status := cloneSmartGroupStatus(s.status)
	statusContexts := make(map[string]adapter.SmartContextStatus, len(s.statusContexts))
	for key, contextStatus := range s.statusContexts {
		statusContexts[key] = cloneSmartContextStatus(contextStatus)
	}
	statusContextOrder := append([]string(nil), s.statusContextOrder...)
	statusLastContext := s.statusLastContext
	s.statusAccess.RUnlock()
	status.Pinned = pinned
	status.TemporaryOverride = temporary
	status.OverrideReason = reason
	if temporary != "" {
		status.OverrideExpiresAt = &expiresAt
		status.OverrideRemainingSeconds = max(0, int64(time.Until(expiresAt).Seconds()))
	}
	status.Candidates = append([]adapter.SmartCandidateStatus(nil), status.Candidates...)
	status.StateCounts = cloneSmartStateCounts(status.StateCounts)
	s.access.RLock()
	status.ProbeEndpointsAttempted, status.ProbeEndpointsTotal = s.probeCoverageLocked()
	s.access.RUnlock()
	if status.ProbeEndpointsTotal > 0 {
		status.ProbeCoveragePercent = 100 * float64(status.ProbeEndpointsAttempted) / float64(status.ProbeEndpointsTotal)
	}
	status.SwitchesTotal = s.switchesTotal.Load()
	status.PerformanceSwitches = s.performanceSwitches.Load()
	status.FailureFailovers = s.failureFailovers.Load()
	status.ColdStarts = s.coldStarts.Load()
	status.SwitchesForceAll = s.switchesForceAll.Load()
	status.SwitchesSelective = s.switchesSelective.Load()
	status.ConnectionsInterrupted = s.connectionsInterrupted.Load()
	status.ConnectionsKept = s.connectionsKept.Load()
	status.StreamFailureWakes = s.streamFailureWakes.Load()
	status.SelectionMismatchTotal = s.selectionMismatchTotal.Load()
	status.UnobservedConnectionTotal = s.unobservedConnectionTotal.Load()
	probeTargets := s.probeTargetSnapshot()
	status.ProbeTargets = append([]adapter.SmartProbeTargetStatus(nil), probeTargets[0])
	if probeTargets[1].TargetHost != "" {
		status.ProbeTargets = append(status.ProbeTargets, probeTargets[1])
	}
	if failureType := s.lastFailureType.Load(); failureType != nil {
		status.LastFailureType = *failureType
	}
	s.access.RLock()
	if statusLastContext != "" {
		status.ZigSelectedEndpointID = s.zigSelectedEndpoint[statusLastContext]
		status.ActualDialEndpointID = s.actualDialEndpoint[statusLastContext]
		status.SelectionGeneration = s.selectionGeneration[statusLastContext]
		status.CircuitState = s.circuitState[statusLastContext]
	}
	s.access.RUnlock()
	status.PolicyBackend = smartPolicyBackendName()
	status.Mode = uint8(s.selectionMode)
	status.PolicyBackendRequired = smartPolicyBackendRequired()
	status.PolicyBackendAvailable = s.policyBackendEnabled()
	if len(statusContexts) > 0 {
		status.Contexts = make([]adapter.SmartContextStatus, 0, len(statusContexts))
		for _, key := range statusContextOrder {
			if contextStatus, loaded := statusContexts[key]; loaded {
				s.access.RLock()
				contextStatus.ZigSelectedEndpointID = s.zigSelectedEndpoint[key]
				contextStatus.ActualDialEndpointID = s.actualDialEndpoint[key]
				contextStatus.SelectionGeneration = s.selectionGeneration[key]
				contextStatus.CircuitState = s.circuitState[key]
				s.access.RUnlock()
				contextStatus.LastFailureType = status.LastFailureType
				contextStatus.SelectionMismatchTotal = status.SelectionMismatchTotal
				contextStatus.UnobservedConnectionTotal = status.UnobservedConnectionTotal
				status.Contexts = append(status.Contexts, cloneSmartContextStatus(contextStatus))
			}
		}
	}
	s.switchAuditAccess.Lock()
	status.RecentSwitches = append([]adapter.SmartSwitchAudit(nil), s.switchAudit...)
	s.switchAuditAccess.Unlock()
	return status
}

func cloneSmartContextStatus(source adapter.SmartContextStatus) adapter.SmartContextStatus {
	result := source
	result.StateCounts = cloneSmartStateCounts(source.StateCounts)
	result.Candidates = append([]adapter.SmartCandidateStatus(nil), source.Candidates...)
	return result
}

func cloneSmartGroupStatus(source adapter.SmartGroupStatus) adapter.SmartGroupStatus {
	result := source
	result.StateCounts = cloneSmartStateCounts(source.StateCounts)
	result.Candidates = append([]adapter.SmartCandidateStatus(nil), source.Candidates...)
	result.ProbeTargets = append([]adapter.SmartProbeTargetStatus(nil), source.ProbeTargets...)
	if source.Contexts != nil {
		result.Contexts = make([]adapter.SmartContextStatus, len(source.Contexts))
		for index, contextStatus := range source.Contexts {
			result.Contexts[index] = cloneSmartContextStatus(contextStatus)
		}
	}
	if source.RecentSwitches != nil {
		result.RecentSwitches = append([]adapter.SmartSwitchAudit(nil), source.RecentSwitches...)
	}
	return result
}

func cloneSmartStateCounts(source map[string]int) map[string]int {
	if source == nil {
		return nil
	}
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (s *Smart) SelectOutbound(tag string) bool {
	s.access.RLock()
	candidate, loaded := s.candidateByTag[tag]
	if !loaded || candidate == nil {
		s.access.RUnlock()
		return false
	}
	metadata := s.candidateMetadataByTag[tag]
	s.access.RUnlock()
	s.control.access.Lock()
	s.control.pinned = tag
	s.control.pinnedEndpoint = metadata.identity
	s.control.pinnedDial = metadata.dialIdentity
	s.control.access.Unlock()
	s.resetPolicyBackend()
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil && s.Tag() != "" {
		if err := storeSelectedRecordValue(cacheFile, s.Tag(), s.smartSelectionRecord(tag)); err != nil {
			s.logger.Error("store smart pin: ", err)
		}
	}
	return true
}

func (s *Smart) ClearSelection() {
	s.control.access.Lock()
	s.control.pinned = ""
	s.control.pinnedEndpoint = ""
	s.control.pinnedDial = ""
	s.control.access.Unlock()
	s.resetPolicyBackend()
	if cacheFile := service.FromContext[adapter.CacheFile](s.ctx); cacheFile != nil && s.Tag() != "" {
		if err := clearSelectedRecord(cacheFile, s.Tag()); err != nil {
			s.logger.Error("clear smart pin: ", err)
		}
	}
}

func (s *Smart) SelectTemporaryOutbound(tag string, ttl time.Duration, reason string) bool {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	s.access.RLock()
	if _, loaded := s.candidateByTag[tag]; !loaded {
		s.access.RUnlock()
		return false
	}
	s.access.RUnlock()
	s.control.access.Lock()
	s.control.temporary = tag
	s.control.temporaryUntil = time.Now().Add(ttl)
	s.control.temporaryReason = reason
	s.control.access.Unlock()
	if s.logger != nil {
		s.logger.Info("smart temporary override selected: ", tag, " for ", ttl)
	}
	return true
}

func (s *Smart) ClearTemporarySelection() {
	s.control.access.Lock()
	s.clearTemporaryLocked()
	s.control.access.Unlock()
}

func (s *Smart) clearTemporaryLocked() {
	s.control.temporary = ""
	s.control.temporaryUntil = time.Time{}
	s.control.temporaryReason = ""
}

func (s *Smart) controlSnapshot(now time.Time) (string, string, time.Time, string) {
	s.control.access.Lock()
	if s.control.temporary != "" && !s.control.temporaryUntil.After(now) {
		if s.logger != nil {
			s.logger.Info("smart temporary override expired: ", s.control.temporary)
		}
		s.clearTemporaryLocked()
	}
	pinned := s.control.pinned
	temporary := s.control.temporary
	expiresAt := s.control.temporaryUntil
	reason := s.control.temporaryReason
	s.control.access.Unlock()

	s.access.RLock()
	_, temporaryExists := s.candidateByTag[temporary]
	s.access.RUnlock()
	if temporary == "" || temporaryExists {
		return pinned, temporary, expiresAt, reason
	}

	s.control.access.Lock()
	if temporary != "" && !temporaryExists && s.control.temporary == temporary {
		s.clearTemporaryLocked()
	}
	pinned = s.control.pinned
	temporary = s.control.temporary
	expiresAt = s.control.temporaryUntil
	reason = s.control.temporaryReason
	s.control.access.Unlock()
	return pinned, temporary, expiresAt, reason
}

func (s *Smart) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dashboardProbe := isSmartDashboardProbe(ctx)
	if !dashboardProbe {
		s.noteTrafficActivity()
	}
	transport := smartTransportKey(network, destination)
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	defer func() { ranking.Release() }()
	ranks := ranking.ranks
	if ranking.policyUnavailable {
		return nil, E.New("smart Zig policy backend unavailable")
	}
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) && !dashboardProbe {
		// All circuits being open is an outage state, not a reason to strand the
		// group indefinitely. Run a small, single-flight half-open URLTest-style
		// recovery sample, then rank again if any endpoint proves reachable.
		recovered := s.recoverOpenCandidatesResult(ctx, ranking.candidates, transport)
		if len(recovered) > 0 {
			ranking.Release()
			ranking, networkKey, siteKey, siteDisplay = s.rankPooled(ctx, transport, destination)
			ranks = ranking.ranks
			// A successful recovery probe may still be hidden by the passive
			// throughput floor. That floor is a soft bulk-quality signal, not
			// proof that the endpoint cannot establish a service connection.
			// Use the measured URLTest latency as a bounded emergency fallback so
			// a low-throughput observation cannot strand the whole group.
			if !hasEligibleSmartRank(ranks) {
				ranks = s.emergencyURLTestRanks(ranks, recovered)
			}
		}
		if !hasEligibleSmartRank(ranks) {
			return nil, E.New("smart group has no service-reachable candidate")
		}
	}
	attempts := s.collectDialAttempts(ranks, networkKey, siteKey, transport)
	if len(attempts) == 0 {
		s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible candidates are circuit-open or recovery-busy")
		return nil, E.New("all smart candidates are circuit-open or recovery-busy")
	}
	if conn, result, attemptErrors, ok := s.dialContextAdaptive(ctx, network, destination, attempts, networkKey, siteKey, transport); ok {
		candidate := result.attempt.candidate
		endpointID := result.attempt.rank.status.EndpointID
		if endpointID == "" {
			endpointID = smartEndpointID(result.attempt.rank.identity, result.attempt.rank.policyID)
		}
		if dashboardProbe {
			// The Clash delay endpoint is a read-only control-plane operation.
			// Do not account it as a real dial or commit its candidate as the
			// Smart incumbent; the caller will close this socket after probing.
			return conn, nil
		}
		observedTransport := result.observedTransport
		if observedTransport == "" {
			observedTransport = transport
		}
		adapter.NoteRealOutbound(ctx, candidate)
		selectionCommitted := s.markSelectedWithSnapshot(candidate, networkKey, siteKey, siteDisplay, transport,
			ranking.snapshotSelected, ranking.snapshotSelectedAt, ranking.snapshotValid,
			ranks, result.attempt.attemptIndex, result.hadPriorFailure)
		s.recordActualDialForAttempt(smartStatusSelectionKey(networkKey, siteDisplay, transport), endpointID, result.attempt.rank.selectionGeneration, selectionCommitted)
		conn = s.interruptGroup.NewConnWithKey(conn, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx), smartConnectionKey(networkKey, siteKey, transport, candidate.Tag()))
		observedStartedAt := time.Now().Add(-result.elapsed)
		observed := newSmartObservedConnWithRetransmitReason(conn, observedStartedAt, func(firstByte time.Duration) {
			s.observeMetricForTransport(networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, observedTransport, func(metricTransport string) {
				s.store.observeFirstByte(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), metricTransport, firstByte)
			})
		}, func(bytes int64, duration time.Duration) {
			s.observeMetricForTransport(networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, observedTransport, func(metricTransport string) {
				s.store.observeThroughput(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), metricTransport, bytes, duration)
			})
		}, func(ratio float64) {
			s.observeMetricForTransport(networkKey, siteKey, s.candidateProfileID(candidate.Tag()), transport, observedTransport, func(metricTransport string) {
				s.store.observeRetransmit(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate.Tag()), metricTransport, ratio)
			})
		}, nil, func(failureType string) {
			// A stream can become unusable after DialContext succeeds (for
			// example a stale multiplex session, a reset upstream socket, or
			// a bounded first-response stall). Record the failure against this
			// network/site/transport profile and wake the shared probe. The
			// callback is coalesced once per connection by smartObservedConn.
			s.streamFailureWakes.Add(1)
			if failureType == "" {
				failureType = "transport"
			}
			s.observeDataPlaneFailureWithType(time.Now(), networkKey, siteKey, candidate.Tag(), transport, time.Since(observedStartedAt), failureType)
			if observedTransport != "" && observedTransport != transport {
				s.observeDataPlaneFailureWithType(time.Now(), networkKey, siteKey, candidate.Tag(), observedTransport, time.Since(observedStartedAt), failureType)
			}
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
		}, s.establishedStallTimeout, ctx)
		if _, wrapped := observed.(smartObservedWrapper); !wrapped {
			s.recordUnobservedConnection(smartStatusSelectionKey(networkKey, siteDisplay, transport), endpointID)
		}
		return observed, nil
	} else {
		s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible candidates failed")
		if len(attemptErrors) == 0 {
			return nil, E.New("all smart candidates are circuit-open or recovery-busy")
		}
		return nil, errors.Join(attemptErrors...)
	}
}

func (s *Smart) collectDialAttempts(ranks []smartRank, networkKey, siteKey, transport string) []smartDialAttempt {
	maxAttempts := s.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	attempts := make([]smartDialAttempt, 0, min(maxAttempts, len(ranks)))
	seenDialIdentities := make(map[string]struct{}, len(ranks))
	for _, rankIndex := range smartAttemptRankOrder(ranks, maxAttempts) {
		if len(attempts) >= maxAttempts {
			break
		}
		rank := ranks[rankIndex]
		if !rank.eligible || rank.status.State == "open" {
			continue
		}
		// A provider aggregate may expose one physical path under multiple
		// aliases. Retry/hedge diversity is about authenticated dial identities,
		// not display tags; never spend two attempts on the same credentialed
		// endpoint. Different credentials remain eligible because their dial
		// identities are distinct from the shared probe identity.
		dialIdentity := rank.dialIdentity
		if dialIdentity == "" {
			dialIdentity = rank.identity
		}
		if dialIdentity == "" && rank.outbound != nil {
			dialIdentity = rank.outbound.Tag()
		}
		if _, exists := seenDialIdentities[dialIdentity]; exists {
			continue
		}
		seenDialIdentities[dialIdentity] = struct{}{}
		reserved := s.reserveHalfOpen(rank, networkKey, siteKey, transport)
		if rank.status.State == "half_open" && !reserved {
			continue
		}
		candidate := rank.outbound
		attempts = append(attempts, smartDialAttempt{
			rankIndex:    rankIndex,
			attemptIndex: len(attempts),
			rank:         rank,
			candidate:    candidate,
			reserved:     reserved,
		})
	}
	return attempts
}

// smartAttemptRankOrder reserves one final retry slot for an explicit standby
// after normal members have failed. A standby never wins the first cold dial
// while a normal member is available, but stays reachable within the bounded
// per-request retry budget instead of sitting behind a large catalog forever.
func smartAttemptRankOrder(ranks []smartRank, maxAttempts int) []int {
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	normals := make([]int, 0, len(ranks))
	standbys := make([]int, 0)
	for index, rank := range ranks {
		if !rank.eligible || rank.status.State == "open" {
			continue
		}
		if rank.standbyOnly {
			standbys = append(standbys, index)
		} else {
			normals = append(normals, index)
		}
	}
	// Once a standby has actually accepted traffic and became the fixed-mode
	// incumbent, keep it first on later requests until it becomes unavailable.
	for position, index := range standbys {
		if ranks[index].incumbent {
			order := make([]int, 0, len(normals)+len(standbys))
			order = append(order, index)
			order = append(order, normals...)
			order = append(order, standbys[:position]...)
			order = append(order, standbys[position+1:]...)
			return order
		}
	}
	if len(normals) == 0 {
		return standbys
	}
	if len(standbys) == 0 || maxAttempts <= 1 {
		return append(normals, standbys...)
	}
	firstNormals := min(len(normals), maxAttempts-1)
	order := make([]int, 0, len(normals)+len(standbys))
	order = append(order, normals[:firstNormals]...)
	order = append(order, standbys...)
	order = append(order, normals[firstNormals:]...)
	return order
}

type smartRecoveryCandidate struct {
	candidate adapter.Outbound
	measured  time.Duration
}

// recoverOpenCandidates is the outage escape hatch for the staged selector.
// Once every candidate is circuit-open, waiting for the ordinary probe cadence
// would strand new connections. A short, rotating half-open sample instead
// revalidates a bounded subset; one success immediately closes that endpoint's
// circuit and lets the normal health-tier ranking choose it as primary. The
// registry keeps the sample single-flight across Smart groups.
func (s *Smart) recoverOpenCandidates(ctx context.Context, candidates []adapter.Outbound, transport string) bool {
	return len(s.recoverOpenCandidatesResult(ctx, candidates, transport)) > 0
}

func (s *Smart) recoverOpenCandidatesResult(ctx context.Context, candidates []adapter.Outbound, transport string) []smartRecoveryCandidate {
	if s == nil || ctx.Err() != nil || s.closing.Load() || len(candidates) == 0 {
		return nil
	}
	baseTransport := smartTransportBase(transport)
	now := time.Now()
	next := s.recoveryProbeUntilUnixNano.Load()
	if next > now.UnixNano() || !s.recoveryProbeUntilUnixNano.CompareAndSwap(next, now.Add(defaultSmartRecoveryProbeCooldown).UnixNano()) {
		return nil
	}
	eligible := make([]adapter.Outbound, 0, len(candidates))
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), baseTransport) {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	budget := max(defaultSmartColdProbeBudget, max(s.maxAttempts, 1))
	if budget > 8 {
		budget = 8
	}
	if len(eligible) > budget {
		start := int(s.probeCursor.Add(uint64(budget))-uint64(budget)) % len(eligible)
		eligible = append(eligible[start:], eligible[:start]...)
		eligible = eligible[:budget]
	}
	probeTimeout := defaultSmartRecoveryProbeTimeout
	if s.probeTimeout > 0 && s.probeTimeout < probeTimeout {
		probeTimeout = s.probeTimeout
	}
	type recoveryResult struct {
		candidate adapter.Outbound
		measured  time.Duration
		err       error
		performed bool
	}
	results := make(chan recoveryResult, len(eligible))
	jobs := make(chan adapter.Outbound)
	workerCount := min(max(s.probeConcurrency, 1), len(eligible))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
				startedAt := time.Now()
				var (
					err       error
					measured  time.Duration
					performed bool
				)
				if s.probeRegistry != nil {
					s.access.RLock()
					metadata := s.candidateMetadataByTag[candidate.Tag()]
					s.access.RUnlock()
					identity := metadata.identity
					if identity == "" {
						identity = candidate.Tag()
					}
					dialIdentity := metadata.dialIdentity
					if dialIdentity == "" {
						dialIdentity = identity
					}
					key := metadata.probeKey
					if baseTransport == N.NetworkUDP {
						key = nodeProfileKey(dialIdentity, "udp://dns-health\x00"+transport, 0)
					} else if probeFamily := smartTransportFamily(transport); probeFamily != "" {
						key = nodeProfileKey(dialIdentity, s.probeProfileLink(transport), 0)
					} else if key == "" {
						key = nodeProfileKey(dialIdentity, s.probeProfileLink(N.NetworkTCP), 0)
					}
					var delay uint16
					delay, err, _ = s.executeProbe(probeCtx, smartProbeRequest{
						purpose:     smartProbeRecovery,
						endpointKey: identity,
						profileKey:  key,
						timeout:     probeTimeout,
						ttl:         s.probeInterval,
					}, func(probeContext context.Context) (uint16, error) {
						performed = true
						if baseTransport == N.NetworkUDP {
							return 0, runSmartUDPHealthProbeForTransport(probeContext, candidate, transport)
						}
						return s.probeURLWithFallback(probeContext, candidate, smartTransportFamily(transport), true)
					})
					if baseTransport == N.NetworkUDP {
						measured = time.Since(startedAt)
					} else if err == nil {
						measured = time.Duration(delay) * time.Millisecond
					}
				} else if baseTransport == N.NetworkUDP {
					performed = true
					err = runSmartUDPHealthProbeForTransport(probeCtx, candidate, transport)
					measured = time.Since(startedAt)
				} else {
					performed = true
					var delay uint16
					delay, err = s.probeURLWithFallback(probeCtx, candidate, smartTransportFamily(transport), false)
					if err == nil {
						measured = time.Duration(delay) * time.Millisecond
					}
				}
				cancel()
				if measured <= 0 {
					measured = time.Since(startedAt)
				}
				results <- recoveryResult{candidate: candidate, measured: measured, err: err, performed: performed}
			}
		}()
	}
dispatch:
	for _, candidate := range eligible {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	close(results)
	networkKey := s.networkFingerprint()
	successes := 0
	observedProfiles := make(map[string]struct{}, len(eligible))
	recovered := make([]smartRecoveryCandidate, 0, len(results))
	for result := range results {
		profileID := s.candidateProfileID(result.candidate.Tag())
		if !result.performed {
			// A waiter still needs one local success observation to recover its
			// own store, but must not duplicate a shared failure penalty.
			if result.err != nil {
				continue
			}
		}
		if _, exists := observedProfiles[profileID]; exists {
			continue
		}
		observedProfiles[profileID] = struct{}{}
		if result.err == nil {
			successes++
			s.observeDial(time.Now(), networkKey, "", result.candidate.Tag(), transport, true, result.measured)
			recovered = append(recovered, smartRecoveryCandidate{candidate: result.candidate, measured: result.measured})
		} else if result.performed {
			s.observeDial(time.Now(), networkKey, "", result.candidate.Tag(), transport, false, result.measured)
		}
	}
	if successes > 0 {
		s.noteProbeCycle(successes)
		sort.SliceStable(recovered, func(i, j int) bool { return recovered[i].measured < recovered[j].measured })
	}
	return recovered
}

// emergencyURLTestRanks converts successful recovery probes into a temporary
// ranking when the normal bulk throughput gate would otherwise mark every
// endpoint open. The probe result is authoritative only for this bounded
// dial attempt; the underlying throughput evidence remains intact and can
// continue to influence later choices once real traffic supplies useful data.
func (s *Smart) emergencyURLTestRanks(ranks []smartRank, recovered []smartRecoveryCandidate) []smartRank {
	if len(ranks) == 0 || len(recovered) == 0 {
		return ranks
	}
	byTag := make(map[string]smartRank, len(ranks))
	for _, rank := range ranks {
		if rank.outbound != nil {
			byTag[rank.outbound.Tag()] = rank
		}
	}
	result := make([]smartRank, 0, min(len(recovered), s.maxAttempts))
	seen := make(map[string]struct{}, len(recovered))
	for _, recovery := range recovered {
		if recovery.candidate == nil {
			continue
		}
		tag := recovery.candidate.Tag()
		if _, exists := seen[tag]; exists {
			continue
		}
		rank, exists := byTag[tag]
		if !exists {
			continue
		}
		// Recovery proved that the endpoint can establish the probe service.
		// Keep this as a warming, one-attempt escape hatch rather than clearing
		// the stored passive throughput evidence or circuit ledger globally.
		rank.eligible = true
		rank.passiveThroughputLow = false
		rank.status.State = "warming"
		rank.status.Reason = "URLTest emergency fallback"
		result = append(result, rank)
		seen[tag] = struct{}{}
		if len(result) >= max(s.maxAttempts, 1) {
			break
		}
	}
	return result
}

func (s *Smart) dialContextAdaptive(ctx context.Context, network string, destination M.Socksaddr, attempts []smartDialAttempt, networkKey, siteKey, transport string) (net.Conn, smartDialResult, []error, bool) {
	dashboardProbe := isSmartDashboardProbe(ctx)
	parentCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	results := make(chan smartDialResult, len(attempts))
	started := 0
	defer func() {
		for index := started; index < len(attempts); index++ {
			if attempts[index].reserved {
				s.releaseHalfOpen(attempts[index].candidate.Tag(), networkKey, siteKey, transport)
			}
		}
	}()
	startAttempt := func(attempt smartDialAttempt) {
		go func() {
			startedAt := time.Now()
			attemptCtx := parentCtx
			var cancel context.CancelFunc
			if s.attemptTimeout > 0 {
				attemptCtx, cancel = context.WithTimeout(parentCtx, s.attemptTimeout)
			}
			conn, err := attempt.candidate.DialContext(attemptCtx, network, destination)
			if cancel != nil {
				cancel()
			}
			if attempt.reserved {
				s.releaseHalfOpen(attempt.candidate.Tag(), networkKey, siteKey, transport)
			}
			elapsed := time.Since(startedAt)
			if err == nil && parentCtx.Err() != nil {
				conn.Close()
				return
			}
			result := smartDialResult{attempt: attempt, conn: conn, err: err, elapsed: elapsed}
			if err == nil {
				result.observedTransport = smartTransportKeyFromConn(network, destination, conn)
			}
			results <- result
		}()
	}

	active := 0
	startAttempt(attempts[started])
	started++
	active++

	var hedgeTimer *time.Timer
	var hedgeC <-chan time.Time
	resetHedge := func() {
		if started >= len(attempts) || active == 0 {
			if hedgeTimer != nil {
				hedgeTimer.Stop()
			}
			hedgeC = nil
			return
		}
		// Once a business already has a well-sampled healthy incumbent, do not
		// race a second endpoint. Hedging is useful during cold start and after
		// a real failure, but on a stable path it creates simultaneous egress
		// IPs for one logical business (notably Google/ChatGPT) and defeats
		// business-family affinity.
		if started == 1 && attempts[0].rank.status.State == "healthy" &&
			attempts[0].rank.status.Reliability >= 0.9 && attempts[0].rank.status.Samples >= 3 {
			hedgeC = nil
			if hedgeTimer != nil {
				hedgeTimer.Stop()
			}
			return
		}
		delay := s.smartHedgeDelay()
		// A well-sampled, highly reliable current candidate should get a
		// little more first-byte time.  The first dial is still started
		// immediately; this only delays a competing dial, avoiding needless
		// Safari/Google connection races.  If the dial actually fails, the
		// normal error path starts the next candidate without waiting.
		if s.currentPhase() > smartPhaseBaseline && started == 1 && attempts[0].rank.status.State == "healthy" &&
			attempts[0].rank.status.Reliability >= 0.9 && attempts[0].rank.status.Samples >= 10 {
			delay += 250 * time.Millisecond
			if delay > 1200*time.Millisecond {
				delay = 1200 * time.Millisecond
			}
		}
		if delay <= 0 {
			hedgeC = nil
			return
		}
		if hedgeTimer == nil {
			hedgeTimer = time.NewTimer(delay)
		} else {
			if !hedgeTimer.Stop() {
				select {
				case <-hedgeTimer.C:
				default:
				}
			}
			hedgeTimer.Reset(delay)
		}
		hedgeC = hedgeTimer.C
	}
	stopHedge := func() {
		if hedgeTimer != nil {
			hedgeTimer.Stop()
		}
	}
	defer stopHedge()
	resetHedge()

	var attemptErrors []error
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, smartDialResult{}, append(attemptErrors, ctx.Err()), false
		case <-hedgeC:
			if started < len(attempts) {
				startAttempt(attempts[started])
				started++
				active++
			}
			resetHedge()
		case result := <-results:
			active--
			// A caller cancellation can race the worker result.  Treat that
			// cancellation as request-local state, not node health evidence, and
			// never return a late socket to a request that has already gone away.
			if parentErr := ctx.Err(); parentErr != nil {
				if result.conn != nil {
					_ = result.conn.Close()
				}
				return nil, smartDialResult{}, append(attemptErrors, parentErr), false
			}
			candidate := result.attempt.candidate
			if result.err != nil {
				if dashboardProbe {
					// A panel check is advisory. It must not quarantine a node or
					// wake the normal recovery worker because of one probe failure.
					s.observeProbeResult(true, time.Now(), networkKey, siteKey, candidate.Tag(), transport, false, result.elapsed)
				} else {
					failureType := smartFailureType(result.err)
					s.observeDataPlaneFailureWithType(time.Now(), networkKey, siteKey, candidate.Tag(), transport, result.elapsed, failureType)
					s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
					// A real data-plane failure must wake recovery itself. Dashboard
					// latency tests may also refresh the shared profile, but production
					// failover must never depend on a user opening the proxy page. The
					// buffered request channel coalesces concurrent failures and the
					// shared probe registry single-flights work per endpoint.
					s.requestProbe()
				}
				attemptErrors = append(attemptErrors, E.Cause(result.err, "smart candidate ", candidate.Tag()))
				if started < len(attempts) {
					startAttempt(attempts[started])
					started++
					active++
				}
				resetHedge()
				continue
			}
			if dashboardProbe {
				s.observeProbeResult(true, time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, result.elapsed)
			} else {
				s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, result.elapsed)
				s.recordSharedDataPlaneEvidence(candidate.Tag(), transport, true)
			}
			if result.observedTransport != "" && result.observedTransport != transport {
				s.observeProbeResult(dashboardProbe, time.Now(), networkKey, siteKey, candidate.Tag(), result.observedTransport, true, result.elapsed)
			}
			result.hadPriorFailure = len(attemptErrors) > 0
			cancelAll()
			return result.conn, result, attemptErrors, true
		}
	}
	return nil, smartDialResult{}, attemptErrors, false
}

func (s *Smart) smartHedgeDelay() time.Duration {
	if s.maxAttempts <= 1 {
		return 0
	}
	if s.currentPhase() <= smartPhaseBaseline {
		// During cold/baseline startup the first candidate is often only an
		// unprofiled guess. Start the backup after 250ms so first use is fast;
		// once profiling is established the longer delay protects keep-alive
		// paths from needless parallel dials.
		return minSmartHedgeDelay
	}
	if s.attemptTimeout <= 0 {
		return defaultSmartHedgeDelay
	}
	delay := s.attemptTimeout / 3
	if delay < minSmartHedgeDelay {
		return minSmartHedgeDelay
	}
	if delay > maxSmartHedgeDelay {
		return maxSmartHedgeDelay
	}
	return delay
}

func (s *Smart) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.noteTrafficActivity()
	transport := smartTransportKey(N.NetworkUDP, destination)
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	defer func() { ranking.Release() }()
	ranks := ranking.ranks
	if ranking.policyUnavailable {
		return nil, E.New("smart Zig policy backend unavailable")
	}
	if len(ranks) == 0 {
		return nil, E.New("smart group is warming: no supported candidate")
	}
	if !hasEligibleSmartRank(ranks) {
		recovered := s.recoverOpenCandidatesResult(ctx, ranking.candidates, transport)
		if len(recovered) > 0 {
			ranking.Release()
			ranking, networkKey, siteKey, siteDisplay = s.rankPooled(ctx, transport, destination)
			ranks = ranking.ranks
			if !hasEligibleSmartRank(ranks) {
				ranks = s.emergencyURLTestRanks(ranks, recovered)
			}
		}
		if !hasEligibleSmartRank(ranks) {
			return nil, E.New("smart group has no service-reachable UDP candidate")
		}
	}
	var attemptErrors []error
	attemptCount := 0
	maxAttempts := s.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultSmartMaxAttempts
	}
	for _, rankIndex := range smartAttemptRankOrder(ranks, maxAttempts) {
		rank := ranks[rankIndex]
		if !rank.eligible || rank.status.State == "open" || attemptCount >= maxAttempts {
			continue
		}
		reserved := s.reserveHalfOpen(rank, networkKey, siteKey, transport)
		if rank.status.State == "half_open" && !reserved {
			continue
		}
		candidate := rank.outbound
		attemptIndex := attemptCount
		attemptCount++
		startedAt := time.Now()
		attemptCtx := ctx
		var cancel context.CancelFunc
		if s.attemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, s.attemptTimeout)
		}
		conn, err := candidate.ListenPacket(attemptCtx, destination)
		if cancel != nil {
			cancel()
		}
		if reserved {
			s.releaseHalfOpen(candidate.Tag(), networkKey, siteKey, transport)
		}
		elapsed := time.Since(startedAt)
		// A caller cancellation/deadline is not evidence that the candidate is
		// unhealthy.  In particular, an outbound may return ctx.Err() after the
		// parent has already been canceled, or may win a cancellation race and
		// return a usable socket just after the caller went away.  Do not feed
		// either case into the breaker, and never leak the late socket to the
		// canceled request.  The independent attempt timeout still reaches the
		// failure path below because ctx itself remains live.
		if parentErr := ctx.Err(); parentErr != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, parentErr
		}
		if err != nil {
			failureType := smartFailureType(err)
			s.observeDataPlaneFailureWithType(time.Now(), networkKey, siteKey, candidate.Tag(), transport, elapsed, failureType)
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
			attemptErrors = append(attemptErrors, E.Cause(err, "smart candidate ", candidate.Tag()))
			continue
		}
		s.observeDial(time.Now(), networkKey, siteKey, candidate.Tag(), transport, true, elapsed)
		s.recordSharedDataPlaneEvidence(candidate.Tag(), transport, true)
		adapter.NoteRealOutbound(ctx, candidate)
		endpointID := rank.status.EndpointID
		if endpointID == "" {
			endpointID = smartEndpointID(rank.identity, rank.policyID)
		}
		selectionCommitted := s.markSelectedWithSnapshot(candidate, networkKey, siteKey, siteDisplay, transport,
			ranking.snapshotSelected, ranking.snapshotSelectedAt, ranking.snapshotValid,
			ranks, attemptIndex, attemptIndex > 0)
		s.recordActualDialForAttempt(smartStatusSelectionKey(networkKey, siteDisplay, transport), endpointID, rank.selectionGeneration, selectionCommitted)
		observed := newSmartObservedPacketConnWithWatchdogThreshold(conn, startedAt, smartUDPExpectsResponse(destination), smartUDPRequiredResponsePackets(destination), s.establishedStallTimeout, func(flowElapsed time.Duration) {
			s.observeDataPlaneFailureWithType(time.Now(), networkKey, siteKey, candidate.Tag(), transport, flowElapsed, "udp_no_response")
			s.clearBrokenPin(candidate.Tag(), networkKey, siteKey, transport)
			s.requestProbe()
		})
		if _, wrapped := observed.(smartObservedWrapper); !wrapped {
			s.recordUnobservedConnection(smartStatusSelectionKey(networkKey, siteDisplay, transport), endpointID)
		}
		return s.interruptGroup.NewPacketConnWithKey(observed, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsProviderConnectionFromContext(ctx), smartConnectionKey(networkKey, siteKey, transport, candidate.Tag())), nil
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, "", "all eligible UDP candidates failed")
	if len(attemptErrors) == 0 {
		return nil, E.New("all smart UDP candidates are circuit-open or recovery-busy")
	}
	return nil, errors.Join(attemptErrors...)
}

func smartUDPExpectsResponse(destination M.Socksaddr) bool {
	switch destination.Port {
	case 53, 443, 3478:
		return true
	default:
		return false
	}
}

func smartUDPRequiredResponsePackets(destination M.Socksaddr) uint64 {
	// DNS is a one-datagram transaction and must remain observable after one
	// query. QUIC/STUN can legitimately spend their first packets on path
	// validation or retransmission; requiring three datagrams before declaring a
	// blackhole avoids turning a single lost packet into a node failover.
	switch destination.Port {
	case 443, 3478:
		return 3
	default:
		return 1
	}
}

func (s *Smart) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Smart) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func hasEligibleSmartRank(ranks []smartRank) bool {
	for _, rank := range ranks {
		if rank.eligible && rank.status.State != "open" {
			return true
		}
	}
	return false
}

func (s *Smart) URLTest(ctx context.Context) (map[string]uint16, error) {
	// URLTest is also the compatibility path used by older panels that do not
	// send the newer DashboardURLTest request. Treat it as a read-only
	// measurement just like the explicit dashboard API: a manual pin must not
	// be released or replaced because a single latency request failed or won.
	return s.probeWithBudget(withSmartDashboardProbe(ctx), 0)
}

// DashboardURLTest is deliberately bounded.  The native URLTest contract is
// a full group probe; using it for a panel refresh would scan every provider
// alias and compete with real traffic.  The dashboard path uses the same
// endpoint-deduplicating registry, health portraits and UDP/TCP split as the
// normal Smart worker, but only a small advisory budget per request.  A later
// scheduled cycle fills the remaining catalog without a control-plane burst.
func (s *Smart) DashboardURLTest(ctx context.Context) (map[string]uint16, error) {
	return s.probeWithBudget(withSmartDashboardProbe(ctx), s.dashboardProbeBudget)
}

// PerformUpdateCheck is the non-blocking hook used by the Clash API after a
// manual delay test. Smart owns its probe worker, so the API must only wake a
// bounded cycle instead of starting a second probe goroutine or mutating
// selection state from the HTTP handler.
func (s *Smart) PerformUpdateCheck() {
	if s.closing.Load() {
		return
	}
	// A leaf delay request is a control-plane hint, not a traffic-activity
	// wakeup. Keep it on the dashboard budget (full catalog when unbounded);
	// otherwise an active Smart group would expand one manual test into its
	// 16-candidate profiling cycle.
	s.requestDashboardProbeWithBudget(s.dashboardProbeBudget)
}

func (s *Smart) probe(ctx context.Context) (map[string]uint16, error) {
	return s.probeWithBudget(ctx, 0)
}

func (s *Smart) probeWithBudget(ctx context.Context, budget int) (result map[string]uint16, err error) {
	probePurpose := smartProbePurposeFromContext(ctx)
	probeStatsBefore := s.probeTargetSnapshot()
	probePolicy := probePurpose.policy()
	dashboardProbe := probePolicy.advisory
	coveragePurpose := smartProbeTransportCoverage
	if dashboardProbe {
		coveragePurpose = smartProbeDashboard
	}
	result = make(map[string]uint16)
	// The portrait sweep must outlive the caller's deadline: a panel timeout
	// must not discard in-flight dial evidence, or the catalog can never fill
	// its health portraits.  Workers and the collector run on an internal
	// sweep deadline (probeCycleTimeout); the caller receives whatever
	// completed inside its own window while the sweep keeps recording.
	var resultMu sync.Mutex
	if ctx.Err() != nil || s.closing.Load() {
		return result, ctx.Err()
	}
	if s.probing.Swap(true) {
		return result, nil
	}
	defer s.probing.Store(false)
	s.access.RLock()
	allCandidates := append([]adapter.Outbound(nil), s.candidates...)
	metadataByTag := s.candidateMetadataByTag
	s.access.RUnlock()
	if len(allCandidates) == 0 || s.closing.Load() {
		return result, nil
	}
	// Keep the TCP budget a true TCP budget. A UDP-only outbound must not
	// consume one of the bounded TCP slots and make a healthy TCP catalog look
	// smaller than it is; the complete catalog is still passed to the separate
	// UDP scheduler below.
	candidates := make([]adapter.Outbound, 0, len(allCandidates))
	for _, candidate := range allCandidates {
		if common.Contains(candidate.Network(), N.NetworkTCP) {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		if ctx.Err() == nil && !s.closing.Load() {
			s.probeUDPWithBudget(ctx, coveragePurpose, allCandidates, budget)
		}
		return result, ctx.Err()
	}
	profileIDFor := func(tag string) string {
		if metadata, ok := metadataByTag[tag]; ok && metadata.profileID != "" {
			return metadata.profileID
		}
		return tag
	}
	if probePurpose == smartProbeBackground && budget > 0 {
		candidates = s.selectProbeCandidates(candidates, budget, probePurpose)
	} else if budget > 0 && len(candidates) > budget {
		s.access.RLock()
		useScoresAvailable := len(s.useScores) > 0
		s.access.RUnlock()
		if useScoresAvailable {
			candidates = s.selectProbeCandidates(candidates, budget, probePurpose)
		} else {
			advance := budget
			start := int(s.probeCursor.Add(uint64(advance))-uint64(advance)) % len(candidates)
			candidates = append(candidates[start:], candidates[:start]...)
			candidates = candidates[:budget]
		}
	} else if len(candidates) > 1 {
		advance := 1
		start := int(s.probeCursor.Add(uint64(advance))-uint64(advance)) % len(candidates)
		candidates = append(candidates[start:], candidates[:start]...)
	}
	sweepDeadline := s.probeCycleTimeout
	if sweepDeadline <= 0 {
		sweepDeadline = defaultSmartProbeCycleTimeout
	}
	sweepCtx, sweepCancel := context.WithTimeout(context.WithoutCancel(ctx), sweepDeadline)
	type probeResult struct {
		candidate adapter.Outbound
		delay     uint16
		err       error
		penalize  bool
		families  []smartTCPProbeFamilyResult
		// performed is false for a registry cache hit.  Cached answers are
		// usable for the caller, but must not be counted as fresh evidence.
		performed bool
	}
	results := make(chan probeResult, len(candidates))
	jobs := make(chan adapter.Outbound)
	var waitGroup sync.WaitGroup
	// Keep exploration from competing with real browser traffic.  The old
	// fixed five workers caused Safari's parallel Google asset requests to
	// fan out across many candidates and briefly starve the selected path.
	probeConcurrency := s.probeConcurrency
	// Test/embedded constructors may not pass through NewSmart. Preserve the
	// bounded default there as well; a zero value must never silently create a
	// probe cycle with no workers.
	if probeConcurrency <= 0 {
		probeConcurrency = defaultSmartProbeConcurrency
	}
	workerCount := min(probeConcurrency, len(candidates))
	for range workerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for candidate := range jobs {
				if sweepCtx.Err() != nil || s.closing.Load() {
					results <- probeResult{candidate: candidate, err: context.Canceled}
					continue
				}
				metadata, ok := metadataByTag[candidate.Tag()]
				if !ok {
					metadata = s.buildCandidateMetadata(candidate.Tag(), "")
				}
				key := metadata.probeKey
				var delay uint16
				var err error
				performed := false
				if s.probeRegistry != nil {
					// Admission is process-wide and may legitimately wait behind
					// another group. Apply the per-node timeout only after a slot is
					// acquired inside the registry; otherwise a healthy node can be
					// mislabeled merely because the shared queue took five seconds.
					delay, err, performed = s.executeProbe(sweepCtx, smartProbeRequest{
						purpose:     probePurpose,
						endpointKey: metadata.identity,
						profileKey:  key,
						timeout:     s.probeTimeout,
						ttl:         s.probeInterval,
					}, func(probeCtx context.Context) (uint16, error) {
						return s.probeURLWithFallback(probeCtx, candidate, "", true)
					})
				} else {
					// Test/embedded constructors created before the shared registry
					// contract retain the stock direct probe path.
					testCtx, cancel := context.WithTimeout(sweepCtx, s.probeTimeout)
					delay, err = s.probeURLWithFallback(testCtx, candidate, "", false)
					cancel()
					performed = true
				}
				families := s.probeTCPFamilies(ctx, coveragePurpose, candidate, metadata)
				penalize := err != nil && !errors.Is(err, errSharedNodeProbeDeferred) && sweepCtx.Err() == nil && !s.closing.Load()
				results <- probeResult{candidate: candidate, delay: delay, err: err, penalize: penalize, performed: performed, families: families}
			}
		}()
	}
	type probeSummary struct {
		collected []probeResult
		successes int
		performed int
	}
	networkKey := s.networkFingerprint()
	summaryDone := make(chan probeSummary, 1)
	go func() {
		summary := probeSummary{collected: make([]probeResult, 0, len(candidates))}
		published := false
		observed := make(map[string]struct{}, len(candidates)*2)
		noted := make(map[string]struct{}, len(candidates))
		attemptedProfiles := make(map[string]struct{}, len(candidates))
		performedProfiles := make(map[string]struct{}, len(candidates))
		successfulProfiles := make(map[string]struct{}, len(candidates))
		for probe := range results {
			summary.collected = append(summary.collected, probe)
			profileID := profileIDFor(probe.candidate.Tag())
			if probe.performed {
				if _, exists := performedProfiles[profileID]; !exists {
					performedProfiles[profileID] = struct{}{}
					summary.performed++
				}
			}
			familySuccess := uint16(0)
			familyPerformed := false
			for _, family := range probe.families {
				if family.performed {
					familyPerformed = true
					if _, exists := noted[profileID]; !exists {
						noted[profileID] = struct{}{}
						s.noteCandidateProbe(probe.candidate.Tag(), time.Now())
					}
				}
				observationKey := profileID + "\x00" + family.transport
				if _, exists := observed[observationKey]; exists {
					continue
				}
				observed[observationKey] = struct{}{}
				if family.err == nil && family.performed {
					if familySuccess == 0 || family.delay < familySuccess {
						familySuccess = family.delay
					}
					elapsed := family.elapsed
					if family.delay > 0 {
						elapsed = time.Duration(family.delay) * time.Millisecond
					}
					s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "", probe.candidate.Tag(), family.transport, true, elapsed)
				} else if family.err != nil && family.performed {
					s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "", probe.candidate.Tag(), family.transport, false, family.elapsed)
				}
			}
			if (probe.performed || probe.err == nil || familyPerformed) && !s.closing.Load() {
				if _, exists := attemptedProfiles[profileID]; !exists {
					attemptedProfiles[profileID] = struct{}{}
					s.noteCandidateAttempt(probe.candidate.Tag(), time.Now())
				}
			}
			if probe.err != nil && familySuccess == 0 {
				continue
			}
			if probe.err != nil && familySuccess > 0 {
				probe.delay = familySuccess
				probe.err = nil
				probe.performed = familyPerformed
			}
			resultMu.Lock()
			result[probe.candidate.Tag()] = probe.delay
			resultMu.Unlock()
			if !probe.performed {
				continue
			}
			if _, exists := successfulProfiles[profileID]; exists {
				continue
			}
			successfulProfiles[profileID] = struct{}{}
			summary.successes++
			if s.closing.Load() {
				continue
			}
			if _, exists := noted[profileID]; !exists {
				noted[profileID] = struct{}{}
				s.noteCandidateProbe(probe.candidate.Tag(), time.Now())
			}
			observationKey := profileID + "\x00" + N.NetworkTCP
			if _, exists := observed[observationKey]; !exists {
				observed[observationKey] = struct{}{}
				s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, true, time.Duration(probe.delay)*time.Millisecond)
			}
			if !published && probePolicy.publishLatest {
				// The first successful basic probe makes a cold group usable while
				// the remaining candidates continue to build profiles in parallel.
				ranking, _, _, _ := s.rankPooled(s.ctx, N.NetworkTCP, M.Socksaddr{})
				ranking.Release()
				published = true
			}
		}
		summaryDone <- summary
	}()
	dispatching := true
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), N.NetworkTCP) {
			select {
			case jobs <- candidate:
			case <-ctx.Done():
				dispatching = false
			}
			if !dispatching {
				break
			}
		}
	}
	close(jobs)
	waitGroup.Wait()
	close(results)

	finishSweep := func(summary probeSummary) {
		defer sweepCancel()
		if sweepCtx.Err() == nil && !s.closing.Load() {
			// TCP probes establish reachability; a small, serialized UDP DNS sample
			// establishes that the same candidate can carry transactional datagrams.
			// Keep this separate from the TCP result map so URLTest callers retain
			// their historical latency contract while UDP evidence enters its own
			// profile and cannot poison TCP ranking.
			s.probeUDPWithBudget(sweepCtx, coveragePurpose, allCandidates, budget)
		}
		if s.closing.Load() {
			// Shutdown: skip store mutations so Close can clear maps safely.  A
			// probe-cycle deadline is different: completed observations remain
			// valuable and must be committed so inactive/large groups eventually
			// build a baseline over multiple bounded cycles.
			return
		}
		commonFailure := summary.performed > 1 && summary.successes == 0
		penalizedProfiles := make(map[string]struct{}, len(summary.collected))
		for _, probe := range summary.collected {
			if probePolicy.allowPenalty && probe.err != nil && probe.penalize && probe.performed && !commonFailure {
				profileID := profileIDFor(probe.candidate.Tag())
				if _, exists := penalizedProfiles[profileID]; exists {
					continue
				}
				metadata, ok := metadataByTag[probe.candidate.Tag()]
				if !ok {
					metadata = s.buildCandidateMetadata(probe.candidate.Tag(), "")
				}
				if s.probeRegistry == nil || s.probeRegistry.dead(metadata.probeKey) {
					penalizedProfiles[profileID] = struct{}{}
					s.noteCandidateProbe(probe.candidate.Tag(), time.Now())
					s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "", probe.candidate.Tag(), N.NetworkTCP, false, s.probeTimeout)
				}
			}
		}
		if summary.successes > 0 {
			s.noteProbeCycle(summary.successes)
			// Publish the baseline immediately.  Ranking is otherwise refreshed only
			// by a real dial, which makes traffic-idle groups look permanently warming
			// even though their active probes have already populated the store.
			if probePolicy.publishLatest {
				ranking, _, _, _ := s.rankPooled(s.ctx, N.NetworkTCP, M.Socksaddr{})
				ranking.Release()
			}
		}
		if commonFailure {
			if s.logger != nil {
				probeStatsAfter := s.probeTargetSnapshot()
				s.logger.Warn("smart probe suppressed candidate penalties because sampled candidates failed: sampled=", len(candidates),
					" performed=", summary.performed,
					" primary=", probeStatsAfter[0].TargetHost,
					" primary_failures=", probeStatsAfter[0].Failures-probeStatsBefore[0].Failures,
					" primary_timeouts=", probeStatsAfter[0].Timeouts-probeStatsBefore[0].Timeouts,
					" primary_http_failures=", probeStatsAfter[0].HTTPFailures-probeStatsBefore[0].HTTPFailures,
					" fallback=", probeStatsAfter[1].TargetHost,
					" fallback_failures=", probeStatsAfter[1].Failures-probeStatsBefore[1].Failures,
					" fallback_timeouts=", probeStatsAfter[1].Timeouts-probeStatsBefore[1].Timeouts,
					" fallback_http_failures=", probeStatsAfter[1].HTTPFailures-probeStatsBefore[1].HTTPFailures,
					" fallback_successes=", probeStatsAfter[1].Successes-probeStatsBefore[1].Successes,
					" last_primary_failure=", probeStatsAfter[0].LastFailureClass)
			}
			err = E.New("all smart probes failed; candidate penalties suppressed")
			return
		}
	}
	var summary probeSummary
	sweepComplete := make(chan struct{})
	go func() {
		defer close(sweepComplete)
		summary = <-summaryDone
		finishSweep(summary)
	}()
	// The caller (a panel HTTP request) gets the delays collected inside its
	// own window; the portrait sweep keeps running to completion on the
	// internal deadline so every performed dial lands in the health ledger.
	select {
	case <-sweepComplete:
		return result, err
	case <-ctx.Done():
	}
	resultMu.Lock()
	snapshot := make(map[string]uint16, len(result))
	for tag, delay := range result {
		snapshot[tag] = delay
	}
	resultMu.Unlock()
	return snapshot, nil
}

type smartUDPProbeFamilyResult struct {
	transport string
	elapsed   time.Duration
	err       error
	performed bool
}

type smartTCPProbeFamilyResult struct {
	transport string
	delay     uint16
	elapsed   time.Duration
	err       error
	performed bool
}

func (s *Smart) probeTCPFamilies(ctx context.Context, purpose smartProbePurpose, candidate adapter.Outbound, metadata smartCandidateMetadata) []smartTCPProbeFamilyResult {
	if s == nil || !s.familyProbeEnabled || ctx.Err() != nil || s.closing.Load() {
		return nil
	}
	identity := metadata.identity
	if identity == "" {
		identity = candidate.Tag()
	}
	dialIdentity := metadata.dialIdentity
	if dialIdentity == "" {
		dialIdentity = identity
	}
	probeTimeout := s.probeTimeout
	if probeTimeout <= 0 {
		probeTimeout = defaultSmartProbeTimeout
	}
	results := make([]smartTCPProbeFamilyResult, 0, 2)
	for _, family := range []struct {
		transport string
	}{
		{transport: "tcp/ipv4"},
		{transport: "tcp/ipv6"},
	} {
		key := nodeProfileKey(dialIdentity, s.probeProfileLink(family.transport), 0)
		startedAt := time.Now()
		var (
			delay     uint16
			err       error
			performed bool
		)
		if s.probeRegistry != nil {
			delay, err, performed = s.executeProbe(ctx, smartProbeRequest{
				purpose:     purpose,
				endpointKey: identity,
				profileKey:  key,
				timeout:     probeTimeout,
				ttl:         s.probeInterval,
			}, func(probeContext context.Context) (uint16, error) {
				performed = true
				return s.probeURLWithFallback(probeContext, candidate, smartTransportFamily(family.transport), false)
			})
		} else {
			performed = true
			testCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			delay, err = s.probeURLWithFallback(testCtx, candidate, smartTransportFamily(family.transport), false)
			cancel()
		}
		if err == nil && delay == 0 {
			delay = uint16(time.Since(startedAt) / time.Millisecond)
		}
		results = append(results, smartTCPProbeFamilyResult{transport: family.transport, delay: delay, elapsed: time.Since(startedAt), err: err, performed: performed})
	}
	return results
}

type smartUDPProbeResult struct {
	candidate    adapter.Outbound
	elapsed      time.Duration
	err          error
	performed    bool
	freshSuccess bool
	families     []smartUDPProbeFamilyResult
}

type smartUDPProbeTarget struct {
	transport   string
	destination M.Socksaddr
}

var smartUDPProbeTargets = [...]smartUDPProbeTarget{
	{transport: "udp/ipv4", destination: M.ParseSocksaddr("1.1.1.1:53")},
	{transport: "udp/ipv6", destination: M.ParseSocksaddr("[2606:4700:4700::1111]:53")},
}

func (s *Smart) probeUDPWithBudget(ctx context.Context, purpose smartProbePurpose, candidates []adapter.Outbound, budget int) {
	dashboardProbe := purpose.policy().advisory
	if ctx.Err() != nil || s.closing.Load() || len(candidates) == 0 {
		return
	}
	udpCandidates := make([]adapter.Outbound, 0, len(candidates))
	seenUDPProbeIDs := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if common.Contains(candidate.Network(), N.NetworkUDP) {
			probeID := s.candidateProbeIdentity(candidate.Tag())
			if _, exists := seenUDPProbeIDs[probeID]; exists {
				continue
			}
			seenUDPProbeIDs[probeID] = struct{}{}
			udpCandidates = append(udpCandidates, candidate)
		}
	}
	if len(udpCandidates) == 0 {
		return
	}
	if budget <= 0 || budget > defaultSmartUDPProbeTargetCount {
		budget = defaultSmartUDPProbeTargetCount
	}
	if budget > len(udpCandidates) {
		budget = len(udpCandidates)
	}
	// Use the independent rotating UDP scheduler rather than the catalog's
	// first-N order. Without this handoff, large groups repeatedly probe only
	// the first two provider lines and leave the rest permanently unknown.
	udpCandidates = s.selectUDPProbeCandidates(udpCandidates, budget)
	if len(udpCandidates) == 0 {
		return
	}
	results := make(chan smartUDPProbeResult, len(udpCandidates))
	jobs := make(chan adapter.Outbound)
	var waitGroup sync.WaitGroup
	// One UDP probe at a time is intentional: the test is a reachability gate,
	// not a throughput benchmark, and this keeps a cold five-region start from
	// creating a burst of NAT sessions.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for candidate := range jobs {
			probeCtx, cancel := context.WithTimeout(ctx, defaultSmartUDPProbeTimeout)
			startedAt := time.Now()
			performed := false
			var err error
			freshSuccess := false
			aggregateElapsed := time.Duration(0)
			aggregateSuccess := false
			families := make([]smartUDPProbeFamilyResult, 0, len(smartUDPProbeTargets))
			s.access.RLock()
			metadata := s.candidateMetadataByTag[candidate.Tag()]
			s.access.RUnlock()
			identity := metadata.identity
			if identity == "" {
				identity = candidate.Tag()
			}
			dialIdentity := metadata.dialIdentity
			if dialIdentity == "" {
				dialIdentity = identity
			}
			probeTimeout := s.probeTimeout
			if probeTimeout <= 0 {
				probeTimeout = defaultSmartUDPProbeTimeout
			}
			for _, target := range smartUDPProbeTargets {
				familyStarted := time.Now()
				familyPerformed := false
				var familyErr error
				key := nodeProfileKey(dialIdentity, "udp://dns-health\x00"+target.transport, 0)
				if s.probeRegistry != nil {
					_, familyErr, familyPerformed = s.executeProbe(probeCtx, smartProbeRequest{
						purpose:     purpose,
						endpointKey: identity,
						profileKey:  key,
						timeout:     probeTimeout,
						ttl:         s.probeInterval,
					}, func(probeContext context.Context) (uint16, error) {
						familyPerformed = true
						return 0, runSmartUDPHealthProbeTarget(probeContext, candidate, target.destination)
					})
				} else {
					familyPerformed = true
					familyErr = runSmartUDPHealthProbeTarget(probeCtx, candidate, target.destination)
				}
				familyElapsed := time.Since(familyStarted)
				families = append(families, smartUDPProbeFamilyResult{transport: target.transport, elapsed: familyElapsed, err: familyErr, performed: familyPerformed})
				if familyPerformed {
					performed = true
				}
				if familyErr == nil {
					aggregateSuccess = true
					if aggregateElapsed == 0 || familyElapsed < aggregateElapsed {
						aggregateElapsed = familyElapsed
					}
					if familyPerformed {
						freshSuccess = true
					}
				} else if err == nil {
					err = familyErr
				}
			}
			if aggregateSuccess {
				err = nil
			} else if !performed && err == nil {
				err = errSharedNodeProbeDeferred
			}
			cancel()
			if aggregateElapsed == 0 {
				aggregateElapsed = time.Since(startedAt)
			}
			results <- smartUDPProbeResult{candidate: candidate, elapsed: aggregateElapsed, err: err, performed: performed, freshSuccess: freshSuccess, families: families}
		}
	}()
dispatch:
	for _, candidate := range udpCandidates {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	waitGroup.Wait()
	close(results)

	networkKey := s.networkFingerprint()
	observedUDP := make(map[string]struct{}, len(udpCandidates)*3)
	for result := range results {
		if s.closing.Load() || ctx.Err() != nil {
			return
		}
		profileID := s.candidateProfileID(result.candidate.Tag())
		if result.performed {
			// Record attempts, not only successes. A failed candidate must leave
			// the current UDP window so the next cycle can cover another profile.
			s.noteUDPCandidateProbe(result.candidate.Tag(), time.Now())
		}
		for _, family := range result.families {
			observationKey := profileID + "\x00" + family.transport
			if _, exists := observedUDP[observationKey]; exists {
				continue
			}
			observedUDP[observationKey] = struct{}{}
			if family.err == nil && family.performed {
				s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "__udp_probe__", result.candidate.Tag(), family.transport, true, family.elapsed)
			} else if family.err != nil && family.performed {
				s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "__udp_probe__", result.candidate.Tag(), family.transport, false, family.elapsed)
			}
		}
		if result.err == nil && result.freshSuccess {
			// Keep an aggregate UDP ledger for domain destinations that have not
			// selected a concrete address family yet.
			observationKey := profileID + "\x00" + N.NetworkUDP
			if _, exists := observedUDP[observationKey]; !exists {
				observedUDP[observationKey] = struct{}{}
				s.observeProbeResult(dashboardProbe, time.Now(), networkKey, "__udp_probe__", result.candidate.Tag(), N.NetworkUDP, true, result.elapsed)
			}
		}
	}
}

func runSmartUDPHealthProbe(ctx context.Context, candidate adapter.Outbound) error {
	for _, target := range smartUDPProbeTargets {
		if err := runSmartUDPHealthProbeTarget(ctx, candidate, target.destination); err == nil {
			return nil
		}
	}
	return errors.New("smart UDP DNS health probe failed")
}

func runSmartUDPHealthProbeForTransport(ctx context.Context, candidate adapter.Outbound, transport string) error {
	if family := smartTransportFamily(transport); family != "" {
		for _, target := range smartUDPProbeTargets {
			if target.transport == transport {
				return runSmartUDPHealthProbeTarget(ctx, candidate, target.destination)
			}
		}
	}
	return runSmartUDPHealthProbe(ctx, candidate)
}

func runSmartUDPHealthProbeTarget(ctx context.Context, candidate adapter.Outbound, target M.Socksaddr) error {
	query, id, question, err := buildSmartDNSHealthQuery()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	packetConn, err := candidate.ListenPacket(ctx, target)
	if err != nil {
		return err
	}
	defer packetConn.Close()
	deadline := time.Now().Add(defaultSmartUDPProbeTimeout)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = packetConn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = packetConn.WriteTo(query, target.UDPAddr()); err != nil {
		return err
	}
	response := make([]byte, 2048)
	count, _, err := packetConn.ReadFrom(response)
	if err != nil {
		return err
	}
	return validateSmartDNSHealthResponse(response[:count], id, question)
}

func buildSmartDNSHealthQuery() ([]byte, uint16, dnsmessage.Question, error) {
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	id := binary.BigEndian.Uint16(randomID[:])
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err = builder.StartQuestions(); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	if err = builder.Question(question); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	message, err := builder.Finish()
	return message, id, question, err
}

func validateSmartDNSHealthResponse(message []byte, id uint16, expected dnsmessage.Question) error {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return err
	}
	if !header.Response || header.ID != id || header.RCode != dnsmessage.RCodeSuccess {
		return errors.New("unexpected smart UDP DNS response")
	}
	question, err := parser.Question()
	if err != nil {
		return err
	}
	if question != expected {
		return errors.New("smart UDP DNS response question mismatch")
	}
	return nil
}

func (s *Smart) rank(ctx context.Context, transport string, destination M.Socksaddr) ([]smartRank, string, string, string) {
	ranking, networkKey, siteKey, siteDisplay := s.rankPooled(ctx, transport, destination)
	ranks := append([]smartRank(nil), ranking.ranks...)
	ranking.Release()
	return ranks, networkKey, siteKey, siteDisplay
}

// observeDial is the single observation fan-out.  The Go EndpointProfile is
// still the source of truth for API/status consumers; when the Zig backend is
// enabled it receives the same event keyed by canonical endpoint identity.
func (s *Smart) observeDial(now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	profileID := s.candidateProfileID(candidate)
	s.store.observeDial(now, network, site, profileID, transport, success, elapsed)
	// The backend observes the canonical endpoint identity. Metadata is read
	// under the catalog lock so provider refresh cannot race this callback.
	s.access.RLock()
	metadata := s.candidateMetadataByTag[candidate]
	s.access.RUnlock()
	if metadata.policyID == 0 {
		// Embedded callers can construct a Smart snapshot without running the
		// provider refresh path. Keep those observations on the same stable tag
		// identity used by rankPooled instead of silently dropping them.
		metadata = s.buildCandidateMetadata(candidate, "")
	}
	if metadata.policyID != 0 {
		s.observePolicyBackend(smartBusinessSelectionKey(network, site, transport), metadata.policyID, success, elapsed, now)
	}
}

// observeProbeResult keeps every active measurement advisory. Scheduled and
// dashboard URL tests contribute latency/success counters, but cannot alter
// breaker state or feed the Zig policy owner. In particular, neither a panel
// ping nor a shared probe-target incident may evict a serving primary.
func (s *Smart) observeProbeResult(_ bool, now time.Time, network, site, candidate, transport string, success bool, elapsed time.Duration) {
	// Active URL tests are baseline/ranking evidence, never breaker evidence.
	// A shared target, local uplink or DNS incident can make many otherwise
	// usable nodes fail together. Promoting those samples into observeDial used
	// to open the real data-plane breaker and caused rapid node_dead switches.
	// Surge keeps failed tests in a lower candidate tier; only actual traffic or
	// protocol/handshake failures may evict the serving primary.
	profileID := s.candidateProfileID(candidate)
	s.store.observeDialAdvisory(now, network, site, profileID, transport, success, elapsed)
}

// observeDataPlaneFailure records a real connection or established-flow
// failure in the affected site's transport portrait. A successful fallback
// becomes its new incumbent; an isolated timeout remains a site-local stain.
// Probe failures intentionally do not use this path.
func (s *Smart) observeDataPlaneFailure(now time.Time, network, site, candidate, transport string, elapsed time.Duration) {
	s.observeDataPlaneFailureWithType(now, network, site, candidate, transport, elapsed, "transport")
}

func (s *Smart) observeDataPlaneFailureWithType(now time.Time, network, site, candidate, transport string, elapsed time.Duration, failureType string) {
	profileID := s.candidateProfileID(candidate)
	// Site-local failures belong to the Go evidence ledger first. Feeding every
	// timeout directly into the Zig context made one website failure look like
	// a group-wide endpoint failure and replaced the primary immediately.
	s.store.observeDial(now, network, site, profileID, transport, false, elapsed)
	nodeFailure := failureType == "protocol" || failureType == "hard_transport"
	if nodeFailure {
		// The shared registry also feeds URLTest and LoadBalance. A site-local
		// timeout must not quarantine this credential for unrelated services.
		s.recordSharedDataPlaneEvidence(candidate, transport, false)
	}
	if s.store != nil && nodeFailure {
		s.store.openEndpointCircuit(now, network, profileID, transport)
	}
	if s.store != nil && s.store.endpointDead(network, profileID, transport, now) {
		s.access.RLock()
		metadata := s.candidateMetadataByTag[candidate]
		s.access.RUnlock()
		if metadata.policyID == 0 {
			metadata = s.buildCandidateMetadata(candidate, "")
		}
		if metadata.policyID != 0 {
			s.observePolicyBackend(smartBusinessSelectionKey(network, site, transport), metadata.policyID, false, elapsed, now)
		}
	}
	s.noteFailureType(smartStatusSelectionKey(network, site, transport), failureType)
}

// recordSharedDataPlaneEvidence publishes only transport reachability to the
// process-wide base profile. Smart keeps site scoring and breaker semantics in
// its policy store, while URLTest and LoadBalance can immediately avoid a
// credential that real Smart traffic just proved unusable. TCP and UDP use
// independent keys so one transport can never poison the other.
func (s *Smart) recordSharedDataPlaneEvidence(tag, transport string, success bool) {
	if s == nil || s.probeRegistry == nil {
		return
	}
	s.access.RLock()
	candidate := s.candidateByTag[tag]
	s.access.RUnlock()
	if candidate == nil {
		return
	}
	key := groupTCPPassiveProfileKey(candidate, transport)
	if smartTransportBase(transport) == N.NetworkUDP {
		key = groupUDPProfileKey(candidate)
	}
	s.probeRegistry.recordPassive(key, success, 0, groupPassiveFailureTTL)
}

func (s *Smart) observeDataPlaneFailureForTransport(now time.Time, network, site, candidate, aggregateTransport, observedTransport string, elapsed time.Duration) {
	s.observeDataPlaneFailure(now, network, site, candidate, aggregateTransport, elapsed)
	if observedTransport != "" && observedTransport != aggregateTransport {
		s.observeDataPlaneFailure(now, network, site, candidate, observedTransport, elapsed)
	}
}

func (s *Smart) observeDialForTransport(now time.Time, network, site, candidate, aggregateTransport, observedTransport string, success bool, elapsed time.Duration) {
	s.observeDial(now, network, site, candidate, aggregateTransport, success, elapsed)
	if observedTransport != "" && observedTransport != aggregateTransport {
		s.observeDial(now, network, site, candidate, observedTransport, success, elapsed)
	}
}

func (s *Smart) observeMetricForTransport(network, site, candidate, aggregateTransport, observedTransport string, observe func(string)) {
	observe(aggregateTransport)
	if observedTransport != "" && observedTransport != aggregateTransport {
		observe(observedTransport)
	}
}

// candidateProfileID maps provider display tags to the credential-aware dial
// profile. Subscription aliases with the same credential share one portrait;
// accounts on the same path stay isolated for authentication/data-plane
// failures. A tag is retained as the fallback for embedded/test candidates.
func (s *Smart) candidateProfileID(candidate string) string {
	if s == nil || candidate == "" {
		return candidate
	}
	s.access.RLock()
	metadata := s.candidateMetadataByTag[candidate]
	s.access.RUnlock()
	if metadata.profileID == "" {
		return candidate
	}
	return metadata.profileID
}

func (s *Smart) resolveSmartSelectionRecord(record adapter.SelectedRecord) string {
	if s == nil {
		return ""
	}
	s.access.RLock()
	selected := resolveSelectionRecord(s.candidates, record)
	s.access.RUnlock()
	if selected == nil {
		return ""
	}
	return selected.Tag()
}

func (s *Smart) smartSelectionRecord(tag string) adapter.SelectedRecord {
	record := adapter.SelectedRecord{Version: 1, DisplayTag: tag}
	s.access.RLock()
	metadata := s.candidateMetadataByTag[tag]
	s.access.RUnlock()
	record.EndpointIdentity = metadata.identity
	record.DialIdentity = metadata.dialIdentity
	return record
}

// candidateProbeIdentity is the credential-free path key used by the bounded
// TCP/UDP probe schedulers. Probes answer a network-path question, so aliases
// with different credentials must consume one probe slot and one probe
// timestamp. Data-plane observations and breaker state use candidateProfileID
// instead, which is credential-aware.
func (s *Smart) candidateProbeIdentity(candidate string) string {
	if s == nil || candidate == "" {
		return candidate
	}
	s.access.RLock()
	metadata := s.candidateMetadataByTag[candidate]
	s.access.RUnlock()
	if metadata.identity != "" {
		return metadata.identity
	}
	return candidate
}

func (s *Smart) rankPooled(ctx context.Context, transport string, destination M.Socksaddr) (*smartRanking, string, string, string) {
	now := time.Now()
	baseTransport := smartTransportBase(transport)
	pinned, temporary, _, _ := s.controlSnapshot(now)
	networkKey := s.networkFingerprint()
	siteDisplay, siteKey := s.resolveSmartSiteIdentity(adapter.ContextFrom(ctx), destination)
	s.access.RLock()
	ranking := acquireSmartRanking(len(s.candidates))
	ranking.candidates = append(ranking.candidates, s.candidates...)
	metadataByTag := s.candidateMetadataByTag
	selectionKey := smartBusinessSelectionKey(networkKey, siteKey, transport)
	statusKey := smartStatusSelectionKey(networkKey, siteDisplay, transport)
	snapshotSelectedAt := s.lastSelectedAt[selectionKey]
	lastSelected := s.lastSelected[selectionKey]
	// Keep the exact incumbent generation used for this ranking. Dial attempts
	// may complete out of order; markSelected uses this snapshot to reject a
	// late healthy result that would otherwise overwrite a newer choice.
	ranking.snapshotSelected = lastSelected
	ranking.snapshotSelectedAt = snapshotSelectedAt
	ranking.statusKey = statusKey
	ranking.snapshotGeneration = s.selectionGeneration[statusKey]
	ranking.snapshotValid = true
	affinity := s.affinity[smartBusinessSelectionKey(networkKey, siteKey, transport)]
	s.access.RUnlock()

	var policyCandidates []smartPolicyCandidate
	var policyIDs map[uint64]struct{}
	usePolicyBackend := s.policyBackendEnabled()
	if usePolicyBackend {
		policyCandidates = make([]smartPolicyCandidate, 0, len(ranking.candidates))
		policyIDs = make(map[uint64]struct{}, len(ranking.candidates))
	}
	profile := smartProfileInteractive
	if baseTransport == N.NetworkUDP {
		profile = smartProfileUDP
	}
	for _, candidate := range ranking.candidates {
		if !common.Contains(candidate.Network(), baseTransport) {
			continue
		}
		metadata, ok := metadataByTag[candidate.Tag()]
		if !ok {
			metadata = s.buildCandidateMetadata(candidate.Tag(), "")
		}
		estimate := s.store.estimate(now, networkKey, siteKey, metadata.profileID, transport, s.minSamples)
		siteTainted := s.store.siteFailedRecently(now, networkKey, siteKey, metadata.profileID, transport, defaultSmartSiteFailureTTL)
		siteSuccesses, siteDelayMS := s.store.siteSuccessSnapshot(now, networkKey, siteKey, metadata.profileID, transport, defaultSmartSiteFailureTTL)
		if siteTainted && estimate.State != "open" && estimate.State != "half_open" {
			// Surge moves a policy that failed for this registered domain from
			// tier A to tier B for one hour. It remains a valid endpoint for other
			// businesses and one successful connection clears the stain.
			estimate.State = "suspect"
		}
		scoreEstimate := estimate
		// Keep the richer health portrait for diagnostics and hard safety gates,
		// but feed Surge's selector its exact 20-slot/300-second first-response
		// and loss histories.
		scoreEstimate.FirstByteMS, scoreEstimate.RetransmitRatio = s.store.surgeScoreSnapshot(networkKey, metadata.profileID, transport)
		activeProbeDegraded := false
		if s.probeRegistry != nil {
			if baseTransport == N.NetworkTCP && common.Contains(candidate.Network(), N.NetworkTCP) {
				probeKey := metadata.probeKey
				if family := smartTransportFamily(transport); family != "" {
					probeKey = nodeProfileKey(metadata.dialIdentity, s.probeProfileLink(transport), 0)
				}
				activeProbeDegraded = s.probeRegistry.dead(probeKey)
			}
		}
		if activeProbeDegraded && candidate.Tag() != lastSelected {
			// Keep the candidate eligible. Repeated active-test failures remain a
			// soft score signal for backups. A serving primary is never displaced
			// by probe evidence alone; its next real flow will either confirm it or
			// produce the data-plane failure that authorizes failover.
			scoreEstimate.Reliability *= 0.5
			scoreEstimate.ConnectMS += 500
			scoreEstimate.ConnectP95MS += 500
		}
		profileThroughputSamples := estimate.ThroughputSamples
		if siteKey != "" {
			profileThroughputSamples = estimate.LocalThroughputSamples
		}
		if profile == smartProfileInteractive && profileThroughputSamples >= 2 {
			profile = smartProfileBulk
		}
		ranking.ranks = append(ranking.ranks, smartRank{
			outbound:            candidate,
			identity:            metadata.identity,
			dialIdentity:        metadata.dialIdentity,
			probeKey:            metadata.probeKey,
			policyID:            metadata.policyID,
			selectionGeneration: ranking.snapshotGeneration,
			weight:              metadata.weight,
			estimate:            estimate,
			scoreEstimate:       scoreEstimate,
			activeProbeDegraded: activeProbeDegraded,
			standbyOnly:         metadata.standbyOnly,
			incumbent:           candidate.Tag() == lastSelected,
			siteTainted:         siteTainted,
			siteSuccesses:       siteSuccesses,
			siteDelayMS:         siteDelayMS,
			// Hard health gates run before weights and soft score. A circuit-open
			// endpoint must never become eligible merely because it has a large
			// configured weight.
			eligible: estimate.State != "open",
			status: adapter.SmartCandidateStatus{
				Tag:             candidate.Tag(),
				StandbyOnly:     metadata.standbyOnly,
				EndpointID:      smartEndpointID(metadata.identity, metadata.policyID),
				State:           estimate.State,
				Reliability:     estimate.Reliability,
				ConnectMS:       estimate.ConnectMS,
				ConnectP95MS:    estimate.ConnectP95MS,
				FirstByteMS:     estimate.FirstByteMS,
				FirstByteP95MS:  estimate.FirstByteP95MS,
				ThroughputBPS:   estimate.ThroughputBPS,
				RetransmitRatio: estimate.RetransmitRatio,
				Samples:         estimate.Samples,
			},
		})
	}
	// Record the passive bulk signal only after the traffic profile is known.
	// Throughput is deliberately a soft ranking signal: it must never make a
	// reachable endpoint ineligible, otherwise a slow/short-lived sample can
	// strand the entire group and prevent recovery traffic from ever arriving.
	if profile == smartProfileBulk {
		for index := range ranking.ranks {
			if !passiveThroughputBelowFloor(ranking.ranks[index].estimate, s.passiveThroughputFloorBPS, s.passiveThroughputSamples) {
				continue
			}
			ranking.ranks[index].passiveThroughputLow = true
			ranking.ranks[index].status.Reason = "passive throughput below advisory floor"
		}
	}
	for index := range ranking.ranks {
		weightMatch := ranking.ranks[index].weight
		weight := weightMatch.Weight
		ranking.ranks[index].profile = profile
		ranking.ranks[index].status.Score = smartSurgeScore(ranking.ranks[index].scoreEstimate) / weight
		ranking.ranks[index].status.Weight = weight
		ranking.ranks[index].status.WeightRule = weightMatch.Rule
		ranking.ranks[index].status.WeightExact = weightMatch.Exact
		if !ranking.ranks[index].passiveThroughputLow {
			ranking.ranks[index].status.Reason = smartEstimateReason(ranking.ranks[index].estimate)
		}
		if ranking.ranks[index].activeProbeDegraded {
			ranking.ranks[index].status.Reason = "active probe degraded; serving eligibility retained"
		}
		if ranking.ranks[index].siteTainted {
			ranking.ranks[index].status.Reason = "site failure stain; downgraded for this business"
		}
		ranking.ranks[index].estimate = smartEstimate{}
		ranking.ranks[index].scoreEstimate = smartEstimate{}
	}
	s.applySurgeOrdering(ranking.ranks, selectionKey, lastSelected, now)
	ranks := ranking.ranks
	if usePolicyBackend {
		policyCandidates = policyCandidates[:0]
		clear(policyIDs)
		for index := range ranks {
			rank := &ranks[index]
			if rank.policyID == 0 {
				continue
			}
			if _, exists := policyIDs[rank.policyID]; exists {
				continue
			}
			policyIDs[rank.policyID] = struct{}{}
			policyCandidates = append(policyCandidates, smartPolicyCandidate{
				ID: rank.policyID, Reliability: rank.status.Reliability, ConnectMS: rank.status.ConnectMS,
				FirstByteMS: rank.status.FirstByteMS, Throughput: rank.status.ThroughputBPS,
				Samples: rank.status.Samples, Weight: rank.status.Weight, CandidateOrder: float64(index + 1),
				State: smartPolicyState(rank.status.State), Eligible: rank.eligible,
			})
		}
	}
	manualPinUnavailable := false
	statusReason := func(reason string) string {
		if manualPinUnavailable {
			return "manual pin unavailable; automatic fallback: " + reason
		}
		return reason
	}
	if len(ranks) == 0 {
		return ranking, networkKey, siteKey, siteDisplay
	}
	// A dashboard delay request is observational only.  It may refresh the
	// latency portrait, but it must not run the selection state machine: doing
	// so would let a single panel ping replace a healthy incumbent or release a
	// manual pin while real traffic is still using it.  Keep the incumbent at
	// the head of the returned snapshot without recording a new Zig selection,
	// switch challenge, cooldown, or pin release.
	if isSmartDashboardProbe(ctx) {
		incumbent := pinned
		if incumbent == "" {
			incumbent = lastSelected
		}
		if index := smartRankIndex(ranks, incumbent); index >= 0 {
			ranks[index].status.Reason = "dashboard probe; incumbent retained"
			moveSmartRankFirst(ranks, index)
		}
		// Delay requests have their own response/history channel. Publishing this
		// observational snapshot as the latest Smart status would steal the legacy
		// dashboard's top-level context and make an unchanged incumbent look as if
		// it switched when the user merely opened the panel.
		return ranking, networkKey, siteKey, siteDisplay
	}
	if smartPolicyBackendRequired() && !usePolicyBackend {
		for index := range ranks {
			ranks[index].eligible = false
			ranks[index].status.State = "open"
			ranks[index].status.Reason = "zig policy unavailable"
		}
		ranking.policyUnavailable = true
		s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy unavailable")
		return ranking, networkKey, siteKey, siteDisplay
	}
	if ranks[0].status.State == "open" {
		s.updateStatus(networkKey, siteDisplay, transport, ranks, "no eligible candidates; circuits open")
		return ranking, networkKey, siteKey, siteDisplay
	}
	if temporary != "" {
		if index := smartRankIndex(ranks, temporary); index >= 0 && ranks[index].status.State != "open" {
			ranks[index].eligible = true
			ranks[index].standbyOnly = false
			ranks[index].status.StandbyOnly = false
			ranks[index].status.Reason = "temporary manual override"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "temporary manual override")
			return ranking, networkKey, siteKey, siteDisplay
		}
		s.ClearTemporarySelection()
	}
	if pinned != "" {
		if index := smartRankIndex(ranks, pinned); index >= 0 && ranks[index].status.State != "open" && ranks[index].status.State != "half_open" {
			// A permanent manual selection is authoritative while its circuit is
			// usable. RTT and score changes must never silently overrule a human.
			ranks[index].eligible = true
			ranks[index].standbyOnly = false
			ranks[index].status.StandbyOnly = false
			ranks[index].status.Reason = "manual pin"
			moveSmartRankFirst(ranks, index)
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "manual pin")
			return ranking, networkKey, siteKey, siteDisplay
		} else {
			manualPinUnavailable = true
			s.releaseConfirmedBrokenPin(pinned, "candidate circuit opened")
		}
	}
	if !hasEligibleSmartRank(ranks) {
		s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("no service-reachable candidates"))
		return ranking, networkKey, siteKey, siteDisplay
	}
	if !usePolicyBackend {
		// Development builds use the exact host-computed candidate order. Production
		// Zig receives the same order through CandidateOrder below; neither path adds
		// the retired primary/challenge/cooldown state machine.
		// Fixed mode keeps the healthy incumbent: spread bands leave ties to a
		// per-request seed, and a fixed primary must not migrate on that seed
		// (mirrors incumbent retention inside policy.zig).
		if s.selectionMode == smartSelectionFixed {
			current := lastSelected
			if current == "" {
				if affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
					current = affinity.Candidate
				}
			}
			if index := smartRankIndex(ranks, current); index >= 0 && ranks[index].status.State != "open" {
				// Preserve the equivalent-line reason: a provider alias of the
				// same canonical endpoint is not a switch at all.
				reason := "fixed primary retained"
				if smartSameEndpoint(metadataByTag, current, ranks[0].outbound.Tag()) {
					reason = ranks[index].status.Reason
					if reason == "" {
						reason = "equivalent subscription line retained"
					}
				}
				ranks[index].status.Reason = reason
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, reason)
				return ranking, networkKey, siteKey, siteDisplay
			}
		}
		if ranks[0].status.Reason == "" {
			ranks[0].status.Reason = "spread candidate order"
		}
		s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("spread candidate order"))
		return ranking, networkKey, siteKey, siteDisplay
	}
	if usePolicyBackend {
		policyIncumbent := lastSelected
		if policyIncumbent == "" && affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
			policyIncumbent = affinity.Candidate
		}
		// A policy context can be evicted and recreated to keep memory bounded.
		// Seed only an empty Zig context from this subservice's confirmed
		// incumbent or its parent business affinity. Zig still owns an independent
		// context afterwards, so failures and confirmation state never cross from
		// one subservice into another.
		if currentIndex := smartRankIndex(ranks, policyIncumbent); currentIndex >= 0 {
			policyID := ranks[currentIndex].policyID
			if policyID != 0 {
				s.adoptPolicyBackendSelected(selectionKey, policyID, now)
			}
		}
		decision, backendAvailable := s.choosePolicyBackend(selectionKey, policyCandidates, profile, now)
		if !backendAvailable {
			// Close can retire the backend while a ranking snapshot is still being
			// assembled. In a Zig-only release this is a closed state, never an
			// invitation to re-enter the duplicate Go policy state machine.
			if smartPolicyBackendRequired() {
				for index := range ranks {
					ranks[index].eligible = false
					ranks[index].status.State = "open"
					ranks[index].status.Reason = "zig policy unavailable"
				}
				ranking.policyUnavailable = true
				s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy unavailable")
				return ranking, networkKey, siteKey, siteDisplay
			}
			usePolicyBackend = false
		} else {
			if decision.SelectedID != 0 {
				// Keep the currently selected provider alias when the Zig
				// decision points at the same canonical endpoint. Providers
				// commonly expose one endpoint more than once with generated
				// suffixes; selecting the first alias on every rank would make
				// the visible tag (and the dial target) oscillate on refresh.
				selectedIndex := smartRankIndexForPolicy(ranks, decision.SelectedID, policyIncumbent)
				equivalentRetained := false
				if selectedIndex >= 0 {
					currentIndex := smartRankIndex(ranks, policyIncumbent)
					if currentIndex >= 0 && currentIndex == selectedIndex {
						for index := range ranks {
							if index != currentIndex && smartSameEndpoint(metadataByTag, ranks[currentIndex].outbound.Tag(), ranks[index].outbound.Tag()) {
								equivalentRetained = true
								break
							}
						}
					}
					if currentIndex >= 0 && !smartPolicyBackendRequired() && !s.performanceSwitchAllowed() && currentIndex != selectedIndex {
						ranks[currentIndex].status.Reason = "baseline retained current candidate"
						moveSmartRankFirst(ranks, currentIndex)
						s.updateStatus(networkKey, siteDisplay, transport, ranks, "baseline retained current candidate")
						return ranking, networkKey, siteKey, siteDisplay
					}
					if currentIndex >= 0 && currentIndex != selectedIndex && ranks[currentIndex].status.State != "open" && !decision.Switched {
						// A policy engine can be recreated after a context eviction or
						// provider refresh. Its first decision is then a cold estimate,
						// not a confirmed failover. Keep a healthy incumbent until the
						// backend's confirmation FSM reports Switched, while still
						// allowing hard-open candidates to fail over immediately.
						ranks[currentIndex].status.Reason = "zig policy awaiting sustained confirmation"
						moveSmartRankFirst(ranks, currentIndex)
						s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy awaiting sustained confirmation")
						return ranking, networkKey, siteKey, siteDisplay
					}
					if currentIndex >= 0 && !smartPolicyBackendRequired() && currentIndex != selectedIndex &&
						!smartAbsoluteImprovement(ranks[selectedIndex], ranks[currentIndex], s.switchMinImprovement) {
						// The Zig kernel already applies relative margin, confirmation,
						// and cooldown. This additional absolute floor prevents a tiny
						// score change from moving a healthy browser path when the p95
						// latency gain is below the user-visible threshold.
						ranks[currentIndex].status.Reason = "healthy current candidate retained below latency floor"
						moveSmartRankFirst(ranks, currentIndex)
						s.updateStatus(networkKey, siteDisplay, transport, ranks, "healthy current candidate retained below latency floor")
						return ranking, networkKey, siteKey, siteDisplay
					}
				}
				if selectedIndex >= 0 {
					ranking.policySelectedEndpointID = ranks[selectedIndex].status.EndpointID
					if ranking.policySelectedEndpointID == "" {
						ranking.policySelectedEndpointID = smartEndpointID(ranks[selectedIndex].identity, ranks[selectedIndex].policyID)
					}
					generation := s.recordZigSelectedEndpoint(ranking.statusKey, ranking.policySelectedEndpointID)
					if generation != 0 {
						for index := range ranks {
							ranks[index].selectionGeneration = generation
						}
					}
					reason := "zig policy retained candidate"
					if decision.Switched {
						reason = "zig policy confirmed candidate"
					} else if equivalentRetained {
						reason = "equivalent subscription line retained"
					}
					ranks[selectedIndex].status.Reason = reason
					moveSmartRankFirst(ranks, selectedIndex)
					s.updateStatus(networkKey, siteDisplay, transport, ranks, reason)
					return ranking, networkKey, siteKey, siteDisplay
				}
			}
			// A corrupt/unsupported backend decision must fail safe to the best
			// host-ranked candidate, without re-entering the Go confirmation FSM.
			// Zig-only release builds instead fail closed: accepting a Go decision
			// here would reintroduce a second policy owner after an ABI/runtime
			// failure and make production behavior non-deterministic.
			if smartPolicyBackendRequired() {
				for index := range ranks {
					ranks[index].eligible = false
					ranks[index].status.State = "open"
					ranks[index].status.Reason = "zig policy unavailable"
				}
				s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy unavailable")
				return ranking, networkKey, siteKey, siteDisplay
			}
			s.updateStatus(networkKey, siteDisplay, transport, ranks, "zig policy fallback to host ranking")
			return ranking, networkKey, siteKey, siteDisplay
		}
	}
	bestScore := ranks[0].status.Score
	current := lastSelected
	if affinity.Candidate != "" && affinity.ExpiresAt.After(now) {
		current = affinity.Candidate
	}
	if current != "" {
		if index := smartRankIndex(ranks, current); index >= 0 && ranks[index].status.State != "open" {
			currentScore := ranks[index].status.Score
			// Fixed mode: dispersion bands intentionally leave ties to a
			// per-request seed. A fixed primary must not
			// migrate on that seed, and the first-response history that feeds
			// surge scores is often empty right after a cold start — the old
			// score-comparison FSM here degenerated to random, so pin the
			// healthy incumbent unless the confirmed challenge completes.
			if s.selectionMode == smartSelectionFixed {
				ranks[index].status.Reason = "fixed primary retained"
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, "fixed primary retained")
				return ranking, networkKey, siteKey, siteDisplay
			}
			if !s.performanceSwitchAllowed() {
				s.clearSwitchChallenge(selectionKey)
				ranks[index].status.Reason = "baseline retained current candidate"
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, "baseline retained current candidate")
				return ranking, networkKey, siteKey, siteDisplay
			}
			bestCandidate := ranks[0].outbound.Tag()
			switchConfirmed := false
			switchReason := "current candidate within switch margin"
			switchStatusReason := "switch margin retained current candidate"
			switch {
			case current == bestCandidate:
				s.clearSwitchChallenge(selectionKey)
			case smartSameEndpoint(metadataByTag, current, bestCandidate):
				s.clearSwitchChallenge(selectionKey)
				switchReason = "equivalent subscription line retained"
				switchStatusReason = "healthy equivalent line retained"
			case !smartRelativeImprovement(bestScore, currentScore, s.switchMargin) ||
				!smartAbsoluteImprovement(ranks[0], ranks[index], s.switchMinImprovement):
				s.clearSwitchChallenge(selectionKey)
			case s.performanceSwitchCoolingDown(selectionKey, now):
				s.clearSwitchChallenge(selectionKey)
				switchReason = "better candidate retained during switch cooldown"
				switchStatusReason = "healthy current candidate retained during switch cooldown"
			case s.confirmSwitchChallenge(selectionKey, bestCandidate, now):
				switchConfirmed = true
			default:
				switchReason = "better candidate awaiting sustained confirmation"
				switchStatusReason = "healthy current candidate retained during switch confirmation"
			}
			if !switchConfirmed {
				ranks[index].status.Reason = switchReason
				moveSmartRankFirst(ranks, index)
				s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason(switchStatusReason))
				return ranking, networkKey, siteKey, siteDisplay
			}
		}
	}
	ranks[0].status.Reason = "lowest confidence-adjusted score"
	s.updateStatus(networkKey, siteDisplay, transport, ranks, statusReason("lowest confidence-adjusted score"))
	return ranking, networkKey, siteKey, siteDisplay
}

func (s *Smart) markSelected(candidate adapter.Outbound, networkKey, siteKey, siteDisplay, transport string, ranks []smartRank, attemptIndex int, hadPriorFailure bool) {
	s.markSelectedWithSnapshot(candidate, networkKey, siteKey, siteDisplay, transport, "", time.Time{}, false, ranks, attemptIndex, hadPriorFailure)
}

func (s *Smart) markSelectedWithSnapshot(candidate adapter.Outbound, networkKey, siteKey, siteDisplay, transport string, snapshotSelected string, snapshotSelectedAt time.Time, snapshotValid bool, ranks []smartRank, attemptIndex int, hadPriorFailure bool) bool {
	now := time.Now()
	key := smartBusinessSelectionKey(networkKey, siteKey, transport)
	statusKey := smartStatusSelectionKey(networkKey, siteDisplay, transport)
	usePolicyBackend := s.policyBackendEnabled()
	// A concurrent Close may retire the Zig engine after rankPooled returned a
	// candidate but before its dial completed. Do not let this late completion
	// update host-owned Go switch/cooldown state in a Zig-only release; the
	// ranking is already invalid and the next request will fail closed.
	if smartPolicyBackendRequired() && !usePolicyBackend {
		return false
	}
	s.access.Lock()
	s.pruneAffinityLocked(now)
	s.pruneContextStateLocked(now)
	previous := s.lastSelected[key]
	currentSelectedAt := s.lastSelectedAt[key]
	// Compare canonical endpoint identity before accounting for a switch. A
	// provider refresh can replace one display alias with another while the
	// underlying server is unchanged; that is not a performance or failure
	// failover and must not interrupt healthy connections.
	sameEndpoint := smartSameEndpoint(s.candidateMetadataByTag, previous, candidate.Tag())
	logicalSwitch := previous != "" && previous != candidate.Tag() && !sameEndpoint
	previousMetadata := s.candidateMetadataByTag[previous]
	currentMetadata := s.candidateMetadataByTag[candidate.Tag()]
	previousEndpointID := smartEndpointID(previousMetadata.identity, previousMetadata.policyID)
	currentEndpointID := smartEndpointID(currentMetadata.identity, currentMetadata.policyID)
	previousRank, _ := smartRankByTag(ranks, previous)
	currentRank, currentFound := smartRankByTag(ranks, candidate.Tag())
	previousProfileID := previousMetadata.profileID
	if previousProfileID == "" {
		previousProfileID = previous
	}
	// Surge may place a policy in C/the ineligible tail because an active test,
	// throughput hint, or site-local record is poor. That affects this request's
	// ordering only; it is not proof that the endpoint is globally dead and must
	// never trigger connection interruption. Only the authoritative hard-failure
	// circuit (protocol/authentication/unreachable evidence) may retire existing
	// flows and count as an operational failover.
	failureSwitch := s.store.endpointDead(networkKey, previousProfileID, transport, now)
	currentGeneration := s.selectionGeneration[statusKey]
	if s.selectionGeneration == nil {
		s.selectionGeneration = make(map[string]uint64)
		currentGeneration = 0
	}
	currentGeneration = s.selectionGeneration[statusKey]
	if currentGeneration == 0 {
		currentGeneration = 1
	}
	dialGeneration := uint64(0)
	if currentFound {
		dialGeneration = currentRank.selectionGeneration
	}
	// A ranking is a point-in-time view. If another request committed a newer
	// incumbent while this dial was in flight, a healthy late result must not
	// roll the decision back. Failure-driven failover remains allowed because
	// preserving a broken incumbent would strand the request.
	staleSnapshot := snapshotValid &&
		(previous != snapshotSelected || !currentSelectedAt.Equal(snapshotSelectedAt))
	staleGeneration := dialGeneration != 0 && dialGeneration != currentGeneration
	if (staleSnapshot || staleGeneration) && logicalSwitch && !failureSwitch {
		s.access.Unlock()
		s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, previous, "stale healthy result retained current candidate")
		return false
	}
	s.lastSelected[key] = candidate.Tag()
	if s.lastSelectedAt == nil {
		s.lastSelectedAt = make(map[string]time.Time)
	}
	s.lastSelectedAt[key] = now
	if logicalSwitch && s.zigSelectedEndpoint[statusKey] != currentEndpointID {
		currentGeneration++
	}
	if s.zigSelectedEndpoint == nil {
		s.zigSelectedEndpoint = make(map[string]string)
	}
	// A failure-driven retry is a new authoritative selection. Keep the Zig
	// proof state aligned before recording the successful data-plane dial; the
	// old ordering reported every legitimate fallback as a mismatch.
	s.zigSelectedEndpoint[statusKey] = currentEndpointID
	s.selectionGeneration[statusKey] = currentGeneration
	delete(s.switchChallenges, key)
	if !usePolicyBackend && logicalSwitch && !failureSwitch {
		if s.performanceCooldown == nil {
			s.performanceCooldown = make(map[string]time.Time)
		}
		s.performanceCooldown[key] = now.Add(s.switchCooldown)
	}
	if siteKey != "" {
		s.affinity[smartBusinessSelectionKey(networkKey, siteKey, transport)] = smartAffinity{Candidate: candidate.Tag(), ExpiresAt: now.Add(s.siteStickiness)}
	}
	ready := 0
	minimum := max(1, s.minSamples)
	for _, rank := range ranks {
		if rank.status.Samples >= float64(minimum) {
			ready++
		}
	}
	s.access.Unlock()
	if usePolicyBackend {
		policyID := currentMetadata.policyID
		if policyID == 0 {
			policyID = smartPolicyID(smartLineFamily(candidate.Tag()))
		}
		s.setPolicyBackendSelected(key, policyID, now)
	}
	// Surge's use score describes TCP policy usage.  A UDP success is a
	// separate health ledger and must not make a candidate look more popular
	// for TCP background testing.
	if smartTransportBase(transport) == N.NetworkTCP {
		s.noteCandidateUse(candidate.Tag(), now)
	}
	if len(ranks) > 0 && ready >= min(2, len(ranks)) {
		s.setPhase(smartPhaseSteady)
	} else if ready > 0 {
		s.setPhase(smartPhaseProfiling)
	}
	s.latest.Store(candidate)
	reason := "selected best candidate"
	category := "cold_start"
	if attemptIndex > 0 {
		if hadPriorFailure {
			reason = "failover attempt " + itoaSmall(attemptIndex+1)
		} else {
			reason = "hedged connection won"
		}
	}
	if previous == "" {
		s.coldStarts.Add(1)
	} else if logicalSwitch {
		if failureSwitch {
			category = "failure_failover"
			s.failureFailovers.Add(1)
			reason = "failed candidate bypassed confirmation"
		} else {
			// Surge evaluates Smart per request. Picking another member for a
			// registered-domain context is candidate ordering, not a persistent
			// group-primary transition. Do not feed the legacy switch counters,
			// cooldown or connection-interruption machinery.
			reason = "spread candidate"
		}
		if failureSwitch {
			s.appendSwitchAudit(adapter.SmartSwitchAudit{
				Network:            networkKey,
				Site:               siteDisplay,
				Transport:          transport,
				Previous:           previous,
				PreviousEndpointID: previousEndpointID,
				Current:            candidate.Tag(),
				CurrentEndpointID:  currentEndpointID,
				Category:           category,
				Reason:             reason,
				PreviousState:      previousRank.status.State,
				CurrentState:       currentRank.status.State,
				PreviousScore:      previousRank.status.Score,
				CurrentScore:       currentRank.status.Score,
				OccurredAt:         now,
			})
		}
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, candidate.Tag(), reason)
	if logicalSwitch && failureSwitch {
		s.switchesTotal.Add(1)
		s.interruptPreviousCandidate(networkKey, siteKey, transport, previous, candidate.Tag())
	}
	return true
}

func smartRankByTag(ranks []smartRank, tag string) (smartRank, bool) {
	for _, rank := range ranks {
		if rank.outbound.Tag() == tag {
			return rank, true
		}
	}
	return smartRank{}, false
}

func smartRankIndexForPolicy(ranks []smartRank, policyID uint64, preferredTag string) int {
	if policyID == 0 {
		return -1
	}
	if preferredTag != "" {
		if index := smartRankIndex(ranks, preferredTag); index >= 0 && ranks[index].policyID == policyID && ranks[index].eligible {
			return index
		}
	}
	for index := range ranks {
		if ranks[index].policyID == policyID && ranks[index].eligible {
			return index
		}
	}
	// The policy backend should only select eligible candidates. Keep a
	// defensive fallback for an inconsistent snapshot so the host can still
	// report the selected policy instead of silently changing endpoints.
	for index := range ranks {
		if ranks[index].policyID == policyID {
			return index
		}
	}
	return -1
}

func smartSameEndpoint(metadataByTag map[string]smartCandidateMetadata, left, right string) bool {
	if left == right {
		return true
	}
	leftMetadata, leftFound := metadataByTag[left]
	rightMetadata, rightFound := metadataByTag[right]
	if leftFound && rightFound {
		return smartMetadataSameEndpoint(leftMetadata, rightMetadata)
	}
	return smartEquivalentLine(left, right)
}

func smartRemapCandidateAlias(tag string, oldMetadataByTag, newMetadataByTag map[string]smartCandidateMetadata, candidates []adapter.Outbound) string {
	if tag == "" {
		return ""
	}
	if _, found := newMetadataByTag[tag]; found {
		return tag
	}
	oldMetadata, found := oldMetadataByTag[tag]
	if !found {
		return tag
	}
	for _, candidate := range candidates {
		newMetadata, found := newMetadataByTag[candidate.Tag()]
		if found && smartMetadataSameEndpoint(oldMetadata, newMetadata) {
			return candidate.Tag()
		}
	}
	return tag
}

func smartMetadataSameEndpoint(left, right smartCandidateMetadata) bool {
	// Policy/profile IDs are dial identities. If either side has one, compare
	// only that namespace; falling back to the credential-free path identity
	// here would incorrectly merge two accounts that share a server but have
	// different authentication or service entitlements.
	if left.policyID != 0 || right.policyID != 0 {
		return left.policyID != 0 && left.policyID == right.policyID
	}
	if left.profileID != "" && left.profileID == right.profileID {
		return true
	}
	if left.dialIdentity != "" || right.dialIdentity != "" {
		return left.dialIdentity != "" && left.dialIdentity == right.dialIdentity
	}
	return left.identity != "" && left.identity == right.identity
}

func smartRelativeImprovement(bestScore, currentScore, margin float64) bool {
	if bestScore >= currentScore {
		return false
	}
	if margin <= 0 {
		return true
	}
	return currentScore > bestScore/(1-margin)
}

func smartAbsoluteImprovement(best, current smartRank, minimum time.Duration) bool {
	if minimum <= 0 {
		return true
	}
	bestLatency := smartRankLatencyMS(best)
	currentLatency := smartRankLatencyMS(current)
	if bestLatency <= 0 || currentLatency <= 0 {
		// Do not switch a healthy path on a score that has no comparable latency
		// evidence. Hard failures are handled before this gate.
		return false
	}
	return currentLatency-bestLatency >= float64(minimum)/float64(time.Millisecond)
}

func smartRankLatencyMS(rank smartRank) float64 {
	if rank.status.FirstByteP95MS > 0 {
		return rank.status.FirstByteP95MS
	}
	if rank.status.ConnectP95MS > 0 {
		return rank.status.ConnectP95MS
	}
	if rank.status.FirstByteMS > 0 {
		return rank.status.FirstByteMS
	}
	return rank.status.ConnectMS
}

// smartEquivalentLine recognizes only suffixes generated by the provider
// duplicate-tag resolver. It intentionally does not strip user-visible numeric
// names such as "BGP 1" and "BGP 2", which can be genuinely different lines.
func smartEquivalentLine(left, right string) bool {
	return left != right && smartLineFamily(left) == smartLineFamily(right)
}

func smartLineFamily(tag string) string {
	if len(tag) > 10 && tag[len(tag)-10:len(tag)-8] == " #" && isLowerHex(tag[len(tag)-8:]) {
		return tag[:len(tag)-10]
	}
	if strings.HasSuffix(tag, ")") {
		if open := strings.LastIndex(tag, " ("); open >= 0 && open+2 < len(tag)-1 && isDecimal(tag[open+2:len(tag)-1]) {
			return tag[:open]
		}
	}
	return tag
}

func isLowerHex(value string) bool {
	if len(value) != 8 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}

func isDecimal(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func (s *Smart) performanceSwitchCoolingDown(key string, now time.Time) bool {
	s.access.RLock()
	until := s.performanceCooldown[key]
	s.access.RUnlock()
	return until.After(now)
}

func (s *Smart) appendSwitchAudit(event adapter.SmartSwitchAudit) {
	s.switchAuditAccess.Lock()
	if len(s.switchAudit) >= smartSwitchAuditLimit {
		copy(s.switchAudit, s.switchAudit[len(s.switchAudit)-smartSwitchAuditLimit+1:])
		s.switchAudit = s.switchAudit[:smartSwitchAuditLimit-1]
	}
	s.switchAudit = append(s.switchAudit, event)
	s.switchAuditAccess.Unlock()
}

func (s *Smart) clearSwitchChallenge(key string) {
	s.access.Lock()
	delete(s.switchChallenges, key)
	s.access.Unlock()
}

func (s *Smart) confirmSwitchChallenge(key, candidate string, now time.Time) bool {
	s.access.Lock()
	defer s.access.Unlock()
	challenge := s.switchChallenges[key]
	if challenge.Candidate != candidate || challenge.Since.IsZero() {
		s.switchChallenges[key] = smartSwitchChallenge{Candidate: candidate, Since: now, Count: 1}
		return false
	}
	challenge.Count++
	s.switchChallenges[key] = challenge
	if challenge.Count < s.switchConfirmSamples || now.Sub(challenge.Since) < s.switchConfirm {
		return false
	}
	delete(s.switchChallenges, key)
	return true
}

func smartSelectionKey(networkKey, siteKey, transport string) string {
	return networkKey + "\x00" + siteKey + "\x00" + transport
}

// A site key may carry a parent business identity after the unit separator.
// Metrics and Zig contexts keep the complete key, so subservice failures and
// confirmation state remain isolated. Only the bounded affinity seed uses the
// parent suffix, allowing a new related subservice to inherit a stable primary.
func smartSelectionSiteKey(siteKey string) string {
	if separator := strings.LastIndexByte(siteKey, '\x1f'); separator >= 0 && separator+1 < len(siteKey) {
		return siteKey[separator+1:]
	}
	return siteKey
}

func smartBusinessSelectionKey(networkKey, siteKey, transport string) string {
	// A Smart group has one primary per network/transport. Business and site
	// health evidence remains separate, but selection is intentionally not:
	// otherwise Google, Discord, and ordinary web traffic can each migrate to
	// a different endpoint and expose multiple egress IPs at once. PBR remains
	// the boundary between regional Smart groups.
	_ = siteKey
	return networkKey
}

// smartStatusSelectionKey is deliberately separate from the policy key. The
// health ledger uses a hashed site key, while the dashboard exposes a readable
// site label. Runtime control/data evidence must use one stable key so a
// display alias cannot hide a real dial mismatch.
func smartStatusSelectionKey(networkKey, siteDisplay, transport string) string {
	return networkKey + "\x00" + siteDisplay + "\x00" + transport
}

// smartTransportKey preserves the address family when the caller already
// knows it. sing's NetworkName intentionally normalizes tcp4/tcp6 and udp4/
// udp6 for protocol dispatch, but Smart must not merge those observations into
// one health ledger. Domain destinations without an explicit family retain
// the legacy aggregate key until a concrete family is available.
func smartTransportKey(network string, destination M.Socksaddr) string {
	base := N.NetworkName(network)
	if family := smartNetworkFamily(network, destination); family != "" {
		return base + "/" + family
	}
	return base
}

func smartNetworkFamily(network string, destination M.Socksaddr) string {
	switch network {
	case N.NetworkTCP + "4", N.NetworkUDP + "4":
		return "ipv4"
	case N.NetworkTCP + "6", N.NetworkUDP + "6":
		return "ipv6"
	}
	switch {
	case destination.IsIPv4():
		return "ipv4"
	case destination.IsIPv6():
		return "ipv6"
	default:
		return ""
	}
}

func smartTransportBase(transport string) string {
	switch {
	case strings.HasSuffix(transport, "/ipv4"), strings.HasSuffix(transport, "/ipv6"):
		return transport[:strings.LastIndexByte(transport, '/')]
	default:
		return N.NetworkName(transport)
	}
}

func smartTransportKeyFromConn(network string, destination M.Socksaddr, conn net.Conn) string {
	key := smartTransportKey(network, destination)
	if smartTransportFamily(key) != "" || conn == nil {
		return key
	}
	remote := conn.RemoteAddr()
	family := smartRemoteAddrFamily(remote)
	if family == "" {
		return key
	}
	return N.NetworkName(network) + "/" + family
}

func smartTransportFamily(transport string) string {
	switch {
	case strings.HasSuffix(transport, "/ipv4"):
		return "ipv4"
	case strings.HasSuffix(transport, "/ipv6"):
		return "ipv6"
	default:
		return ""
	}
}

func smartProbeNetwork(family string) string {
	switch family {
	case "ipv4":
		return N.NetworkTCP + "4"
	case "ipv6":
		return N.NetworkTCP + "6"
	default:
		return N.NetworkTCP
	}
}

func smartRemoteAddrFamily(address net.Addr) string {
	switch value := address.(type) {
	case *net.TCPAddr:
		if value.IP != nil {
			if value.IP.To4() != nil {
				return "ipv4"
			}
			if value.IP.To16() != nil {
				return "ipv6"
			}
		}
	case *net.UDPAddr:
		if value.IP != nil {
			if value.IP.To4() != nil {
				return "ipv4"
			}
			if value.IP.To16() != nil {
				return "ipv6"
			}
		}
	}
	return ""
}

func smartConnectionKey(networkKey, siteKey, transport, candidate string) string {
	return smartSelectionKey(networkKey, siteKey, transport) + "\x00" + candidate
}

func (s *Smart) interruptPreviousCandidate(networkKey, siteKey, transport, previous, current string) {
	if s.interruptMode == "none" {
		return
	}
	nodeDead := s.store.endpointDead(networkKey, s.candidateProfileID(previous), transport, time.Now())
	forceAll := s.interruptMode == "all" || nodeDead
	// A performance-driven switch must be invisible to established flows. New
	// connections use the better candidate while existing healthy connections
	// drain naturally. Only a confirmed dead candidate justifies interruption.
	if !forceAll {
		if s.logger != nil {
			s.logger.Info("smart switch ", previous, " -> ", current, " reason=confirmed_performance kept_existing=true")
		}
		return
	}
	policy := interrupt.InterruptPolicy{
		IdleThreshold: s.interruptIdle,
		LongConnAge:   s.interruptLongAge,
		GracePeriod:   s.interruptGrace,
		ForceAll:      forceAll,
		TargetKey:     smartConnectionKey(networkKey, siteKey, transport, previous),
		OnInterrupted: func() { s.connectionsInterrupted.Add(1) },
	}
	result := s.interruptGroup.InterruptSelective(policy)
	if forceAll {
		s.switchesForceAll.Add(1)
	}
	s.connectionsKept.Add(uint64(result.Kept))
	if s.logger != nil {
		reason := "confirmed_performance"
		if nodeDead {
			reason = "node_dead"
		}
		s.logger.Info("smart switch ", previous, " -> ", current, " reason=", reason,
			" interrupted=", result.Interrupted, " deferred=", result.Deferred, " idle=", result.Idle,
			" short=", result.Short, " kept=", result.Kept, " kept_long=", result.KeptLong)
	}
}

func (s *Smart) updateStatus(networkKey, siteDisplay, transport string, ranks []smartRank, reason string) {
	selected := ""
	if len(ranks) > 0 {
		selected = ranks[0].outbound.Tag()
	}
	s.updateStatusSelected(networkKey, siteDisplay, transport, ranks, selected, reason)
}

func (s *Smart) updateStatusSelected(networkKey, siteDisplay, transport string, ranks []smartRank, selected, reason string) {
	now := time.Now()
	phase := s.currentPhase().String()
	contextKey := smartStatusSelectionKey(networkKey, siteDisplay, transport)
	selectedEndpointID := ""
	circuitState := ""
	if selectedRank, found := smartRankByTag(ranks, selected); found {
		selectedEndpointID = selectedRank.status.EndpointID
		if selectedEndpointID == "" {
			selectedEndpointID = smartEndpointID(selectedRank.identity, selectedRank.policyID)
		}
		circuitState = selectedRank.status.State
	}
	s.access.Lock()
	if s.circuitState == nil {
		s.circuitState = make(map[string]string)
	}
	if circuitState != "" {
		s.circuitState[contextKey] = circuitState
	}
	zigSelectedEndpointID := s.zigSelectedEndpoint[contextKey]
	actualDialEndpointID := s.actualDialEndpoint[contextKey]
	selectionGeneration := s.selectionGeneration[contextKey]
	s.access.Unlock()
	lastFailureType := ""
	if failureType := s.lastFailureType.Load(); failureType != nil {
		lastFailureType = *failureType
	}
	pinned, _, _, _ := s.controlSnapshot(now)
	statusCount := min(len(ranks), smartStatusCandidateLimit)
	s.statusAccess.Lock()
	// Identical decisions within a short window are coalesced. Selection and
	// failure reasons are still published immediately; only repeated healthy
	// ranking snapshots from connection fan-out take the fast path.
	if !s.statusLastAt.IsZero() && now.Sub(s.statusLastAt) < smartStatusMinPublishInterval &&
		s.statusLastContext == contextKey && s.statusLastSelected == selected &&
		s.statusLastReason == reason && s.statusLastPhase == phase {
		s.statusAccess.Unlock()
		return
	}
	statuses := s.status.Candidates[:0]
	if cap(statuses) < statusCount {
		statuses = make([]adapter.SmartCandidateStatus, 0, statusCount)
	}
	hasNormal := false
	for _, rank := range ranks {
		if rank.eligible && rank.status.State != "open" && !rank.standbyOnly {
			hasNormal = true
			break
		}
	}
	primaryAssigned := false
	appendStatus := func(rank smartRank) {
		if len(statuses) >= statusCount {
			return
		}
		status := rank.status
		switch {
		case selected != "" && rank.outbound.Tag() == selected:
			status.Role = "primary"
			primaryAssigned = true
		case !rank.eligible || rank.status.State == "open":
			status.Role = "standby"
		case hasNormal && rank.standbyOnly:
			status.Role = "standby"
		case !primaryAssigned:
			status.Role = "primary"
			primaryAssigned = true
		default:
			status.Role = "backup"
		}
		statuses = append(statuses, status)
	}
	stateCounts := s.status.StateCounts
	if stateCounts == nil {
		stateCounts = make(map[string]int, 6)
	} else {
		clear(stateCounts)
	}
	for _, rank := range ranks {
		stateCounts[rank.status.State]++
	}
	if selectedIndex := smartRankIndex(ranks, selected); selectedIndex >= 0 && len(statuses) < statusCount {
		appendStatus(ranks[selectedIndex])
	}
	for index := range ranks {
		if len(statuses) >= statusCount {
			break
		}
		if ranks[index].outbound.Tag() == selected {
			continue
		}
		appendStatus(ranks[index])
	}
	profile := smartProfileInteractive
	if len(ranks) > 0 {
		profile = ranks[0].profile
	}
	s.status = adapter.SmartGroupStatus{
		Selected:                  selected,
		SelectedEndpointID:        selectedEndpointID,
		ZigSelectedEndpointID:     zigSelectedEndpointID,
		ActualDialEndpointID:      actualDialEndpointID,
		SelectionGeneration:       selectionGeneration,
		LastFailureType:           lastFailureType,
		CircuitState:              circuitState,
		SelectionMismatchTotal:    s.selectionMismatchTotal.Load(),
		UnobservedConnectionTotal: s.unobservedConnectionTotal.Load(),
		Pinned:                    pinned,
		Network:                   networkKey,
		Site:                      siteDisplay,
		Phase:                     s.currentPhase().String(),
		Reason:                    transport + "/" + profile.String() + ": " + reason,
		UpdatedAt:                 now,
		CandidateCount:            len(ranks),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(ranks),
		StateCounts:               stateCounts,
		Candidates:                statuses,
	}
	if s.statusContexts == nil {
		s.statusContexts = make(map[string]adapter.SmartContextStatus)
	}
	if _, loaded := s.statusContexts[contextKey]; !loaded {
		s.statusContextOrder = append(s.statusContextOrder, contextKey)
		if len(s.statusContextOrder) > smartStatusContextLimit {
			oldest := s.statusContextOrder[0]
			s.statusContextOrder = s.statusContextOrder[1:]
			delete(s.statusContexts, oldest)
		}
	}
	s.statusContexts[contextKey] = adapter.SmartContextStatus{
		Network:                   networkKey,
		Site:                      siteDisplay,
		Transport:                 transport,
		Phase:                     s.currentPhase().String(),
		Selected:                  selected,
		SelectedEndpointID:        selectedEndpointID,
		ZigSelectedEndpointID:     zigSelectedEndpointID,
		ActualDialEndpointID:      actualDialEndpointID,
		SelectionGeneration:       selectionGeneration,
		LastFailureType:           lastFailureType,
		CircuitState:              circuitState,
		SelectionMismatchTotal:    s.selectionMismatchTotal.Load(),
		UnobservedConnectionTotal: s.unobservedConnectionTotal.Load(),
		Reason:                    transport + "/" + profile.String() + ": " + reason,
		UpdatedAt:                 s.status.UpdatedAt,
		CandidateCount:            len(ranks),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(ranks),
		StateCounts:               cloneSmartStateCounts(stateCounts),
		Candidates:                append([]adapter.SmartCandidateStatus(nil), statuses...),
	}
	s.statusLastAt = now
	s.statusLastContext = contextKey
	s.statusLastSelected = selected
	s.statusLastReason = reason
	s.statusLastPhase = phase
	s.statusAccess.Unlock()
}

func (s *Smart) setWarmingStatus(reason string) {
	s.statusAccess.Lock()
	s.statusLastAt = time.Time{}
	s.statusLastContext = ""
	s.statusLastSelected = ""
	s.statusLastReason = ""
	s.statusLastPhase = ""
	s.status = adapter.SmartGroupStatus{
		Phase:       s.currentPhase().String(),
		Reason:      "warming: " + reason,
		UpdatedAt:   time.Now(),
		StateCounts: map[string]int{},
		Candidates:  []adapter.SmartCandidateStatus{},
	}
	clear(s.statusContexts)
	s.statusContextOrder = nil
	s.statusAccess.Unlock()
}

func (s *Smart) reserveHalfOpen(rank smartRank, networkKey, siteKey, transport string) bool {
	if rank.status.State != "half_open" {
		return false
	}
	key := networkKey + "\x00" + siteKey + "\x00" + rank.outbound.Tag() + "\x00" + transport
	s.access.Lock()
	defer s.access.Unlock()
	if s.halfOpen == nil {
		s.halfOpen = make(map[string]struct{})
	}
	if _, loaded := s.halfOpen[key]; loaded {
		return false
	}
	if s.halfOpenActive >= defaultSmartMaxHalfOpenProbes {
		return false
	}
	s.halfOpen[key] = struct{}{}
	s.halfOpenActive++
	return true
}

func (s *Smart) releaseHalfOpen(candidate, networkKey, siteKey, transport string) {
	key := networkKey + "\x00" + siteKey + "\x00" + candidate + "\x00" + transport
	s.access.Lock()
	if _, loaded := s.halfOpen[key]; loaded {
		delete(s.halfOpen, key)
		if s.halfOpenActive > 0 {
			s.halfOpenActive--
		}
	}
	s.access.Unlock()
}

func (s *Smart) pruneAffinityLocked(now time.Time) {
	limit := min(10000, max(1024, s.maxHistoryEntries/4))
	if len(s.affinity) < limit {
		return
	}
	for key, affinity := range s.affinity {
		if !affinity.ExpiresAt.After(now) {
			delete(s.affinity, key)
		}
	}
	for key := range s.affinity {
		if len(s.affinity) < limit {
			break
		}
		delete(s.affinity, key)
	}
}

// pruneContextStateLocked bounds the per-context maps that otherwise grow one
// entry per (network, site, transport) key for the lifetime of the process.
// It runs on the same cadence as pruneAffinityLocked, inside s.access.
func (s *Smart) pruneContextStateLocked(now time.Time) {
	limit := min(10000, max(1024, s.maxHistoryEntries/4))
	// Cooldown rows are useless once expired.
	for key, until := range s.performanceCooldown {
		if !until.After(now) {
			delete(s.performanceCooldown, key)
		}
	}
	// Challenges older than the confirmation window can never confirm again.
	challengeMaxAge := s.switchConfirm * 8
	if challengeMaxAge <= 0 || challengeMaxAge > time.Hour {
		challengeMaxAge = time.Hour
	}
	for key, challenge := range s.switchChallenges {
		if now.Sub(challenge.Since) > challengeMaxAge {
			delete(s.switchChallenges, key)
		}
	}
	// zigSelectedEndpoint and selectionGeneration share one key set; cap both
	// together by dropping arbitrary rows past the limit (same policy as the
	// affinity overflow pass).
	if len(s.zigSelectedEndpoint) >= limit {
		for key := range s.zigSelectedEndpoint {
			if len(s.zigSelectedEndpoint) < limit && len(s.selectionGeneration) < limit {
				break
			}
			delete(s.zigSelectedEndpoint, key)
			delete(s.selectionGeneration, key)
		}
	}
	if len(s.selectionGeneration) >= limit {
		for key := range s.selectionGeneration {
			if len(s.selectionGeneration) < limit {
				break
			}
			delete(s.selectionGeneration, key)
		}
	}
}

func (s *Smart) clearBrokenPin(candidate, networkKey, siteKey, transport string) {
	temporaryCleared := false
	s.control.access.Lock()
	if s.control.temporary == candidate {
		s.clearTemporaryLocked()
		temporaryCleared = true
	}
	s.control.access.Unlock()
	if temporaryCleared && s.logger != nil {
		s.logger.Warn("smart temporary override cleared after connection failure: ", candidate)
	}
	estimate := s.store.estimate(time.Now(), networkKey, siteKey, s.candidateProfileID(candidate), transport, s.minSamples)
	if estimate.State == "open" || estimate.State == "half_open" {
		s.releaseConfirmedBrokenPin(candidate, "confirmed connection failure threshold reached")
	}
}

// releaseConfirmedBrokenPin turns a failed manual choice back into normal Smart
// operation. The pin is intentionally not restored after recovery: a new pin
// requires a new explicit user selection.
func (s *Smart) releaseConfirmedBrokenPin(candidate, reason string) bool {
	if candidate == "" {
		return false
	}
	s.control.access.Lock()
	if s.control.pinned != candidate {
		s.control.access.Unlock()
		return false
	}
	s.control.pinned = ""
	s.control.pinnedEndpoint = ""
	s.control.pinnedDial = ""
	s.control.access.Unlock()
	s.resetPolicyBackend()
	if s.logger != nil {
		s.logger.Warn("smart manual pin released: ", reason, " tag=", candidate)
	}
	return true
}

func (s *Smart) onProviderUpdated(tag string) error {
	if s.closing.Load() {
		return nil
	}
	s.lifecycleAccess.Lock()
	retired := s.retired
	s.lifecycleAccess.Unlock()
	if retired {
		return nil
	}
	// Provider callbacks may race with Close, which unregisters callbacks and
	// clears the provider map under providerAccess.  Keep this lookup under the
	// same lock as rebuildCandidates/unregisterProviderCallbacks so a late
	// callback cannot read a map while it is being replaced.
	s.providerAccess.Lock()
	_, loaded := s.providers[tag]
	if loaded {
		s.providerRevision++
	}
	s.providerAccess.Unlock()
	if s.closing.Load() {
		return nil
	}
	if !loaded {
		return E.New("outbound provider not found: ", tag)
	}
	// Coalesce re-entrant/concurrent provider callbacks. The first caller owns
	// the rebuild loop; later callbacks only mark a trailing pass and return.
	s.providerRebuildAccess.Lock()
	if s.providerRebuildRunning {
		s.providerRebuildPending = true
		if tag != "" {
			s.providerRebuildTag = tag
		}
		s.providerRebuildAccess.Unlock()
		return nil
	}
	s.providerRebuildRunning = true
	s.providerRebuildAccess.Unlock()

	err := error(nil)
	for {
		err = s.rebuildCandidates(tag)
		if err == nil && !s.closing.Load() {
			// Providers commonly publish after PostStart. The cold-start probe may
			// therefore have observed an empty catalog; do not leave a traffic-idle
			// group unprofiled until the next periodic interval.
			s.requestProbe()
		}
		s.providerRebuildAccess.Lock()
		if !s.providerRebuildPending || s.closing.Load() {
			s.providerRebuildRunning = false
			s.providerRebuildPending = false
			s.providerRebuildTag = ""
			s.providerRebuildAccess.Unlock()
			break
		}
		tag = s.providerRebuildTag
		s.providerRebuildTag = ""
		s.providerRebuildPending = false
		s.providerRebuildAccess.Unlock()
	}
	if errors.Is(err, errSmartNoCandidates) && !s.closing.Load() {
		s.setWarmingStatus("provider " + tag + " has no matching candidates")
	}
	if err != nil && s.logger != nil {
		s.logger.Error("rebuild smart candidates from provider ", tag, ": ", err)
	}
	return err
}

func (s *Smart) rebuildCandidates(updatedProvider string) error {
	if s.closing.Load() {
		return nil
	}
	var roots []adapter.Outbound
	for index, tag := range s.tags {
		candidate, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", index, " not found: ", tag)
		}
		roots = append(roots, candidate)
	}

	// Snapshot provider ownership and immutable filters first. Provider methods
	// must run without providerAccess: a provider is allowed to synchronize its
	// own callback list or synchronously notify consumers while producing its
	// outbound snapshot.
	type providerSnapshot struct {
		tag      string
		provider adapter.Provider
		cached   []adapter.Outbound
		refresh  bool
	}
	s.providerAccess.Lock()
	providerTags := append([]string(nil), s.providerTags...)
	providerRevision := s.providerRevision
	providerSnapshots := make([]providerSnapshot, 0, len(providerTags))
	providerByTag := make(map[string]adapter.Provider, len(providerTags))
	for _, providerTag := range providerTags {
		provider := s.providers[providerTag]
		providerByTag[providerTag] = provider
		cached, cachedOK := s.outboundsCache[providerTag]
		providerSnapshots = append(providerSnapshots, providerSnapshot{
			tag:      providerTag,
			provider: provider,
			cached:   append([]adapter.Outbound(nil), cached...),
			refresh:  updatedProvider == "" || providerTag == updatedProvider || !cachedOK,
		})
	}
	exclude := s.exclude
	include := s.include
	manualExclude := s.manualExclude
	s.providerAccess.Unlock()

	for _, snapshot := range providerSnapshots {
		cache := snapshot.cached
		if snapshot.refresh && snapshot.provider != nil {
			cache = make([]adapter.Outbound, 0)
			for _, candidate := range snapshot.provider.Outbounds() {
				if candidate == nil {
					continue
				}
				if manualExclude.Match(candidate.Tag()) {
					continue
				}
				if !providerMemberAllowed(candidate.Tag(), include, exclude) {
					continue
				}
				cache = append(cache, candidate)
			}
			s.providerAccess.Lock()
			if !s.closing.Load() && s.providers[snapshot.tag] == snapshot.provider {
				s.outboundsCache[snapshot.tag] = append([]adapter.Outbound(nil), cache...)
			}
			s.providerAccess.Unlock()
		}
		roots = append(roots, cache...)
	}

	// A use_all_providers reconciliation may have completed while provider code
	// was running. Do not publish a catalog assembled from retired providers;
	// the reconciliation callback will perform the current rebuild.
	s.providerAccess.Lock()
	providerSetCurrent := s.providerCatalogCurrentLocked(providerTags, providerRevision, providerByTag)
	s.providerAccess.Unlock()
	if !providerSetCurrent {
		return nil
	}
	var candidates []adapter.Outbound
	seen := make(map[string]bool)
	stack := make(map[string]bool)
	for _, root := range roots {
		s.flattenCandidate(root, stack, seen, &candidates)
	}
	if len(candidates) == 0 {
		return errSmartNoCandidates
	}
	allMetadataByTag := make(map[string]smartCandidateMetadata, len(candidates))
	// probeIdentityLocked reads the provider map. Keep the lock only around the
	// identity snapshot; all provider-owned Outbounds calls above are lock-free.
	s.providerAccess.Lock()
	for _, candidate := range candidates {
		tag := candidate.Tag()
		identity := s.probeIdentityLocked(candidate)
		dialIdentity := s.dialIdentityLocked(candidate)
		metadata := s.buildCandidateMetadataWithDialIdentity(tag, identity, dialIdentity)
		allMetadataByTag[tag] = metadata
	}
	s.providerAccess.Unlock()

	// A provider aggregate can expose one authenticated endpoint through
	// several aliases.  Keep aliases available to selector/url-test, but Smart
	// must model routing diversity: one DialIdentity is one candidate.  Pick the
	// lexicographically smallest display tag so provider refresh order cannot
	// move the health profile or the active choice between aliases.
	candidates, candidateMetadataByTag := dedupeSmartCandidates(candidates, allMetadataByTag)
	if len(candidates) == 0 {
		return errSmartNoCandidates
	}
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	keepProfiles := make(map[string]struct{}, len(candidates))
	keepPolicyIDs := make([]uint64, 0, len(candidates))
	seenPolicyIDs := make(map[uint64]struct{}, len(candidates))
	for _, candidate := range candidates {
		tag := candidate.Tag()
		metadata := candidateMetadataByTag[tag]
		candidateByTag[tag] = candidate
		if metadata.profileID != "" {
			keepProfiles[metadata.profileID] = struct{}{}
		}
		if metadata.policyID != 0 {
			if _, exists := seenPolicyIDs[metadata.policyID]; !exists {
				seenPolicyIDs[metadata.policyID] = struct{}{}
				keepPolicyIDs = append(keepPolicyIDs, metadata.policyID)
			}
		}
	}
	// Close or a provider callback can race with the expensive candidate build.
	// Hold providerAccess while taking the catalog lock for the final check and
	// publication. This closes the TOCTOU window where a newer provider
	// generation could be published immediately after an earlier validation.
	// All other paths acquire providerAccess before touching the catalog during
	// reconciliation, so this lock order is deliberate and consistent.
	s.providerAccess.Lock()
	if s.closing.Load() || !s.providerCatalogCurrentLocked(providerTags, providerRevision, providerByTag) {
		s.providerAccess.Unlock()
		return nil
	}
	s.access.Lock()
	if s.closing.Load() {
		s.access.Unlock()
		s.providerAccess.Unlock()
		return nil
	}
	oldMetadataByTag := s.candidateMetadataByTag
	for key, selected := range s.lastSelected {
		s.lastSelected[key] = smartRemapCandidateAlias(selected, oldMetadataByTag, candidateMetadataByTag, candidates)
	}
	for key, affinity := range s.affinity {
		affinity.Candidate = smartRemapCandidateAlias(affinity.Candidate, oldMetadataByTag, candidateMetadataByTag, candidates)
		s.affinity[key] = affinity
	}
	s.candidates = candidates
	s.candidateByTag = candidateByTag
	s.candidateMetadataByTag = candidateMetadataByTag
	s.access.Unlock()
	s.providerAccess.Unlock()
	s.remapPinnedCandidate(candidateMetadataByTag, candidates)
	if s.store != nil {
		s.store.pruneCandidates(keepProfiles)
	}
	s.prunePolicyBackend(keepPolicyIDs)
	if s.closing.Load() {
		return nil
	}
	if latest := s.latest.Load(); latest != nil && candidateByTag[latest.Tag()] == nil {
		s.latest.Store(nil)
	}
	s.control.access.Lock()
	if s.control.temporary != "" && candidateByTag[s.control.temporary] == nil {
		s.clearTemporaryLocked()
	}
	s.control.access.Unlock()
	s.setCandidatesReadyStatus(candidates)
	return nil
}

// providerCatalogCurrentLocked reports whether a candidate build still
// describes the provider set that was snapshotted before external provider
// code ran. The caller must hold providerAccess. Keeping this comparison in a
// single helper makes it possible to repeat it immediately before publishing
// the catalog, closing the validation/publish TOCTOU window.
func (s *Smart) providerCatalogCurrentLocked(providerTags []string, providerRevision uint64, providerByTag map[string]adapter.Provider) bool {
	if len(providerTags) != len(s.providerTags) || providerRevision != s.providerRevision {
		return false
	}
	for index, providerTag := range s.providerTags {
		if providerTags[index] != providerTag || s.providers[providerTag] != providerByTag[providerTag] {
			return false
		}
	}
	return true
}

func (s *Smart) remapPinnedCandidate(metadataByTag map[string]smartCandidateMetadata, candidates []adapter.Outbound) {
	s.control.access.Lock()
	if s.control.pinned == "" {
		s.control.access.Unlock()
		return
	}
	record := adapter.SelectedRecord{
		Version:          1,
		DisplayTag:       s.control.pinned,
		DialIdentity:     s.control.pinnedDial,
		EndpointIdentity: s.control.pinnedEndpoint,
	}
	selected := resolveSelectionRecord(candidates, record)
	if selected == nil || selected.Tag() == s.control.pinned {
		s.control.access.Unlock()
		return
	}
	oldTag := s.control.pinned
	metadata := metadataByTag[selected.Tag()]
	s.control.pinned = selected.Tag()
	s.control.pinnedEndpoint = metadata.identity
	s.control.pinnedDial = metadata.dialIdentity
	s.control.access.Unlock()
	if s.logger != nil {
		s.logger.Info("smart manual pin remapped: ", oldTag, " -> ", selected.Tag())
	}
}

func (s *Smart) setCandidatesReadyStatus(candidates []adapter.Outbound) {
	statusCount := min(len(candidates), smartStatusCandidateLimit)
	statuses := make([]adapter.SmartCandidateStatus, statusCount)
	s.access.RLock()
	for index := range statusCount {
		metadata := s.candidateMetadataByTag[candidates[index].Tag()]
		statuses[index] = adapter.SmartCandidateStatus{
			Tag:        candidates[index].Tag(),
			EndpointID: smartEndpointID(metadata.identity, metadata.policyID),
			State:      "warming",
			Reason:     "awaiting observations",
		}
	}
	s.access.RUnlock()
	s.statusAccess.Lock()
	s.statusLastAt = time.Time{}
	s.statusLastContext = ""
	s.statusLastSelected = ""
	s.statusLastReason = ""
	s.statusLastPhase = ""
	s.status = adapter.SmartGroupStatus{
		Phase:                     s.currentPhase().String(),
		Reason:                    "warming: candidates loaded, awaiting observations",
		UpdatedAt:                 time.Now(),
		CandidateCount:            len(candidates),
		CandidateDetailsCount:     len(statuses),
		CandidateDetailsTruncated: len(statuses) < len(candidates),
		StateCounts:               map[string]int{"warming": len(candidates)},
		Candidates:                statuses,
	}
	clear(s.statusContexts)
	s.statusContextOrder = nil
	s.statusAccess.Unlock()
}

func (s *Smart) flattenCandidate(candidate adapter.Outbound, stack, seen map[string]bool, destination *[]adapter.Outbound) {
	tag := candidate.Tag()
	if tag == "" || stack[tag] {
		return
	}
	if outboundGroup, isGroup := candidate.(adapter.OutboundGroup); isGroup {
		stack[tag] = true
		for _, childTag := range outboundGroup.All() {
			child, loaded := s.outbound.Outbound(childTag)
			if loaded {
				s.flattenCandidate(child, stack, seen, destination)
			}
		}
		delete(stack, tag)
		return
	}
	if seen[tag] {
		return
	}
	if s.manualExclude.Match(tag) {
		return
	}
	seen[tag] = true
	*destination = append(*destination, candidate)
}

func dedupeSmartCandidates(candidates []adapter.Outbound, metadataByTag map[string]smartCandidateMetadata) ([]adapter.Outbound, map[string]smartCandidateMetadata) {
	if len(candidates) <= 1 {
		return candidates, metadataByTag
	}
	keyFor := func(candidate adapter.Outbound) string {
		if candidate == nil {
			return ""
		}
		metadata := metadataByTag[candidate.Tag()]
		if metadata.dialIdentity != "" {
			return "dial:" + metadata.dialIdentity
		}
		if metadata.identity != "" {
			return "path:" + metadata.identity
		}
		return "tag:" + candidate.Tag()
	}
	winner := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		key := keyFor(candidate)
		if previous, exists := winner[key]; !exists || candidate.Tag() < previous {
			winner[key] = candidate.Tag()
		}
	}
	selected := make([]adapter.Outbound, 0, len(winner))
	selectedMetadata := make(map[string]smartCandidateMetadata, len(winner))
	for _, candidate := range candidates {
		key := keyFor(candidate)
		if winner[key] != candidate.Tag() {
			continue
		}
		selected = append(selected, candidate)
		selectedMetadata[candidate.Tag()] = metadataByTag[candidate.Tag()]
	}
	return selected, selectedMetadata
}

func (s *Smart) networkFingerprint() string {
	if s.network == nil {
		return "network-default"
	}
	now := time.Now().UnixNano()
	if cached := s.fingerprint.Load(); cached != nil && now < cached.expiresAt {
		return cached.value
	}
	s.fingerprintLock.Lock()
	defer s.fingerprintLock.Unlock()
	if cached := s.fingerprint.Load(); cached != nil && now < cached.expiresAt {
		return cached.value
	}
	value := smartNetworkFingerprint(s.network.DefaultNetworkInterface(), s.network.WIFIState())
	s.fingerprint.Store(&smartFingerprintCache{
		value:     value,
		expiresAt: now + int64(smartNetworkFingerprintTTL),
	})
	return value
}

func smartNetworkFingerprint(networkInterface *adapter.NetworkInterface, wifi adapter.WIFIState) string {
	var identity strings.Builder
	if networkInterface != nil {
		identity.WriteString(networkInterface.Name)
		identity.WriteByte('|')
		identity.WriteString(itoaSmall(networkInterface.Index))
		identity.WriteByte('|')
		identity.WriteString(networkInterface.Type.String())
		identity.WriteByte('|')
		identity.WriteString(networkInterface.HardwareAddr.String())
		identity.WriteByte('|')
		identity.WriteString(itoaSmall(networkInterface.MTU))
		addresses := append([]netip.Prefix(nil), networkInterface.Addresses...)
		sort.Slice(addresses, func(i, j int) bool {
			return addresses[i].String() < addresses[j].String()
		})
		for _, address := range addresses {
			identity.WriteByte('|')
			identity.WriteString(address.Masked().String())
		}
		dnsServers := append([]string(nil), networkInterface.DNSServers...)
		sort.Strings(dnsServers)
		for _, dnsServer := range dnsServers {
			identity.WriteByte('|')
			identity.WriteString(dnsServer)
		}
	}
	identity.WriteByte('|')
	identity.WriteString(wifi.SSID)
	identity.WriteByte('|')
	identity.WriteString(wifi.BSSID)
	return "network-" + hashSmartIdentity(identity.String())
}

func smartSiteIdentity(metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	return resolveSmartSiteIdentity(nil, metadata, destination)
}

func (s *Smart) resolveSmartSiteIdentity(metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	if s == nil {
		return smartSiteIdentity(metadata, destination)
	}
	return resolveSmartSiteIdentity(s.families, metadata, destination)
}

func resolveSmartSiteIdentity(families *trafficfamily.Resolver, metadata *adapter.InboundContext, destination M.Socksaddr) (string, string) {
	host := ""
	if metadata != nil {
		host = sniffOrDomain(metadata)
	}
	if host == "" && destination.IsDomain() {
		host = destination.Fqdn
	}
	host = normalizeSmartHostname(host)
	var address netip.Addr
	if metadata != nil && len(metadata.DestinationAddresses) > 0 {
		address = metadata.DestinationAddresses[0]
	} else {
		address = destination.Addr
	}
	if host != "" {
		if net.ParseIP(host) == nil {
			family := ""
			business := ""
			if families != nil {
				application := ""
				if metadata != nil {
					application = metadata.Application
				}
				protocol := ""
				if metadata != nil {
					protocol = metadata.Protocol
				}
				match := families.ResolveEvidence(trafficfamily.Evidence{Host: host, Application: application, Protocol: protocol, Feature: protocol, Address: address}, smartFamilyClientScope(metadata), time.Now())
				family = match.ID
				business = match.Business
			} else {
				match := trafficfamily.Classify(host)
				family = match.ID
				business = match.Business
			}
			if display, siteKey, ok := smartFamilySiteIdentity(family, business); ok {
				return display, siteKey
			}
			if strings.HasPrefix(family, "site:") {
				host = strings.TrimPrefix(family, "site:")
			} else if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
				host = etld
			}
		}
		return host, "site-" + hashSmartIdentity(host)
	}
	if address.IsValid() {
		match := trafficfamily.ClassifyAddress(address)
		if families != nil {
			application := ""
			feature := ""
			if metadata != nil {
				application = metadata.Application
				feature = metadata.Protocol
			}
			match = families.ResolveEvidence(trafficfamily.Evidence{Application: application, Feature: feature, Address: address}, smartFamilyClientScope(metadata), time.Now())
		}
		if display, siteKey, ok := smartFamilySiteIdentity(match.ID, match.Business); ok {
			return display, siteKey
		}
		display := address.String()
		return display, "site-" + hashSmartIdentity(display)
	}
	return "", ""
}

func smartFamilySiteIdentity(family, business string) (string, string, bool) {
	if family == "" || family == "unknown" || strings.HasPrefix(family, "site:") {
		return "", "", false
	}
	display := "service:" + family
	// The display family remains precise for diagnostics, while health and
	// affinity use the canonical business identity.  A logical service often
	// spans an account origin, API, static assets and CDN (for example Google
	// OAuth + gstatic + googleusercontent).  Keeping those origins in separate
	// ledgers allows a partially stalled node to pass the primary-origin check
	// and strand the browser in a loading spinner.  Unknown/registrable sites
	// still use their own site key above and are not merged.
	// Google OAuth is the one cross-origin flow that must share the same
	// failure ledger with its static/API/CDN hosts.  Keep other business
	// families service-scoped: their API and web products intentionally have
	// different failure domains.
	if business == "google" {
		siteKey := "business-" + hashSmartIdentity("business:"+business)
		return display, siteKey, true
	}
	siteKey := "site-" + hashSmartIdentity(display)
	if business != "" && business != family {
		siteKey += "\x1fsite-" + hashSmartIdentity("business:"+business)
	}
	return display, siteKey, true
}

func smartFamilyClientScope(metadata *adapter.InboundContext) string {
	if metadata == nil {
		return "default"
	}
	return metadata.Inbound + "\x00" + metadata.Source.Addr.String() + "\x00" + metadata.User
}

func smartEstimateReason(estimate smartEstimate) string {
	switch estimate.State {
	case "open":
		return "circuit open until " + estimate.CircuitUntil.Format(time.RFC3339)
	case "half_open":
		return "breaker cooldown elapsed; limited recovery trial"
	case "warming":
		return "collecting baseline samples"
	case "suspect":
		return "confidence-adjusted reliability is low"
	case "unknown":
		return "no observations; exploration budget applies"
	default:
		return "healthy"
	}
}

func smartRankIndex(ranks []smartRank, tag string) int {
	for index := range ranks {
		if ranks[index].outbound.Tag() == tag {
			return index
		}
	}
	return -1
}

func moveSmartRankFirst(ranks []smartRank, index int) {
	if index <= 0 {
		return
	}
	selected := ranks[index]
	copy(ranks[1:index+1], ranks[:index])
	ranks[0] = selected
}

func hashSmartIdentity(value string) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil))
}

func itoaSmall(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

type smartObservedConn struct {
	N.ExtendedConn
	startedAt        time.Time
	readBytes        atomic.Int64
	writeBytes       atomic.Int64
	firstRead        atomic.Bool
	closeOnce        sync.Once
	failureOnce      sync.Once
	onFirstByte      func(time.Duration)
	onClose          func(int64, time.Duration)
	onRetransmit     func(float64)
	onFailure        func()
	onFailureReason  func(string)
	stallOnce        sync.Once
	failureNotified  atomic.Bool
	stallTimeout     time.Duration
	stallTimerAccess sync.Mutex
	stallTimer       *time.Timer
	stallGeneration  uint64
	stallPending     bool
	closed           atomic.Bool
	requestCtx       context.Context
}

// smartObservedWrapper is implemented by every stream and packet observation
// wrapper. Packet wrappers embed smartObservedPacketConn, so a concrete type
// assertion against *smartObservedPacketConn would reject the extended reader,
// writer, and reader/writer wrappers even though they are fully observed.
type smartObservedWrapper interface {
	smartObservedWrapperMarker()
}

func (*smartObservedConn) smartObservedWrapperMarker() {}

func newSmartObservedConn(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onFailure func()) net.Conn {
	return newSmartObservedConnWithStall(conn, startedAt, onFirstByte, onClose, onFailure, 0)
}

func newSmartObservedConnWithStall(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onFailure func(), stallTimeout time.Duration) net.Conn {
	return newSmartObservedConnWithRetransmit(conn, startedAt, onFirstByte, onClose, nil, onFailure, stallTimeout)
}

func newSmartObservedConnWithRetransmit(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onRetransmit func(float64), onFailure func(), stallTimeout time.Duration, requestCtx ...context.Context) net.Conn {
	return newSmartObservedConnWithRetransmitReason(conn, startedAt, onFirstByte, onClose, onRetransmit, onFailure, nil, stallTimeout, requestCtx...)
}

func newSmartObservedConnWithRetransmitReason(conn net.Conn, startedAt time.Time, onFirstByte func(time.Duration), onClose func(int64, time.Duration), onRetransmit func(float64), onFailure func(), onFailureReason func(string), stallTimeout time.Duration, requestCtx ...context.Context) net.Conn {
	var ctx context.Context
	if len(requestCtx) > 0 {
		ctx = requestCtx[0]
	}
	return &smartObservedConn{
		ExtendedConn:    bufio.NewExtendedConn(conn),
		startedAt:       startedAt,
		onFirstByte:     onFirstByte,
		onClose:         onClose,
		onRetransmit:    onRetransmit,
		onFailure:       onFailure,
		onFailureReason: onFailureReason,
		stallTimeout:    stallTimeout,
		requestCtx:      ctx,
	}
}

func (c *smartObservedConn) Read(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Read(buffer)
	c.observeRead(int64(n))
	c.observeFailure(err)
	return n, err
}

func (c *smartObservedConn) Write(buffer []byte) (int, error) {
	n, err := c.ExtendedConn.Write(buffer)
	c.observeWrite(int64(n))
	c.observeFailure(err)
	return n, err
}

func (c *smartObservedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.ExtendedConn.ReadBuffer(buffer)
	readBytes := buffer.Len() - before
	c.observeRead(int64(readBytes))
	c.observeFailure(err)
	return err
}

func (c *smartObservedConn) WriteBuffer(buffer *buf.Buffer) error {
	writeBytes := buffer.Len()
	err := c.ExtendedConn.WriteBuffer(buffer)
	if err == nil && writeBytes > 0 {
		c.observeWrite(int64(writeBytes))
	}
	c.observeFailure(err)
	return err
}

func (c *smartObservedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.stopStallTimer()
		if c.onClose != nil {
			c.onClose(c.readBytes.Load()+c.writeBytes.Load(), time.Since(c.startedAt))
		}
		if c.onRetransmit != nil {
			if ratio, ok := smartTCPRetransmitRatio(c.ExtendedConn); ok {
				c.onRetransmit(ratio)
			}
		}
	})
	return c.ExtendedConn.Close()
}

func (c *smartObservedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	// Keep the byte-counter contract used by sing/common/bufio, but do not
	// return the raw upstream reader.  CopyWithIncreateBuffer unwraps a
	// ReadCounter before copying; returning ExtendedConn directly would bypass
	// Read/ReadBuffer and lose the terminal proxy-protocol error (for example
	// VLESS "unknown version: 72").  The small reader shim preserves the
	// zero-allocation counter path while routing the read error through the
	// Smart classifier.
	return smartObservedReader{owner: c}, []N.CountFunc{c.observeRead}
}

func (c *smartObservedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return smartObservedWriter{owner: c}, []N.CountFunc{c.observeWrite}
}

type smartObservedReader struct {
	owner *smartObservedConn
}

func (r smartObservedReader) Read(buffer []byte) (int, error) {
	return r.owner.Read(buffer)
}

func (r smartObservedReader) ReadBuffer(buffer *buf.Buffer) error {
	return r.owner.ReadBuffer(buffer)
}

type smartObservedWriter struct {
	owner *smartObservedConn
}

func (w smartObservedWriter) Write(buffer []byte) (int, error) {
	return w.owner.Write(buffer)
}

func (w smartObservedWriter) WriteBuffer(buffer *buf.Buffer) error {
	return w.owner.WriteBuffer(buffer)
}

func (c *smartObservedConn) Upstream() any {
	return c.ExtendedConn
}

func (c *smartObservedConn) observeRead(n int64) {
	if n <= 0 {
		return
	}
	c.readBytes.Add(n)
	// A response, including one on an already-established stream, completes
	// the current request phase.  Clearing the timer here keeps idle keep-alive
	// and streaming connections from being treated as failures.
	c.stopStallTimer()
	if c.firstRead.CompareAndSwap(false, true) {
		if c.onFirstByte != nil {
			c.onFirstByte(time.Since(c.startedAt))
		}
	}
}

func (c *smartObservedConn) observeWrite(n int64) {
	if n > 0 {
		c.writeBytes.Add(n)
		c.armStallTimer()
	}
}

func (c *smartObservedConn) armStallTimer() {
	if c.stallTimeout <= 0 || c.closed.Load() || c.failureNotified.Load() {
		return
	}
	c.stallTimerAccess.Lock()
	if c.stallTimer == nil && !c.stallPending && !c.closed.Load() && !c.failureNotified.Load() {
		c.stallGeneration++
		generation := c.stallGeneration
		c.stallPending = true
		c.stallTimer = time.AfterFunc(c.stallTimeout, func() {
			c.observeStall(generation)
		})
	}
	c.stallTimerAccess.Unlock()
}

func (c *smartObservedConn) stopStallTimer() {
	c.stallTimerAccess.Lock()
	c.stallGeneration++
	if c.stallTimer != nil {
		c.stallTimer.Stop()
		c.stallTimer = nil
	}
	c.stallPending = false
	c.stallTimerAccess.Unlock()
}

func (c *smartObservedConn) observeStall(generation uint64) {
	c.stallTimerAccess.Lock()
	if c.closed.Load() || !c.stallPending || generation != c.stallGeneration {
		c.stallTimerAccess.Unlock()
		return
	}
	c.stallTimer = nil
	c.stallPending = false
	c.stallTimerAccess.Unlock()
	if c.requestCtx != nil && c.requestCtx.Err() != nil {
		return
	}
	c.stallOnce.Do(func() {
		c.notifyFailureType("timeout")
	})
}

func (c *smartObservedConn) observeFailure(err error) {
	if err != nil {
		// A terminal or classified read/write error ends the current request
		// phase.  Do not leave its timer behind to report a second, synthetic
		// stall after the transport has already told us what happened.
		c.stopStallTimer()
	}
	if isSmartRequestContextError(c.requestCtx, err) {
		return
	}
	// The explicit protocol markers below are authoritative even when the
	// protocol reader consumed invalid bytes before returning the error.  The
	// old gate treated any byte as a valid first response, which allowed a
	// malformed VLESS/VMess/Trojan handshake to escape the breaker.  Ordinary
	// application responses (403/429/EOF) are not in that marker set and remain
	// site-local observations.
	if !isSmartStreamFailure(err, !c.firstRead.Load()) {
		return
	}
	failureType := "transport"
	if isSmartProtocolHandshakeFailure(err) {
		failureType = "protocol"
	}
	c.notifyFailureType(failureType)
}

func (c *smartObservedConn) notifyFailure() {
	c.notifyFailureType("")
}

func (c *smartObservedConn) notifyFailureType(failureType string) {
	c.failureOnce.Do(func() {
		c.failureNotified.Store(true)
		if c.onFailureReason != nil {
			c.onFailureReason(failureType)
		} else if c.onFailure != nil {
			c.onFailure()
		}
	})
}

func isSmartStreamFailure(err error, _ ...bool) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	// A protocol reader may consume the invalid response bytes before it can
	// report the framing/authentication error.  Therefore an explicit proxy
	// protocol marker is hard evidence regardless of whether the raw stream has
	// already yielded bytes.  HTTP status codes and normal EOF are intentionally
	// excluded by isSmartProtocolHandshakeFailure.
	return isSmartProtocolHandshakeFailure(err)
}

func smartFailureType(err error) string {
	if isSmartProtocolHandshakeFailure(err) {
		return "protocol"
	}
	// A peer or route that explicitly refuses/unreachably rejects the dial is
	// authoritative node evidence. Timeouts, resets and broken pipes remain
	// site-local exactly like Surge's per-registered-domain failure records.
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return "hard_transport"
	}
	return "transport"
}

// isSmartRequestContextError separates a caller-owned request deadline from a
// transport timeout. The former only says that this flow was abandoned and
// must never lower the endpoint score; the latter remains valid node evidence.
func isSmartRequestContextError(requestCtx context.Context, err error) bool {
	if requestCtx == nil || requestCtx.Err() == nil || err == nil {
		return false
	}
	requestErr := requestCtx.Err()
	if errors.Is(requestErr, context.Canceled) {
		return errors.Is(err, context.Canceled)
	}
	if errors.Is(requestErr, context.DeadlineExceeded) {
		return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
	}
	return false
}

// isSmartProtocolHandshakeFailure recognizes errors emitted by protocol
// readers after DialContext or ListenPacket has already returned.  The list is
// intentionally explicit and covers both the normal and slim-build-disabled
// protocol modules.  Application HTTP status codes, normal EOF, generic TLS
// errors and arbitrary remote text must not evict a node; only a protocol
// parser/authenticator sentinel is strong enough to do so.
func isSmartProtocolHandshakeFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "i/o timeout") || strings.Contains(message, "deadline exceeded") {
		return false
	}
	markers := []string{
		// VLESS / VMess.
		"unknown version:",
		"unknown version ",
		"unknown protobuf message header",
		"unknown command:",
		"unknown command ",
		"unknown uuid:",
		"unknown flow:",
		"flow mismatch",
		"bad response header",
		"bad length chunk",
		"bad session status",
		"bad network:",
		"bad packet connection",
		"bad header type",
		"bad client session id",
		"bad request salt",
		"bad timestamp",
		"bad request:",
		"vmess: invalid chunk checksum",
		"vmess: unsupported security type",
		"vision: not a valid supported tls connection",

		// Trojan and Shadowsocks (including Shadowsocks 2022).
		"bad request size",
		"snell: bad header",
		"salt not unique",
		"server session changed more than once during the last minute",
		"shadowsocks: unsupported method",

		// TUIC / Hysteria / Hysteria2.  UDP capability errors are transport
		// scoped by the caller, so they do not evict TCP candidates.
		"authentication:",
		"authentication timeout",
		"unsupported stream command",
		"invalid dissociate message",
		"invalid message",
		"unsupported client version",
		"authentication failed, auth_str=",
		"unknown session id:",
		"udp disabled by server",
		"udp session id duplicated",

		// SOCKS and HTTP CONNECT upstreams.
		"unknown socks version:",
		"socks5: incorrect user name or password",
		"socks5: unsupported auth method:",
		"socks4: authentication failed",
		"socks5: authentication failed",
		"socks4: udp unsupported",
		"socks4: unsupported command",
		"socks5: unsupported command",
		"http: authentication failed",

		// Snell.
		"snell: reserved header",
		"snell: unsupported command",
		"snell: bad user key",
		"snell: invalid udp tunnel request",
		"snell: duplicated salt",
		"snell: server error ",

		// SSH and VPN protocols that can fail after their underlying socket
		// has connected.  WireGuard/Tailscale readiness errors are returned
		// from Dial/ListenPacket and are already counted by the caller.
		"ssh: handshake failed",
		"ssh: unable to authenticate",
		"ssh: host key mismatch",
		"ssh: no common algorithm",
		"ssh: no authentication methods",
		"host key mismatch",
		"no shared cipher",
		"cipher negotiation failed with peer",
		"negotiated cipher not allowed",
		"unsupported openvpn protocol",
		"invalid tls control packet",
		"invalid tls-crypt packet",
		"invalid tls-auth packet",
		"invalid tls-crypt-v2 packet",
		"invalid tls-crypt-v2 wrapped key",
		"missing tls-crypt-v2 wrapped client key",
		"peer wants tls-crypt-v2 but no server key is present",
		"tls-crypt-v2 client key authentication failed",
		"invalid tls data packet",
		"invalid tls data packet hmac",
		"replayed tls data packet",
		"invalid tls stream data packet hmac",
		"replayed tls stream data packet",
		"invalid gcm ciphertext",
		"invalid gcm payload",
		"replayed gcm packet",
		"invalid static key payload",
		"invalid static key payload hmac",
		"replayed static key data packet",
		"invalid static key packet id",
		"invalid openvpn push reply fields",
		"invalid openconnect authentication response",
		"invalid openconnect browser authentication result",
		"protocol behavior is not supported",
		"invalid cstp packet header",
		"invalid cstp http headers",
		"invalid cstp http status",
		"received unknown cstp packet type",

		// Naive / AnyTLS / other optional transports.
		"v2ray-http: unexpected status:",
		"v2ray-http-upgrade: unexpected status:",
		"v2ray-grpc: unexpected status:",
		"anytls: authentication failed",
		"anytls: remote:",
		"unknown user password",
		"authentication failed:",
		"authentication failed, status code:",
		"message authentication failed",
		"remote error:",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// Shadowsocks/2022, VMess, OpenConnect and OpenVPN also expose exact
	// sentinel messages.  Keep these exact (rather than substring) matches so a
	// target application response cannot accidentally open a node breaker.
	switch message {
	case "bad header", "invalid request", "bad request", "bad version", "replayed request", "authentication failed", "authentication required", "authorization failed":
		return true
	default:
		return false
	}
}

// smartObservedPacketConn turns real transactional UDP blackholes into Smart
// node evidence. It deliberately ignores one-way UDP and idle timeouts after
// any response, so telemetry and long-lived QUIC sessions are not penalized.
// A response watchdog is armed after the protocol-specific write threshold
// (one DNS query, three QUIC/STUN datagrams). This closes the old gap where a
// half-open UDP/QUIC flow was only reported when its owner happened to close,
// without treating one lost handshake packet as a dead node.
type smartObservedPacketConn struct {
	net.PacketConn
	startedAt          time.Time
	expectResponse     bool
	requiredPackets    uint64
	watchdogTimeout    time.Duration
	writePackets       atomic.Uint64
	readPackets        atomic.Uint64
	closeOnce          sync.Once
	noResponseOnce     sync.Once
	onNoResponse       func(time.Duration)
	closed             atomic.Bool
	watchdogAccess     sync.Mutex
	watchdogTimer      *time.Timer
	watchdogGeneration uint64
	watchdogPending    bool
	requestCtx         context.Context
}

func (*smartObservedPacketConn) smartObservedWrapperMarker() {}

func newSmartObservedPacketConn(conn net.PacketConn, startedAt time.Time, expectResponse bool, onNoResponse func(time.Duration)) net.PacketConn {
	return newSmartObservedPacketConnWithWatchdog(conn, startedAt, expectResponse, 0, onNoResponse)
}

func newSmartObservedPacketConnWithWatchdog(conn net.PacketConn, startedAt time.Time, expectResponse bool, watchdogTimeout time.Duration, onNoResponse func(time.Duration)) net.PacketConn {
	return newSmartObservedPacketConnWithWatchdogThreshold(conn, startedAt, expectResponse, 1, watchdogTimeout, onNoResponse)
}

func newSmartObservedPacketConnWithWatchdogThreshold(conn net.PacketConn, startedAt time.Time, expectResponse bool, requiredPackets uint64, watchdogTimeout time.Duration, onNoResponse func(time.Duration), requestCtx ...context.Context) net.PacketConn {
	if requiredPackets == 0 {
		requiredPackets = 1
	}
	base := &smartObservedPacketConn{
		PacketConn:      conn,
		startedAt:       startedAt,
		expectResponse:  expectResponse,
		requiredPackets: requiredPackets,
		watchdogTimeout: watchdogTimeout,
		onNoResponse:    onNoResponse,
	}
	if len(requestCtx) > 0 {
		base.requestCtx = requestCtx[0]
	}
	reader, hasReader := conn.(N.PacketReader)
	writer, hasWriter := conn.(N.PacketWriter)
	switch {
	case hasReader && hasWriter:
		return &smartObservedExtendedPacketConn{smartObservedPacketConn: base, reader: reader, writer: writer}
	case hasReader:
		return &smartObservedPacketReaderConn{smartObservedPacketConn: base, reader: reader}
	case hasWriter:
		return &smartObservedPacketWriterConn{smartObservedPacketConn: base, writer: writer}
	default:
		return base
	}
}

func (c *smartObservedPacketConn) observeRead(count int) {
	if count > 0 {
		c.readPackets.Add(1)
		c.stopWatchdog()
	}
}

func (c *smartObservedPacketConn) observeWrite(count int) {
	if count > 0 {
		packets := c.writePackets.Add(1)
		if packets >= c.requiredPackets {
			c.armWatchdog()
		}
	}
}

func (c *smartObservedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, source, err := c.PacketConn.ReadFrom(payload)
	c.observeRead(count)
	c.observePacketFailure(err)
	return count, source, err
}

func (c *smartObservedPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	count, err := c.PacketConn.WriteTo(payload, destination)
	if err == nil {
		c.observeWrite(count)
	} else {
		c.observePacketFailure(err)
	}
	return count, err
}

func (c *smartObservedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.stopWatchdog()
		elapsed := time.Since(c.startedAt)
		if (c.requestCtx == nil || c.requestCtx.Err() == nil) && c.expectResponse && c.writePackets.Load() >= c.requiredPackets && c.readPackets.Load() == 0 && elapsed >= time.Second && c.onNoResponse != nil {
			c.notifyNoResponse(elapsed)
		}
	})
	return c.PacketConn.Close()
}

func (c *smartObservedPacketConn) armWatchdog() {
	if !c.expectResponse || c.watchdogTimeout <= 0 || c.closed.Load() || c.writePackets.Load() < c.requiredPackets {
		return
	}
	c.watchdogAccess.Lock()
	if c.watchdogTimer == nil && !c.watchdogPending && !c.closed.Load() {
		c.watchdogGeneration++
		generation := c.watchdogGeneration
		c.watchdogPending = true
		c.watchdogTimer = time.AfterFunc(c.watchdogTimeout, func() {
			c.observeWatchdog(generation)
		})
	}
	c.watchdogAccess.Unlock()
}

func (c *smartObservedPacketConn) stopWatchdog() {
	c.watchdogAccess.Lock()
	c.watchdogGeneration++
	if c.watchdogTimer != nil {
		c.watchdogTimer.Stop()
		c.watchdogTimer = nil
	}
	c.watchdogPending = false
	c.watchdogAccess.Unlock()
}

func (c *smartObservedPacketConn) observeWatchdog(generation uint64) {
	c.watchdogAccess.Lock()
	if c.closed.Load() || !c.watchdogPending || generation != c.watchdogGeneration {
		c.watchdogAccess.Unlock()
		return
	}
	c.watchdogTimer = nil
	c.watchdogPending = false
	c.watchdogAccess.Unlock()
	if c.requestCtx != nil && c.requestCtx.Err() != nil {
		return
	}
	c.notifyNoResponse(time.Since(c.startedAt))
}

func (c *smartObservedPacketConn) notifyNoResponse(elapsed time.Duration) {
	c.noResponseOnce.Do(func() {
		if c.onNoResponse != nil {
			c.onNoResponse(elapsed)
		}
	})
}

func (c *smartObservedPacketConn) observePacketFailure(err error) {
	if err == nil {
		return
	}
	if isSmartRequestContextError(c.requestCtx, err) {
		return
	}
	// Network failures only have node-level meaning for a transactional UDP
	// flow that is waiting for a response.  Protocol sentinels are different:
	// they prove that the proxy/VPN peer rejected or could not decode the
	// session, even for one-way UDP, and must be fed into the same breaker.
	if !isSmartProtocolHandshakeFailure(err) && (!c.expectResponse || !isSmartPacketFailure(err)) {
		return
	}
	c.stopWatchdog()
	c.notifyNoResponse(time.Since(c.startedAt))
}

func isSmartPacketFailure(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ETIMEDOUT)
}

func (c *smartObservedPacketConn) Upstream() any         { return c.PacketConn }
func (*smartObservedPacketConn) ReaderReplaceable() bool { return false }
func (*smartObservedPacketConn) WriterReplaceable() bool { return false }

type smartObservedPacketReaderConn struct {
	*smartObservedPacketConn
	reader N.PacketReader
}

func (c *smartObservedPacketReaderConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	c.observePacketFailure(err)
	return destination, err
}

type smartObservedPacketWriterConn struct {
	*smartObservedPacketConn
	writer N.PacketWriter
}

func (c *smartObservedPacketWriterConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil {
		c.observeWrite(count)
	} else {
		c.observePacketFailure(err)
	}
	return err
}

type smartObservedExtendedPacketConn struct {
	*smartObservedPacketConn
	reader N.PacketReader
	writer N.PacketWriter
}

func (c *smartObservedExtendedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	c.observeRead(buffer.Len() - before)
	c.observePacketFailure(err)
	return destination, err
}

func (c *smartObservedExtendedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil {
		c.observeWrite(count)
	} else {
		c.observePacketFailure(err)
	}
	return err
}
