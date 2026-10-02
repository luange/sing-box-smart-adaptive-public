package adaptive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/nodefilter"
	"github.com/sagernet/sing-box/common/nodeweight"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/probe"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	defaultProbeURL          = probe.GoogleConnectivityURL
	defaultProbeCoverage     = 10 * time.Minute
	defaultProbeTimeout      = 5 * time.Second
	defaultProbeConcurrency  = 8
	defaultProbeQueueSize    = 4096
	defaultCapabilityRefresh = 5 * time.Minute
	defaultCapabilityTimeout = 20 * time.Second
	defaultStateRetention    = 7 * 24 * time.Hour
	defaultStateMaxEntries   = 4096
	defaultStrictLeaseTTL    = 30 * time.Minute
	defaultAdaptiveLeaseTTL  = 10 * time.Minute
	defaultMaxLeases         = 8192
	defaultMaxAttempts       = 3
	defaultAttemptTimeout    = 4 * time.Second
	defaultHedgeDelay        = 450 * time.Millisecond
	statusCandidateLimit     = 64
)

type adaptivePublishPhase uint8

const (
	publishPhasePrepared adaptivePublishPhase = iota + 1
	publishPhasePublishing
	publishPhaseActive
	publishPhaseRollingBack
	publishPhaseRetired
)

var (
	_ adapter.AdaptivePoolGroup        = (*AdaptivePool)(nil)
	_ adapter.DashboardURLTestGroup    = (*AdaptivePool)(nil)
	_ adapter.PreMatchDisabledOutbound = (*AdaptivePool)(nil)
	_ adapter.RuntimeEpochLifecycle    = (*AdaptivePool)(nil)
)

type AdaptivePool struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	source SourceRuntime

	shadow                     bool
	probeURL                   string
	probeCoverage              time.Duration
	probeTimeout               time.Duration
	probeConcurrency           int
	probeQueueSize             int
	probeRunner                func(context.Context, string, N.Dialer) (uint16, error)
	statePath                  string
	groupID                    string
	runtimeManager             *RuntimeManager
	identityKey                [32]byte
	identityKeyNew             bool
	identityHasher             *IdentityHasher
	nodeWeights                *nodeweight.Matcher
	catalog                    *CatalogPort
	health                     *HealthStore
	resolver                   *ServiceResolver
	leases                     *SessionLeaseManager
	policy                     *PolicyEngine
	policyMaxAttempts          int
	manualFailure              string
	switchMargin               float64
	switchCooldown             time.Duration
	affinityMode               string
	runner                     *AttemptRunner
	defaultMode                PolicyMode
	strictLeaseTTL             time.Duration
	adaptiveLeaseTTL           time.Duration
	generation                 atomic.Uint64
	attemptSequence            atomic.Uint64
	missedObservations         atomic.Uint64
	observationStale           atomic.Uint64
	observationDuplicate       atomic.Uint64
	observationBackpressure    atomic.Uint64
	observationReducerFailure  atomic.Uint64
	observationIdentityFailure atomic.Uint64
	observationPanic           atomic.Uint64
	observationPermitBusy      atomic.Uint64
	businessTLSFailures        atomic.Uint64
	transportFailures          atomic.Uint64
	observationReducerHook     func(ObservationEvidence, []DomainEvidence) error
	observationAccess          sync.Mutex
	observationIngestor        *ObservationIngestor
	statePersistenceAccess     sync.Mutex
	statePersistenceFailures   atomic.Uint64
	stateWriter                *adaptiveStateWriter
	// runtimeAccess protects the epoch-scoped pointers below.  A source refresh
	// may publish a new health/lease/policy set while late dials from the old
	// epoch are still settling; readers take a short snapshot and the policy
	// kernel has its own close-safe lock.
	runtimeAccess         sync.RWMutex
	control               *ControlState
	switchAudit           *SwitchAuditStore
	selectionMemoryAccess sync.Mutex
	selectionMemory       map[selectionMemoryKey]selectionMemoryEntry
	catalogAccess         sync.Mutex
	preparedIdentity      *PreparedIdentity
	preparedExecution     *PreparedExecution
	runtimeIdentity       RuntimeIdentity
	appliedRevision       atomic.Uint64
	sourcePublication     *SourcePublication
	deltaAppliedTotal     atomic.Uint64
	deltaFallbackTotal    atomic.Uint64

	lifecycleAccess         sync.Mutex
	published               bool
	publishPhase            adaptivePublishPhase
	sourceDirty             bool
	postStarted             bool
	retired                 bool
	scheduler               *ProbeScheduler
	manualProbePending      atomic.Bool
	dashboardProbeRunning   atomic.Bool
	dashboardProbeCursor    atomic.Uint64
	schedulerOwner          *SchedulerCoordinator
	schedulerGen            uint64
	capabilityProvider      RefreshableProbeTargetProvider
	capabilityServiceIDs    []string
	capabilityRunner        *CapabilityProbeRunner
	capabilityControllers   map[string]*CapabilityProbeController
	capabilityRefresh       time.Duration
	capabilityTimeout       time.Duration
	capabilityQuorum        int
	capabilityCommonModeMin int
	exitIdentityStore       *ExitIdentityStore
	aiIPv6Policy            string
	aiIPv6Blocked           atomic.Uint64
	capabilityInitFailures  atomic.Uint64
	closing                 atomic.Bool
}

func (p *AdaptivePool) runtimeSnapshot() (*HealthStore, *SessionLeaseManager, *ControlState, *PolicyEngine) {
	if p == nil {
		return nil, nil, nil, nil
	}
	p.runtimeAccess.RLock()
	health, leases, control, policy := p.health, p.leases, p.control, p.policy
	p.runtimeAccess.RUnlock()
	return health, leases, control, policy
}

func (p *AdaptivePool) policySnapshot() *PolicyEngine {
	_, _, _, policy := p.runtimeSnapshot()
	return policy
}

func New(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.AdaptivePoolOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds)+len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, errors.New("adaptive_pool requires outbound or provider sources")
	}
	aiIPv6Policy := strings.ToLower(strings.TrimSpace(options.Policy.AIIPv6Policy))
	if aiIPv6Policy == "" {
		aiIPv6Policy = "allow"
	}
	if aiIPv6Policy != "allow" && aiIPv6Policy != "block" {
		return nil, errors.New("adaptive AI IPv6 policy is invalid")
	}
	probeURL := options.Probe.URL
	if probeURL == "" {
		probeURL = defaultProbeURL
	}
	probeCoverage := time.Duration(options.Probe.CoverageInterval)
	if probeCoverage <= 0 {
		probeCoverage = defaultProbeCoverage
	}
	probeTimeout := time.Duration(options.Probe.Timeout)
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	probeConcurrency := options.Probe.Concurrency
	if probeConcurrency <= 0 {
		probeConcurrency = defaultProbeConcurrency
	}
	probeQueueSize := options.Probe.QueueSize
	if probeQueueSize <= 0 {
		probeQueueSize = defaultProbeQueueSize
	}
	var capabilityProvider RefreshableProbeTargetProvider
	var capabilityServiceIDs []string
	capabilityRefresh := time.Duration(options.Capability.RefreshInterval)
	capabilityTimeout := time.Duration(options.Capability.Timeout)
	capabilityQuorum := options.Capability.Quorum
	capabilityCommonModeMin := options.Capability.CommonModeMinNodes
	if options.Capability.Enabled {
		if capabilityRefresh < 0 || capabilityTimeout < 0 || capabilityQuorum < 0 || capabilityCommonModeMin < 0 {
			return nil, errors.New("adaptive capability policy is invalid")
		}
		if capabilityRefresh == 0 {
			capabilityRefresh = defaultCapabilityRefresh
		}
		if capabilityTimeout == 0 {
			capabilityTimeout = defaultCapabilityTimeout
		}
		if capabilityQuorum == 0 {
			if options.Capability.BuiltinYouTubeTLS || options.Capability.BuiltinExitIdentity {
				capabilityQuorum = 1
			} else {
				capabilityQuorum = 2
			}
		}
		if capabilityCommonModeMin == 0 {
			capabilityCommonModeMin = 2
		}
		if capabilityCommonModeMin < 2 {
			return nil, errors.New("adaptive capability common-mode threshold is invalid")
		}
		if options.Capability.BuiltinAIServiceTLS {
			// Sealed: keep the JSON field for migration, but refuse production enablement.
			return nil, errors.New("adaptive builtin_ai_service_tls is sealed and disabled; use builtin_youtube_tls, builtin_exit_identity, or a signed manifest")
		}
		if options.Capability.BuiltinYouTubeTLS || options.Capability.BuiltinExitIdentity {
			if capabilityQuorum != 1 {
				return nil, errors.New("adaptive builtin capability requires quorum 1")
			}
			if options.Capability.ManifestURL != "" || len(options.Capability.TrustedKeys) != 0 {
				return nil, errors.New("adaptive builtin capability cannot use manifest trust options")
			}
			builtinProvider, providerErr := NewBuiltinCapabilityTargetProvider(nil, options.Capability.BuiltinYouTubeTLS, false, options.Capability.BuiltinExitIdentity)
			if providerErr != nil {
				return nil, errors.New("adaptive builtin capability is invalid")
			}
			capabilityProvider = builtinProvider
			capabilityServiceIDs = builtinProvider.ServiceIDs()
		} else {
			trustedKeys, keyErr := parseCapabilityTrustedKeys(options.Capability.TrustedKeys)
			if keyErr != nil {
				return nil, keyErr
			}
			fetcher, fetcherErr := NewHTTPSignedProbeTargetFetcher(options.Capability.ManifestURL, nil)
			if fetcherErr != nil {
				return nil, errors.New("adaptive capability manifest endpoint is invalid")
			}
			trustedProvider, providerErr := NewTrustedYouTubeTargetProvider(nil, fetcher, trustedKeys)
			if providerErr != nil {
				return nil, errors.New("adaptive capability trust configuration is invalid")
			}
			capabilityProvider = trustedProvider
			capabilityServiceIDs = []string{youtubeProbeServiceID}
		}
	}
	var exitIdentityStore *ExitIdentityStore
	if options.Capability.Enabled && options.Capability.BuiltinExitIdentity {
		identityStore, identityErr := NewExitIdentityStore(tag)
		if identityErr != nil {
			return nil, identityErr
		}
		exitIdentityStore = identityStore
	}
	stateRetention := time.Duration(options.State.Retention)
	if stateRetention <= 0 {
		stateRetention = defaultStateRetention
	}
	stateMaxEntries := options.State.MaxEntries
	if stateMaxEntries <= 0 {
		stateMaxEntries = defaultStateMaxEntries
	}
	defaultMode := PolicyMode(options.Policy.Default)
	if defaultMode == "" {
		defaultMode = ModeAdaptive
	}
	if defaultMode != ModeAdaptive && defaultMode != ModeStrictAffinity && defaultMode != ModeLatency && defaultMode != ModeBulk {
		return nil, E.New("unknown adaptive default policy: ", defaultMode)
	}
	strictLeaseTTL := time.Duration(options.Policy.StrictLeaseTTL)
	if strictLeaseTTL <= 0 {
		strictLeaseTTL = defaultStrictLeaseTTL
	}
	adaptiveLeaseTTL := time.Duration(options.Policy.AdaptiveLeaseTTL)
	if adaptiveLeaseTTL <= 0 {
		adaptiveLeaseTTL = defaultAdaptiveLeaseTTL
	}
	maxLeases := options.Policy.MaxLeases
	if maxLeases <= 0 {
		maxLeases = defaultMaxLeases
	}
	maxAttempts := options.Policy.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	switchMargin := defaultSwitchMargin
	if options.Policy.SwitchMargin != nil {
		switchMargin = *options.Policy.SwitchMargin
	}
	switchCooldown := time.Duration(options.Policy.SwitchCooldown)
	if options.Policy.SwitchCooldown == 0 {
		switchCooldown = defaultSwitchCooldown
	}
	affinityMode := options.Policy.AffinityMode
	switch affinityMode {
	case "", "service", "disabled":
	default:
		return nil, E.New("unknown adaptive affinity_mode: ", affinityMode)
	}
	attemptTimeout := time.Duration(options.Policy.AttemptTimeout)
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}
	hedgeDelay := time.Duration(options.Policy.HedgeDelay)
	if hedgeDelay <= 0 {
		hedgeDelay = defaultHedgeDelay
	}
	manualFailure := options.Policy.ManualFailure
	if manualFailure == "" {
		manualFailure = "fallback"
	}
	if manualFailure != "fallback" && manualFailure != "fail_closed" {
		return nil, E.New("unknown adaptive manual_failure: ", manualFailure)
	}
	statePath := options.State.Path
	if statePath == "" {
		statePath = "adaptive-state-" + safeFileName(tag)
	}
	statePath = filemanager.BasePath(ctx, statePath)
	identityKey, keyNew, err := loadOrPrepareIdentityKey(statePath + ".key")
	if err != nil {
		return nil, err
	}
	hasher, err := NewIdentityHasher(identityKey[:])
	if err != nil {
		return nil, err
	}
	health := NewHealthStore(stateRetention, stateMaxEntries)
	resolver := NewServiceResolver(hasher, defaultMode)
	manualExclude, err := nodefilter.New([]string(options.ExcludeNodes))
	if err != nil {
		return nil, err
	}
	weightRules := make([]nodeweight.Rule, len(options.NodeWeights))
	for index, rule := range options.NodeWeights {
		weightRules[index] = nodeweight.Rule{Match: rule.Match, Weight: rule.Weight}
	}
	nodeWeights, err := nodeweight.New(weightRules)
	if err != nil {
		return nil, err
	}
	sourceRuntime, err := NewA48SourceRuntimeV1(ctx, hasher, SourceRuntimeConfig{
		StaticTags:    options.Outbounds,
		ProviderTags:  options.Providers,
		UseAll:        options.UseAllProviders,
		Include:       (*regexp.Regexp)(options.Include),
		Exclude:       (*regexp.Regexp)(options.Exclude),
		ManualExclude: manualExclude,
	})
	if err != nil {
		return nil, err
	}
	runtimeManager := service.PtrFromContext[RuntimeManager](ctx)
	if runtimeManager == nil {
		runtimeManager = NewRuntimeManager()
	}
	// Register before looking up the coordinator so an old drain waiter cannot
	// delete it between lookup and publication of this pool's user reference.
	runtimeManager.RegisterGroup(tag)
	catalog := NewCatalogPort()
	pool := &AdaptivePool{
		Adapter:                 outbound.NewAdapter(C.TypeAdaptivePool, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                     ctx,
		logger:                  logger,
		source:                  sourceRuntime,
		shadow:                  options.Shadow,
		probeURL:                probeURL,
		probeCoverage:           probeCoverage,
		probeTimeout:            probeTimeout,
		probeConcurrency:        probeConcurrency,
		probeQueueSize:          probeQueueSize,
		capabilityProvider:      capabilityProvider,
		capabilityServiceIDs:    capabilityServiceIDs,
		capabilityRefresh:       capabilityRefresh,
		capabilityTimeout:       capabilityTimeout,
		capabilityQuorum:        capabilityQuorum,
		capabilityCommonModeMin: capabilityCommonModeMin,
		exitIdentityStore:       exitIdentityStore,
		aiIPv6Policy:            aiIPv6Policy,
		probeRunner:             urltest.URLTest,
		statePath:               statePath,
		groupID:                 tag,
		runtimeManager:          runtimeManager,
		schedulerOwner:          runtimeManager.SchedulerCoordinator(tag),
		identityKey:             identityKey,
		identityKeyNew:          keyNew,
		identityHasher:          hasher,
		nodeWeights:             nodeWeights,
		catalog:                 catalog,
		health:                  health,
		resolver:                resolver,
		leases:                  NewSessionLeaseManager(maxLeases),
		policy: NewPolicyEngine(health, maxAttempts, manualFailure).
			BindNodeWeights(nodeWeights).
			BindSwitchStability(switchMargin, switchCooldown).
			BindAffinityMode(affinityMode),
		policyMaxAttempts:   maxAttempts,
		manualFailure:       manualFailure,
		switchMargin:        switchMargin,
		switchCooldown:      switchCooldown,
		affinityMode:        affinityMode,
		runner:              NewAttemptRunner(attemptTimeout, hedgeDelay, catalog),
		defaultMode:         defaultMode,
		strictLeaseTTL:      strictLeaseTTL,
		adaptiveLeaseTTL:    adaptiveLeaseTTL,
		control:             new(ControlState),
		switchAudit:         NewSwitchAuditStore(),
		selectionMemory:     make(map[selectionMemoryKey]selectionMemoryEntry),
		observationIngestor: NewObservationIngestor(nil, nil, 10*time.Minute, 16384),
	}
	pool.policy.BindBulkSequence(&pool.control.bulkSequence)
	pool.loadPersistentState()
	return pool, nil
}

func (p *AdaptivePool) Start() error {
	// Configuration checks construct outbounds but do not start them. Starting
	// the writer in New leaked one goroutine and retained the entire validation
	// Box on every reload because an unstarted outbound manager has nothing to
	// close. Background ownership begins only with the real runtime lifecycle.
	if p.stateWriter == nil {
		p.stateWriter = newAdaptiveStateWriter(p)
	}
	if err := p.source.Start(p.onSourceUpdated); err != nil {
		p.stateWriter.Close()
		p.stateWriter = nil
		return err
	}
	if err := p.rebuild(); err != nil {
		_ = p.source.Close()
		p.stateWriter.Close()
		p.stateWriter = nil
		return err
	}
	return nil
}

func (p *AdaptivePool) PostStart() error {
	p.lifecycleAccess.Lock()
	p.postStarted = true
	p.startSchedulerLocked()
	p.lifecycleAccess.Unlock()
	return nil
}

func (p *AdaptivePool) OnRuntimeEpochPublish() error {
	p.lifecycleAccess.Lock()
	if p.publishPhase != publishPhasePrepared {
		p.lifecycleAccess.Unlock()
		return errors.New("adaptive runtime epoch is not in prepared phase")
	}
	if p.identityKeyNew {
		p.lifecycleAccess.Unlock()
		return errors.New("adaptive identity key is not durable")
	}
	p.publishPhase = publishPhasePublishing
	p.lifecycleAccess.Unlock()

	p.catalogAccess.Lock()
	preparedIdentity := p.preparedIdentity
	preparedExecution := p.preparedExecution
	if preparedIdentity == nil || preparedExecution == nil {
		p.lifecycleAccess.Lock()
		if p.publishPhase == publishPhasePublishing {
			p.publishPhase = publishPhasePrepared
		}
		p.lifecycleAccess.Unlock()
		p.catalogAccess.Unlock()
		return errors.New("adaptive runtime epoch was not prepared")
	}
	shared, identity, err := preparedIdentity.Commit()
	if err != nil {
		// A stale/consumed preparation can never be committed again. Drop it
		// while holding the catalog lock so the next source rebuild creates a
		// fresh optimistic transaction instead of leaving the pool stuck in the
		// prepared phase.
		p.preparedIdentity = nil
		p.preparedExecution = nil
		p.lifecycleAccess.Lock()
		if p.publishPhase == publishPhasePublishing {
			p.publishPhase = publishPhasePrepared
		}
		p.lifecycleAccess.Unlock()
		p.catalogAccess.Unlock()
		return err
	}
	p.runtimeIdentity = identity
	var oldHealth *HealthStore
	var oldLeases *SessionLeaseManager
	var oldControl *ControlState
	var oldPolicy *PolicyEngine
	publishedState := false
	p.lifecycleAccess.Lock()
	if p.publishPhase == publishPhasePublishing {
		newPolicy := NewPolicyEngine(shared.health, p.policyMaxAttempts, p.manualFailure).
			BindNodeWeights(p.nodeWeights).
			BindSwitchStability(p.switchMargin, p.switchCooldown).
			BindAffinityMode(p.affinityMode).
			BindBulkSequence(&shared.control.bulkSequence)
		p.runtimeAccess.Lock()
		oldHealth, oldLeases, oldControl = p.health, p.leases, p.control
		oldPolicy = p.policy
		p.health = shared.health
		p.leases = shared.leases
		p.control = shared.control
		p.policy = newPolicy
		p.runtimeAccess.Unlock()
		publishedState = true
	}
	p.lifecycleAccess.Unlock()
	if !publishedState {
		_ = preparedIdentity.Rollback()
		p.runtimeIdentity = RuntimeIdentity{}
		p.preparedIdentity = nil
		p.preparedExecution = nil
		p.catalogAccess.Unlock()
		return errors.New("adaptive runtime epoch publish was superseded")
	}
	if err = p.persistStateDurable(); err != nil {
		_ = preparedIdentity.Rollback()
		p.runtimeIdentity = RuntimeIdentity{}
		p.preparedIdentity = nil
		p.preparedExecution = nil
		p.runtimeAccess.Lock()
		currentPolicy := p.policy
		p.health = oldHealth
		p.leases = oldLeases
		p.control = oldControl
		p.policy = oldPolicy
		p.runtimeAccess.Unlock()
		if currentPolicy != nil && currentPolicy != oldPolicy {
			currentPolicy.Close()
		}
		p.lifecycleAccess.Lock()
		if p.publishPhase == publishPhasePublishing {
			p.publishPhase = publishPhasePrepared
		}
		p.lifecycleAccess.Unlock()
		p.catalogAccess.Unlock()
		return errors.New("adaptive identity state is not durable")
	}
	if oldPolicy != nil {
		oldPolicy.Close()
	}
	p.catalog.CommitPrepared(preparedExecution)
	p.catalogAccess.Unlock()
	return nil
}

func (p *AdaptivePool) OnRuntimeEpochPublishCommit() {
	p.catalogAccess.Lock()
	identity := cloneRuntimeIdentity(p.runtimeIdentity)
	p.preparedIdentity = nil
	p.preparedExecution = nil
	p.catalogAccess.Unlock()
	p.applyCommittedTransitions(identity)
	p.lifecycleAccess.Lock()
	if p.publishPhase != publishPhasePublishing {
		p.lifecycleAccess.Unlock()
		return
	}
	p.publishPhase = publishPhaseActive
	p.published = true
	dirty := p.sourceDirty
	p.sourceDirty = false
	p.startSchedulerLocked()
	p.lifecycleAccess.Unlock()
	if dirty {
		if err := p.rebuild(); err != nil && p.logger != nil {
			p.logger.Error("replay adaptive source update after epoch publish: ", err)
		}
	}
}

func (p *AdaptivePool) OnRuntimeEpochPublishRollback() {
	p.lifecycleAccess.Lock()
	p.publishPhase = publishPhaseRollingBack
	p.published = false
	p.sourceDirty = false
	p.lifecycleAccess.Unlock()
	p.catalogAccess.Lock()
	prepared := p.preparedIdentity
	epochID := p.runtimeIdentity.EpochID
	p.runtimeIdentity = RuntimeIdentity{}
	p.catalogAccess.Unlock()
	if prepared != nil {
		_ = prepared.Rollback()
	}
	p.catalog.RollbackEpoch(epochID)
	_ = p.persistStateDurable()
	p.OnRuntimeEpochRetire()
}

func (p *AdaptivePool) OnRuntimeEpochRetire() {
	p.lifecycleAccess.Lock()
	p.retired = true
	p.publishPhase = publishPhaseRetired
	// D/C: single controller map is the only ownership path.
	capabilityControllers := p.capabilityControllers
	p.capabilityControllers = nil
	scheduler := p.scheduler
	p.scheduler = nil
	coordinator := p.schedulerOwner
	ownerGeneration := p.schedulerGen
	p.schedulerGen = 0
	p.lifecycleAccess.Unlock()
	closeCapabilityControllers(capabilityControllers)
	p.catalogAccess.Lock()
	epochID := p.runtimeIdentity.EpochID
	p.catalogAccess.Unlock()
	if epochID != 0 {
		p.runtimeManager.RetireEpoch(p.groupID, epochID)
	}
	if coordinator != nil && epochID != 0 && ownerGeneration != 0 {
		coordinator.Release(epochID, ownerGeneration)
	}
	if scheduler != nil {
		_ = scheduler.Close()
	}
	// Drop bounded selection/audit views on retire. Observation transactions
	// remain alive until epoch leases drain so late real failures are not lost.
	if _, _, _, policy := p.runtimeSnapshot(); policy != nil {
		policy.Clear()
	}
	if p.switchAudit != nil {
		p.switchAudit.Clear()
	}
	p.clearSelectionMemory()
}

func (p *AdaptivePool) Close() error {
	if !p.closing.CompareAndSwap(false, true) {
		return nil
	}
	p.OnRuntimeEpochRetire()
	p.runtimeAccess.Lock()
	policy := p.policy
	p.policy = nil
	p.runtimeAccess.Unlock()
	if policy != nil {
		policy.Close()
	}
	if p.source != nil {
		_ = p.source.Close()
	}
	if p.stateWriter != nil {
		p.stateWriter.Close()
	}
	p.runtimeManager.UnregisterGroup(p.groupID)
	return nil
}

func (p *AdaptivePool) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (p *AdaptivePool) Now() string {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		return ""
	}
	control.access.RLock()
	defer control.access.RUnlock()
	if p.shadow {
		return "shadow"
	}
	return control.latestTag
}

func (p *AdaptivePool) All() []string {
	snapshot := p.catalog.load()
	if snapshot == nil {
		return nil
	}
	tags := make([]string, len(snapshot.Candidates))
	for index, candidate := range snapshot.Candidates {
		tags[index] = candidate.PrimaryTag
	}
	return tags
}

func (p *AdaptivePool) SelectAdaptiveOutbound(tag string) bool {
	return p.selectAdaptiveOutbound(tag, nil)
}

func (p *AdaptivePool) SelectAdaptiveOutboundAt(tag string, expected uint64) bool {
	return p.selectAdaptiveOutbound(tag, &expected)
}

func (p *AdaptivePool) selectAdaptiveOutbound(tag string, expected *uint64) bool {
	snapshot := p.catalog.load()
	if snapshot == nil {
		return false
	}
	nodeID, loaded := snapshot.AliasToID[tag]
	if !loaded {
		return false
	}
	_, leases, control, _ := p.runtimeSnapshot()
	if control == nil {
		control = new(ControlState)
		p.runtimeAccess.Lock()
		if p.control == nil {
			p.control = control
		} else {
			control = p.control
		}
		p.runtimeAccess.Unlock()
	}
	control.access.Lock()
	if expected != nil && control.revision.Load() != *expected {
		control.access.Unlock()
		return false
	}
	control.pinned = nodeID
	control.pinnedTag = tag
	control.revision.Add(1)
	control.access.Unlock()
	if leases != nil {
		leases.Clear()
	}
	p.persistState()
	return true
}

func (p *AdaptivePool) ClearAdaptiveSelection() {
	_ = p.clearAdaptiveSelection(nil)
}

func (p *AdaptivePool) ClearAdaptiveSelectionAt(expected uint64) bool {
	return p.clearAdaptiveSelection(&expected)
}

func (p *AdaptivePool) clearAdaptiveSelection(expected *uint64) bool {
	_, leases, control, _ := p.runtimeSnapshot()
	if control == nil {
		control = new(ControlState)
		p.runtimeAccess.Lock()
		if p.control == nil {
			p.control = control
		} else {
			control = p.control
		}
		p.runtimeAccess.Unlock()
	}
	control.access.Lock()
	if expected != nil && control.revision.Load() != *expected {
		control.access.Unlock()
		return false
	}
	control.pinned = NodeID{}
	control.pinnedTag = ""
	control.revision.Add(1)
	control.access.Unlock()
	if leases != nil {
		leases.Clear()
	}
	p.persistState()
	return true
}

func (p *AdaptivePool) AdaptiveSelectionRevision() uint64 {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		return 0
	}
	return control.revision.Load()
}

func (p *AdaptivePool) SetAdaptiveServiceOverride(serviceID, mode string, ttl time.Duration, expectedRevision uint64) error {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		return errors.New("adaptive control revision conflict")
	}
	control.access.Lock()
	if control.revision.Load() != expectedRevision {
		control.access.Unlock()
		return errors.New("adaptive control revision conflict")
	}
	if err := p.resolver.SetOverride(serviceID, PolicyMode(mode), ttl, time.Now()); err != nil {
		control.access.Unlock()
		return err
	}
	control.revision.Add(1)
	control.access.Unlock()
	p.persistState()
	return nil
}

func (p *AdaptivePool) ClearAdaptiveServiceOverride(serviceID string, expectedRevision uint64) error {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		return errors.New("adaptive control revision conflict")
	}
	control.access.Lock()
	if control.revision.Load() != expectedRevision {
		control.access.Unlock()
		return errors.New("adaptive control revision conflict")
	}
	if !p.resolver.ClearOverride(serviceID) {
		control.access.Unlock()
		return errors.New("adaptive service override not found")
	}
	control.revision.Add(1)
	control.access.Unlock()
	p.persistState()
	return nil
}

func (p *AdaptivePool) AdaptiveServiceOverrides() []adapter.AdaptiveServiceOverride {
	overrides := p.resolver.Overrides(time.Now())
	result := make([]adapter.AdaptiveServiceOverride, len(overrides))
	for index, override := range overrides {
		result[index] = adapter.AdaptiveServiceOverride{ServiceID: override.ServiceID, Mode: string(override.Mode), ExpiresAt: override.ExpiresAt}
	}
	return result
}

func (*AdaptivePool) DisablePreMatch() {}

func (p *AdaptivePool) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if p.shadow {
		return nil, errors.New("adaptive_pool is running in shadow mode and cannot carry traffic")
	}
	if err := p.waitUntilPublished(ctx); err != nil {
		return nil, err
	}
	_, leases, _, policy := p.runtimeSnapshot()
	if leases == nil || policy == nil {
		return nil, errors.New("adaptive pool runtime state is unavailable")
	}
	metadata := adapter.ContextFrom(ctx)
	serviceContext := p.resolver.Resolve(metadata, destination, N.NetworkName(network))
	if p.applyAIIPv6Policy(serviceContext, destination, metadata) {
		return nil, errors.New("adaptive AI IPv6 destination blocked by policy")
	}
	snapshot := p.catalog.load()
	var lease SessionLease
	var reservation *LeaseReservation
	var err error
	if modeUsesLease(serviceContext.Mode) {
		lease, reservation, err = leases.Reserve(ctx, serviceContext.Session, time.Now())
		if err != nil {
			return nil, err
		}
	}
	var leasePointer *SessionLease
	if modeUsesLease(serviceContext.Mode) && reservation == nil {
		leasePointer = &lease
	}
	pinned := p.pinnedNodeID()
	plan, err := policy.Plan(snapshot, serviceContext, leasePointer, pinned)
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	startedAt := time.Now()
	conn, candidate, err := p.runner.Dial(ctx, network, destination, plan, p.beginDialAttempt(snapshot, serviceContext, destination))
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	if modeUsesLease(serviceContext.Mode) {
		previous := NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}
		ttl := p.leaseTTL(serviceContext.Mode)
		if reservation != nil {
			reservation.CommitHandle(candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
		} else if lease.NodeID != candidate.ID || lease.NodeSlot != candidate.Handle.Slot || lease.NodeVersion != candidate.Handle.Version {
			leases.ReplaceHandle(serviceContext.Session, NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}, candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
		} else {
			leases.RenewHandle(serviceContext.Session, candidate.Handle, ttl, time.Now())
		}
		p.switchAudit.RecordSelection(serviceContext.Session, serviceContext.ID, previous, candidate, plan.Reason, time.Now())
	}
	// Business TLS/write failures must charge the family that actually connected.
	// (Selection sticky is by node handle, not path — do not invent path sticky.)
	if path := observedHealthTransport(serviceContext, destination, conn.RemoteAddr()); path != "" {
		serviceContext.HealthTransport = path
	}
	p.rememberPolicySelectionWithReason(serviceContext, candidate, plan.Reason)
	p.setLatest(candidate.PrimaryTag)
	if candidate.PrimaryTag != "" {
		if metadata := adapter.ContextFrom(ctx); metadata != nil {
			metadata.AppendRealOutbound(candidate.PrimaryTag)
		}
	}
	return p.wrapBusinessConn(conn, snapshot, candidate, serviceContext, startedAt), nil
}

func (p *AdaptivePool) applyAIIPv6Policy(service ServiceContext, destination M.Socksaddr, metadata *adapter.InboundContext) bool {
	if p == nil || p.aiIPv6Policy != "block" || !isAIIdentityService(service.ID) {
		return false
	}
	if destination.Addr.IsValid() && destination.Addr.Is6() && !destination.Addr.Is4In6() {
		p.aiIPv6Blocked.Add(1)
		return true
	}
	if metadata == nil || len(metadata.DestinationAddresses) == 0 {
		return false
	}
	filtered := metadata.DestinationAddresses[:0]
	removed := false
	for _, address := range metadata.DestinationAddresses {
		if address.Is6() && !address.Is4In6() {
			removed = true
			continue
		}
		filtered = append(filtered, address)
	}
	if !removed {
		return false
	}
	p.aiIPv6Blocked.Add(1)
	metadata.DestinationAddresses = filtered
	return len(filtered) == 0
}

func isAIIdentityService(serviceID string) bool {
	switch serviceID {
	case "openai_api", "chatgpt_web", "claude", "gemini", "google_account", "apple_account", "microsoft_account", "cloudflare_challenge":
		return true
	default:
		return false
	}
}

func (p *AdaptivePool) waitUntilPublished(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	phase := p.publishPhase
	published := p.published
	retired := p.retired
	p.lifecycleAccess.Unlock()
	// Zero is used by isolated/unit pools which do not participate in the
	// runtime epoch publication protocol.
	if phase == 0 || published {
		return nil
	}
	if retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired {
		return errors.New("adaptive pool runtime epoch is unavailable")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("adaptive pool runtime epoch publication timed out")
		case <-ticker.C:
			p.lifecycleAccess.Lock()
			published = p.published
			phase = p.publishPhase
			retired = p.retired
			p.lifecycleAccess.Unlock()
			if published {
				return nil
			}
			if retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired {
				return errors.New("adaptive pool runtime epoch is unavailable")
			}
		}
	}
}

func (p *AdaptivePool) beginDialAttempt(snapshot *ExecutionSnapshot, service ServiceContext, destination M.Socksaddr) AttemptBegin {
	if snapshot == nil || snapshot.RuntimeEpochID == 0 || snapshot.CatalogRevision == 0 || p.runtimeManager == nil {
		return nil
	}
	// Prefer destination IP family when known (literal dial); */any remains until
	// a live RemoteAddr is available on completion.
	path := observedHealthTransport(service, destination, nil)
	return func(candidate Candidate, permit *AttemptPermit) (AttemptComplete, error) {
		attempt, err := p.beginObservationAttempt(snapshot, candidate, permit, service.Transport, path)
		if err != nil {
			return nil, err
		}
		return func(result DialAttemptResult) {
			p.completeTransportAttempt(attempt, service, destination, result)
		}, nil
	}
}

func (p *AdaptivePool) completeTransportAttempt(attempt *observationAttempt, service ServiceContext, destination M.Socksaddr, result DialAttemptResult) {
	defer attempt.lease.Release()
	attemptErr := result.Err
	delay := result.Delay
	deferred := result.Deferred
	implementationFailure := result.Panic
	evidence := attempt.evidence
	// Pin the health ledger to the address family that was actually dialed when
	// known; otherwise a single dual-stack failure collapses into tcp/any and
	// falsely poisons the peer family.
	evidence.NetworkPath = observedHealthTransport(service, destination, result.RemoteAddr)
	if evidence.NetworkPath == "" {
		evidence.NetworkPath = attempt.evidence.NetworkPath
	}
	evidence.Source = SourceDial
	evidence.Confidence = ConfidenceHigh
	evidence.Delay = delay
	if attempt.reducer != nil && attempt.reducer.Store != nil {
		evidence.At = attempt.reducer.Store.Now()
	} else if health, _, _, _ := p.runtimeSnapshot(); health != nil {
		evidence.At = health.Now()
	} else {
		evidence.At = time.Now()
	}
	evidence.Reason = errorReason(attemptErr)
	switch {
	case deferred || errors.Is(attemptErr, context.Canceled):
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeDeferred, FailureCanceled
	case implementationFailure:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageProxyTunnel, OutcomeFailure, FailureProtocol
	case attemptErr == nil:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeSuccess, FailureNone
	case errors.Is(attemptErr, context.DeadlineExceeded) || isTimeoutError(attemptErr):
		// Timeouts start as medium (quality). After enough medium timeouts the
		// ledger becomes HealthUnreachable (see observeQualityLocked) so the
		// node leaves Plan — without treating one slow RTT as a hard open.
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeFailure, FailureTimeout
		evidence.Confidence = ConfidenceMedium
	default:
		evidence.Stage, evidence.Outcome, evidence.Failure = StageDestinationTransport, OutcomeFailure, FailureConnect
	}
	disposition, publishErr := PublishSettledObservationGuarded(p.sharedObservationIngestor(), attempt.guard, evidence, attempt.reducer)
	p.recordObservationResult(disposition, publishErr)
	if publishErr == nil && disposition == IngestAccepted && evidence.Outcome == OutcomeFailure && evidence.Stage == StageDestinationTransport {
		p.transportFailures.Add(1)
		path := evidence.NetworkPath
		if snapshot := p.catalog.load(); snapshot != nil {
			if candidate, loaded := snapshot.Candidate(evidence.Handle.NodeID); loaded {
				p.switchAudit.RecordFailure(service.Session, service.ID, candidate, evidence.Failure, "destination_transport", evidence.At)
				p.recordFailureMemory(candidate, evidence.Failure, service.ID, path)
			}
		}
		health := attempt.reducer.Store
		status := health.StatusHandle(evidence.Handle, DomainTransport, path, "")
		policy := p.policySnapshot()
		earlyFailure := policy != nil && policy.ForgetSelectionAfterEarlyFailure(service, evidence.Handle, evidence.At)
		// Invalidate lease on breaker open OR quality-escalated unreachable (timeout blackhole).
		pathDead := status.Breaker == BreakerOpen || status.Breaker == BreakerCooldown || status.Health == HealthUnreachable
		if modeUsesLease(service.Mode) && (earlyFailure || pathDead) {
			if _, leases, _, _ := p.runtimeSnapshot(); leases != nil {
				leases.Invalidate(service.Session, evidence.Handle.NodeID)
			}
			p.persistState()
		}
		p.scheduleFailureProbe(evidence.Handle)
	}
}

// scheduleFailureProbe feeds real connection failures back into the existing
// scheduler. Submit coalesces an on-demand probe with an active or pending
// periodic probe, so an outage cannot create a second scheduler or an
// unbounded probe fan-out.

type observationAttempt struct {
	lease    *RuntimeEpochIdentityLease
	evidence ObservationEvidence
	guard    ObservationIdentityGuard
	reducer  *HealthObservationReducer
}

func (p *AdaptivePool) beginObservationAttempt(snapshot *ExecutionSnapshot, candidate Candidate, permit *AttemptPermit, transport string, networkPath ...string) (*observationAttempt, error) {
	health, _, _, _ := p.runtimeSnapshot()
	if health == nil {
		return nil, errors.New("adaptive health store is unavailable")
	}
	lease, err := p.runtimeManager.AcquireEpoch(p.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		return nil, err
	}
	evidence := ObservationEvidence{RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation, Handle: candidate.Handle, AttemptID: AttemptID(p.attemptSequence.Add(1)), Transport: transport}
	if len(networkPath) > 0 {
		evidence.NetworkPath = networkPath[0]
	}
	guard := RuntimeEpochObservationGuard{Lease: lease}
	reducer := &HealthObservationReducer{Store: health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: p.observationReducerHook}
	return &observationAttempt{lease: lease, evidence: evidence, guard: guard, reducer: reducer}, nil
}

func (p *AdaptivePool) sharedObservationIngestor() *ObservationIngestor {
	p.observationAccess.Lock()
	if p.observationIngestor == nil {
		p.observationIngestor = NewObservationIngestor(nil, nil, 10*time.Minute, 16384)
	}
	ingestor := p.observationIngestor
	p.observationAccess.Unlock()
	return ingestor
}

func (p *AdaptivePool) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if p.shadow {
		return nil, errors.New("adaptive_pool is running in shadow mode and cannot carry traffic")
	}
	if err := p.waitUntilPublished(ctx); err != nil {
		return nil, err
	}
	_, leases, _, policy := p.runtimeSnapshot()
	if leases == nil || policy == nil {
		return nil, errors.New("adaptive pool runtime state is unavailable")
	}
	metadata := adapter.ContextFrom(ctx)
	serviceContext := p.resolver.Resolve(metadata, destination, N.NetworkUDP)
	if p.applyAIIPv6Policy(serviceContext, destination, metadata) {
		return nil, errors.New("adaptive AI IPv6 destination blocked by policy")
	}
	snapshot := p.catalog.load()
	var lease SessionLease
	var reservation *LeaseReservation
	var err error
	if modeUsesLease(serviceContext.Mode) {
		lease, reservation, err = leases.Reserve(ctx, serviceContext.Session, time.Now())
		if err != nil {
			return nil, err
		}
	}
	var leasePointer *SessionLease
	if modeUsesLease(serviceContext.Mode) && reservation == nil {
		leasePointer = &lease
	}
	plan, err := policy.Plan(snapshot, serviceContext, leasePointer, p.pinnedNodeID())
	if err != nil {
		if reservation != nil {
			reservation.Abort()
		}
		return nil, err
	}
	var attemptErrors []error
	for _, candidate := range plan.Candidates {
		permit, allowed := plan.TryAcquireAttemptPermit(candidate.ID, time.Time{})
		if !allowed {
			attemptErrors = append(attemptErrors, E.Cause(ErrBreakerAttemptDeferred, "adaptive UDP candidate ", candidate.PrimaryTag))
			continue
		}
		var observation *observationAttempt
		if snapshot != nil && snapshot.RuntimeEpochID != 0 && snapshot.CatalogRevision != 0 && p.runtimeManager != nil {
			observation, err = p.beginObservationAttempt(snapshot, candidate, permit, N.NetworkUDP, observedHealthTransport(serviceContext, destination, nil))
			if err != nil {
				permit.ReleaseDeferred()
				attemptErrors = append(attemptErrors, E.Cause(err, "prepare adaptive UDP observation ", candidate.PrimaryTag))
				continue
			}
		}
		startedAt := time.Now()
		settle := func(attemptErr error, deferred bool, remote net.Addr) {
			if observation == nil {
				permit.ReleaseDeferred()
				return
			}
			p.completeTransportAttempt(observation, serviceContext, destination, DialAttemptResult{
				Candidate: candidate, Err: attemptErr, Delay: time.Since(startedAt), Deferred: deferred, RemoteAddr: remote,
			})
		}
		attemptCtx, cancel := context.WithTimeout(ctx, p.runner.attemptTimeout)
		var packetConn net.PacketConn
		var attemptErr error
		execution, loaded := p.catalog.AcquireExecution(ExecutionToken{RuntimeEpochID: plan.RuntimeEpochID, CatalogRevision: plan.CatalogRevision, Handle: candidate.Handle})
		if !loaded {
			attemptErr = ErrExecutionBindingUnavailable
		} else {
			packetConn, attemptErr = execution.Port.ListenPacket(attemptCtx, destination)
			execution.Release()
		}
		parentCanceled := ctx.Err() != nil
		cancel()
		if attemptErr == nil && packetConn == nil {
			attemptErr = errors.New("adaptive outbound returned nil packet connection")
		}
		if attemptErr == nil && parentCanceled {
			_ = packetConn.Close()
			attemptErr = ctx.Err()
		}
		if parentCanceled {
			settle(attemptErr, true, nil)
			attemptErrors = append(attemptErrors, attemptErr)
			continue
		}
		if attemptErr != nil {
			settle(attemptErr, false, nil)
			attemptErrors = append(attemptErrors, E.Cause(attemptErr, "adaptive UDP candidate ", candidate.PrimaryTag))
			continue
		}
		// ListenPacket only proves the outbound accepted the bind. Do NOT publish
		// high-confidence transport success here — that would half-open-recover a
		// path before any datagram is answered. Real path evidence comes from
		// wrapBusinessPacketConn Read* (or active dns_health). Deferred settles the
		// dial permit without writing health success.
		settle(nil, true, nil)
		if modeUsesLease(serviceContext.Mode) {
			previous := NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}
			ttl := p.leaseTTL(serviceContext.Mode)
			if reservation != nil {
				reservation.CommitHandle(candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
			} else if lease.NodeID != candidate.ID || lease.NodeSlot != candidate.Handle.Slot || lease.NodeVersion != candidate.Handle.Version {
				leases.ReplaceHandle(serviceContext.Session, NodeHandle{NodeID: lease.NodeID, Slot: lease.NodeSlot, Version: lease.NodeVersion}, candidate.Handle, serviceContext.ID, serviceContext.Mode, ttl, time.Now())
			} else {
				leases.RenewHandle(serviceContext.Session, candidate.Handle, ttl, time.Now())
			}
			p.switchAudit.RecordSelection(serviceContext.Session, serviceContext.ID, previous, candidate, plan.Reason, time.Now())
		}
		if path := observedHealthTransport(serviceContext, destination, nil); path != "" {
			serviceContext.HealthTransport = path
		}
		p.rememberPolicySelectionWithReason(serviceContext, candidate, plan.Reason)
		p.setLatest(candidate.PrimaryTag)
		if candidate.PrimaryTag != "" {
			if metadata := adapter.ContextFrom(ctx); metadata != nil {
				metadata.AppendRealOutbound(candidate.PrimaryTag)
			}
		}
		return p.wrapBusinessPacketConn(packetConn, snapshot, candidate, serviceContext, startedAt), nil
	}
	if reservation != nil {
		reservation.Abort()
	}
	if len(attemptErrors) == 0 {
		return nil, ErrNoEligibleCandidates
	}
	return nil, errors.Join(attemptErrors...)
}

func (p *AdaptivePool) URLTest(ctx context.Context) (map[string]uint16, error) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return nil, errors.New("adaptive probe scheduler is not running")
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return nil, ErrNoCandidates
	}
	result := make(map[string]uint16)
	type pendingProbe struct {
		tag    string
		future *ProbeFuture
	}
	pending := make([]pendingProbe, 0, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		submission := scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
		if submission.Err != nil {
			for _, probe := range pending {
				probe.future.Cancel()
			}
			return result, submission.Err
		}
		pending = append(pending, pendingProbe{tag: candidate.PrimaryTag, future: submission.Future})
	}
	for index, probe := range pending {
		probeResult, err := probe.future.Await(ctx)
		if err != nil {
			for _, remaining := range pending[index+1:] {
				remaining.future.Cancel()
			}
			return result, err
		}
		if probeResult.Outcome == OutcomeSuccess {
			result[probe.tag] = uint16(max(0, probeResult.Delay.Milliseconds()))
		}
	}
	return result, nil
}

// DashboardURLTest is a bounded control-plane probe.  AdaptivePool.URLTest is
// intentionally a complete scheduler check for explicit callers; using it for
// a dashboard refresh would enqueue every provider node at once.  Keep the
// dashboard request on the pool scheduler, endpoint admission and observation
// path, but inspect only a small rotating slice of candidates.
func (p *AdaptivePool) DashboardURLTest(ctx context.Context) (map[string]uint16, error) {
	if p.closing.Load() || !p.dashboardProbeRunning.CompareAndSwap(false, true) {
		return map[string]uint16{}, nil
	}
	defer p.dashboardProbeRunning.Store(false)

	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return nil, errors.New("adaptive probe scheduler is not running")
	}
	snapshot := p.catalog.load()
	if snapshot == nil || len(snapshot.Candidates) == 0 {
		return map[string]uint16{}, nil
	}
	const dashboardProbeLimit = 2
	limit := min(dashboardProbeLimit, len(snapshot.Candidates))
	start := int(p.dashboardProbeCursor.Add(uint64(limit))-uint64(limit)) % len(snapshot.Candidates)
	candidates := make([]Candidate, 0, limit)
	for index := range limit {
		candidates = append(candidates, snapshot.Candidates[(start+index)%len(snapshot.Candidates)])
	}
	result := make(map[string]uint16, len(candidates))
	pending := make([]struct {
		tag    string
		future *ProbeFuture
	}, 0, len(candidates))
	for _, candidate := range candidates {
		submission := scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
		if submission.Err != nil {
			for _, probe := range pending {
				probe.future.Cancel()
			}
			return result, submission.Err
		}
		pending = append(pending, struct {
			tag    string
			future *ProbeFuture
		}{tag: candidate.PrimaryTag, future: submission.Future})
	}
	for index, probe := range pending {
		probeResult, err := probe.future.Await(ctx)
		if err != nil {
			for _, remaining := range pending[index+1:] {
				remaining.future.Cancel()
			}
			return result, err
		}
		if probeResult.Outcome == OutcomeSuccess {
			result[probe.tag] = uint16(max(0, probeResult.Delay.Milliseconds()))
		}
	}
	return result, nil
}

// PerformUpdateCheck is the non-blocking URLTestGroup hook used by the Clash
// API after a manual delay test. The delay handler has already tested one
// concrete outbound; adaptive only needs to wake a bounded, coalesced probe
// batch so the shared profile can incorporate the fresh observation. Keeping
// this path bounded avoids making an HTTP dashboard request enqueue one task
// per provider node (and avoids creating an unbounded goroutine fan-out).
func (p *AdaptivePool) PerformUpdateCheck() {
	if p.closing.Load() || !p.manualProbePending.CompareAndSwap(false, true) {
		return
	}

	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		p.manualProbePending.Store(false)
		return
	}
	snapshot := p.catalog.load()
	if snapshot == nil || len(snapshot.Candidates) == 0 {
		p.manualProbePending.Store(false)
		return
	}
	limit := min(max(p.probeConcurrency, 1), len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates[:limit] {
		task := p.probeTask(snapshot, candidate, time.Now(), 0)
		task.Priority = ProbePriorityOnDemand
		if submission := scheduler.Submit(task); submission.Err != nil {
			break
		}
	}
	p.manualProbePending.Store(false)
}

func (p *AdaptivePool) TriggerAdaptiveProbe(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return errors.New("adaptive probe scheduler is not running")
	}
	snapshot := p.catalog.load()
	if snapshot == nil {
		return ErrNoCandidates
	}
	for _, candidate := range snapshot.Candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		submission := scheduler.Submit(p.probeTask(snapshot, candidate, time.Now(), 0))
		if submission.Err != nil {
			return submission.Err
		}
		submission = scheduler.Submit(p.dnsHealthProbeTask(snapshot, candidate, "ipv4", time.Now(), 0))
		if submission.Err != nil {
			return submission.Err
		}
	}
	return nil
}

func (p *AdaptivePool) TriggerAdaptiveCapabilityProbe(ctx context.Context) error {
	p.lifecycleAccess.Lock()
	controllers := cloneCapabilityControllers(p.capabilityControllers)
	p.lifecycleAccess.Unlock()
	if len(controllers) == 0 {
		return adapter.ErrAdaptiveCapabilityUnavailable
	}
	for _, serviceID := range sortedCapabilityControllerIDs(controllers) {
		_, err := controllers[serviceID].RunOnce(ctx)
		if errors.Is(err, ErrCapabilityCycleBusy) {
			return adapter.ErrAdaptiveCapabilityBusy
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *AdaptivePool) onSourceUpdated() error {
	if p.closing.Load() {
		return nil
	}
	p.lifecycleAccess.Lock()
	phase := p.publishPhase
	if phase == publishPhasePrepared || phase == publishPhasePublishing {
		p.sourceDirty = true
		p.lifecycleAccess.Unlock()
		return nil
	}
	retired := p.retired || phase == publishPhaseRollingBack || phase == publishPhaseRetired
	p.lifecycleAccess.Unlock()
	if retired {
		return nil
	}
	return p.rebuild()
}

func (p *AdaptivePool) rebuild() error {
	p.catalogAccess.Lock()
	defer p.catalogAccess.Unlock()
	generation := p.generation.Add(1)
	var source SourcePublication
	var err error
	if p.sourcePublication != nil {
		if incremental, loaded := p.source.(IncrementalSourceRuntime); loaded {
			var delta SourceDeltaPublication
			delta, err = incremental.Delta(p.ctx, generation)
			if err == nil {
				source, err = ApplySourceDelta(*p.sourcePublication, delta)
				if err == nil {
					p.deltaAppliedTotal.Add(1)
				}
			}
			if err != nil {
				err = nil
			}
		}
	}
	if source.Generation == 0 && err == nil {
		source, err = p.source.Snapshot(p.ctx, generation)
		if p.sourcePublication != nil {
			p.deltaFallbackTotal.Add(1)
		}
	}
	if err != nil {
		return err
	}
	clonedSource := cloneSourcePublication(source)
	p.sourcePublication = &clonedSource
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		return err
	}
	p.lifecycleAccess.Lock()
	published := p.published
	p.lifecycleAccess.Unlock()
	if !published {
		health, leases, control, _ := p.runtimeSnapshot()
		preparedIdentity, prepareErr := p.runtimeManager.PrepareEpoch(p.groupID, health, leases, control, identitySource)
		if prepareErr != nil {
			return prepareErr
		}
		preparedExecution, prepareErr := p.catalog.PrepareCommitted(source, preparedIdentity.Identity())
		if prepareErr != nil {
			return prepareErr
		}
		if prepareErr = p.persistPreparedIdentityKey(); prepareErr != nil {
			return prepareErr
		}
		p.preparedIdentity = preparedIdentity
		p.preparedExecution = preparedExecution
		p.lifecycleAccess.Lock()
		p.publishPhase = publishPhasePrepared
		p.lifecycleAccess.Unlock()
		return nil
	}
	preparedIdentity, err := p.runtimeManager.PrepareRevision(p.groupID, p.runtimeIdentity.EpochID, identitySource)
	if err != nil {
		return err
	}
	preparedExecution, err := p.catalog.PrepareCommitted(source, preparedIdentity.Identity())
	if err != nil {
		return err
	}
	previous := p.catalog.load()
	_, identity, err := preparedIdentity.Commit()
	if err != nil {
		return err
	}
	if err = p.persistStateDurable(); err != nil {
		_ = preparedIdentity.Rollback()
		return errors.New("adaptive identity revision is not durable")
	}
	next := p.catalog.CommitPrepared(preparedExecution)
	p.runtimeIdentity = identity
	p.applyCommittedTransitions(identity)
	p.reconcileScheduler(previous, next)
	return nil
}

func (p *AdaptivePool) persistPreparedIdentityKey() error {
	if !p.identityKeyNew {
		return nil
	}
	if err := persistIdentityKey(p.statePath+".key", p.identityKey[:]); err != nil {
		return E.Cause(err, "persist adaptive identity key")
	}
	p.identityKeyNew = false
	return nil
}

func (p *AdaptivePool) startSchedulerLocked() {
	if !p.published || !p.postStarted || p.retired || p.scheduler != nil {
		return
	}
	if p.schedulerOwner == nil {
		p.schedulerOwner = p.runtimeManager.SchedulerCoordinator(p.groupID)
	}
	snapshot := p.catalog.load()
	if snapshot == nil || snapshot.RuntimeEpochID == 0 {
		return
	}
	ownership, err := p.schedulerOwner.Claim(snapshot.RuntimeEpochID)
	if err != nil {
		return
	}
	p.schedulerGen = ownership.Generation
	p.scheduler = newOwnedProbeScheduler(p.ctx, p.schedulerOwner, ownership, p.probeConcurrency, p.probeQueueSize)
	for _, task := range p.startupProbeTasks(snapshot, time.Now()) {
		_ = p.scheduler.Submit(task)
	}
	p.startCapabilityControllerLocked(snapshot)
}

func (p *AdaptivePool) startCapabilityControllerLocked(snapshot *ExecutionSnapshot) {
	// C1: single map entry-point only — no parallel singular controller field.
	if p.capabilityProvider == nil || len(p.capabilityControllers) != 0 || p.scheduler == nil || snapshot == nil || snapshot.RuntimeEpochID == 0 {
		return
	}
	refresh := p.capabilityRefresh
	if refresh <= 0 {
		refresh = defaultCapabilityRefresh
	}
	timeout := p.capabilityTimeout
	if timeout <= 0 {
		timeout = defaultCapabilityTimeout
	}
	quorum := p.capabilityQuorum
	if quorum <= 0 {
		quorum = 2
	}
	commonModeMin := p.capabilityCommonModeMin
	if commonModeMin <= 0 {
		commonModeMin = 2
	}
	runner := p.capabilityRunner
	if runner == nil {
		runner = NewCapabilityProbeRunner(nil)
	}
	health, _, _, _ := p.runtimeSnapshot()
	if health == nil {
		p.capabilityInitFailures.Add(1)
		return
	}
	sessions, err := NewRuntimeCapabilityObservationFactory(p.runtimeManager, p.groupID, p.sharedObservationIngestor(), health, p.observationReducerHook)
	if err != nil {
		p.capabilityInitFailures.Add(1)
		return
	}
	serviceIDs := append([]string(nil), p.capabilityServiceIDs...)
	if len(serviceIDs) == 0 {
		serviceIDs = []string{youtubeProbeServiceID}
	}
	controllers := make(map[string]*CapabilityProbeController, len(serviceIDs))
	parent := p.ctx
	if parent == nil {
		parent = context.Background()
	}
	for _, serviceID := range serviceIDs {
		suite, err := NewCapabilityProbeSuite(nil, p.scheduler, p.capabilityProvider, runner, NewProbeAggregator(ProbeAggregatorConfig{}, nil, nil), sessions, p.exitIdentityStore)
		if err != nil {
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controller, err := NewCapabilityProbeController(nil, p.capabilityProvider, suite, p.catalog.Snapshot, snapshot.RuntimeEpochID, refresh, timeout, quorum, commonModeMin, p.catalog)
		if err != nil {
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controller.WithServiceID(serviceID)
		if err = controller.Start(parent); err != nil {
			controller.Close()
			p.capabilityInitFailures.Add(1)
			closeCapabilityControllers(controllers)
			return
		}
		controllers[serviceID] = controller
	}
	p.capabilityControllers = controllers
}

func cloneCapabilityControllers(source map[string]*CapabilityProbeController) map[string]*CapabilityProbeController {
	cloned := make(map[string]*CapabilityProbeController, len(source))
	for serviceID, controller := range source {
		cloned[serviceID] = controller
	}
	return cloned
}

func sortedCapabilityControllerIDs(controllers map[string]*CapabilityProbeController) []string {
	serviceIDs := make([]string, 0, len(controllers))
	for serviceID := range controllers {
		serviceIDs = append(serviceIDs, serviceID)
	}
	slices.Sort(serviceIDs)
	return serviceIDs
}

func closeCapabilityControllers(controllers map[string]*CapabilityProbeController) {
	for _, controller := range controllers {
		controller.Close()
	}
}

func (p *AdaptivePool) reconcileScheduler(previous, next *ExecutionSnapshot) {
	p.lifecycleAccess.Lock()
	scheduler := p.scheduler
	p.lifecycleAccess.Unlock()
	if scheduler == nil {
		return
	}
	if previous != nil {
		scheduler.RemoveRevision(previous.RuntimeEpochID, previous.CatalogRevision)
	}
	for _, task := range p.startupProbeTasks(next, time.Now()) {
		_ = scheduler.Submit(task)
	}
}

func (p *AdaptivePool) applyCommittedTransitions(identity RuntimeIdentity) {
	if identity.Revision == 0 {
		return
	}
	for {
		applied := p.appliedRevision.Load()
		if uint64(identity.Revision) <= applied {
			return
		}
		if p.appliedRevision.CompareAndSwap(applied, uint64(identity.Revision)) {
			break
		}
	}
	health, leases, _, _ := p.runtimeSnapshot()
	for _, handle := range identity.RetiredHandles {
		if health != nil {
			health.RetireNodeHandle(handle)
		}
		if leases != nil {
			leases.RetireNodeHandle(handle)
		}
		p.lifecycleAccess.Lock()
		scheduler := p.scheduler
		p.lifecycleAccess.Unlock()
		if scheduler != nil {
			scheduler.RemoveHandle(handle)
		}
	}
}

func (p *AdaptivePool) pinnedNodeID() *NodeID {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		return nil
	}
	control.access.RLock()
	pinned := control.pinned
	control.access.RUnlock()
	if pinned == (NodeID{}) {
		return nil
	}
	return &pinned
}

func (p *AdaptivePool) setLatest(tag string) {
	_, _, control, _ := p.runtimeSnapshot()
	if control == nil {
		control = new(ControlState)
		p.runtimeAccess.Lock()
		if p.control == nil {
			p.control = control
		} else {
			control = p.control
		}
		p.runtimeAccess.Unlock()
	}
	control.access.Lock()
	control.latestTag = tag
	control.access.Unlock()
}

func (p *AdaptivePool) leaseTTL(mode PolicyMode) time.Duration {
	if mode == ModeStrictAffinity {
		return p.strictLeaseTTL
	}
	return p.adaptiveLeaseTTL
}

func loadOrPrepareIdentityKey(path string) ([32]byte, bool, error) {
	var key [32]byte
	content, err := os.ReadFile(path)
	if err == nil {
		if len(content) != len(key) {
			return key, false, errors.New("invalid adaptive identity key length")
		}
		copy(key[:], content)
		return key, false, nil
	}
	if !os.IsNotExist(err) {
		return key, false, err
	}
	if _, err = rand.Read(key[:]); err != nil {
		return key, false, err
	}
	return key, true, nil
}

func persistIdentityKey(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".adaptive-key-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(key)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

func safeFileName(value string) string {
	if value == "" {
		return "default"
	}
	result := make([]rune, 0, len(value))
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9', character == '-', character == '_':
			result = append(result, character)
		default:
			result = append(result, '_')
		}
	}
	return string(result)
}

func firstOrDefault(values []string, fallback string) string {
	if len(values) == 0 || values[0] == "" {
		return fallback
	}
	return values[0]
}

func parseCapabilityTrustedKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	if len(encoded) == 0 {
		return nil, errors.New("adaptive capability trusted keys are required")
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("adaptive capability trusted key is invalid")
		}
		keys[keyID] = ed25519.PublicKey(decoded)
	}
	return cloneProbeTargetKeyring(keys)
}
