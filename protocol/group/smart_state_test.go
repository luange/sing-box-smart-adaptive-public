package group

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/probe"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSmartProbeUsesOnlyConnectivity204(t *testing.T) {
	leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "leaf", []string{N.NetworkTCP}, nil)}
	var access sync.Mutex
	var links []string
	registry := &nodeProfileRegistry{
		ctx:     context.Background(),
		cancel:  func() {},
		entries: make(map[string]*nodeProfileEntry),
		slots:   make(chan struct{}, 1),
		probe: func(_ context.Context, link string, _ adapter.Outbound) (uint16, error) {
			access.Lock()
			links = append(links, link)
			access.Unlock()
			return 7, nil
		},
	}
	smart := &Smart{
		ctx:               context.Background(),
		control:           &smartControlState{},
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeURL:          probe.GoogleConnectivityURL,
		probeInterval:     time.Minute,
		probeCycleTimeout: time.Second,
		probeTimeout:      time.Second,
		probeRegistry:     registry,
		candidates:        []adapter.Outbound{leaf},
		candidateByTag:    map[string]adapter.Outbound{"leaf": leaf},
		lastSelected:      make(map[string]string),
		affinity:          make(map[string]smartAffinity),
		switchChallenges:  make(map[string]smartSwitchChallenge),
		halfOpen:          make(map[string]struct{}),
	}
	setSmartCandidateIdentities(smart, map[string]string{"leaf": "endpoint-id"})
	delays, err := smart.probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if delays["leaf"] != 7 {
		t.Fatalf("unexpected probe delay: %v", delays)
	}
	access.Lock()
	defer access.Unlock()
	if len(links) != 1 || links[0] != probe.GoogleConnectivityURL {
		t.Fatalf("Smart must probe only the connectivity 204 target, got %v", links)
	}
}

func TestSmartDashboardProbeDoesNotOpenCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 2, time.Minute)
	now := time.Now()
	for range 5 {
		store.observeDialAdvisory(now, N.NetworkTCP, "", "node", N.NetworkTCP, false, time.Millisecond)
	}
	estimate := store.estimate(now, N.NetworkTCP, "", "node", N.NetworkTCP, 1)
	if estimate.State == "open" {
		t.Fatalf("dashboard failures opened circuit: %+v", estimate)
	}
	if estimate.CircuitUntil.After(now) {
		t.Fatalf("dashboard failures set circuit deadline: %s", estimate.CircuitUntil)
	}
}

func TestSmartProbeScheduleObservesTrafficWithoutForegroundWakeup(t *testing.T) {
	smart := &Smart{
		probeInterval: 10 * time.Minute,
		probeNow:      make(chan struct{}, 1),
	}
	now := time.Now()
	if smart.activeAt(now) {
		t.Fatal("new Smart group must start idle")
	}
	if interval := smart.nextProbeInterval(now); interval != defaultSmartIdleProbeInterval {
		t.Fatalf("idle interval = %v, want %v", interval, defaultSmartIdleProbeInterval)
	}
	if budget := smart.scheduledProbeBudget(now); budget != 1 {
		t.Fatalf("idle scheduled budget = %d, want 1", budget)
	}
	if budget := smart.requestedProbeBudget(now); budget != defaultSmartColdProbeBudget {
		t.Fatalf("cold requested budget = %d, want %d", budget, defaultSmartColdProbeBudget)
	}

	smart.noteTrafficActivity()
	now = time.Now()
	if !smart.activeAt(now) {
		t.Fatal("real traffic did not wake Smart profiling")
	}
	if interval := smart.nextProbeInterval(now); interval != smart.probeInterval {
		t.Fatalf("active interval = %v, want %v", interval, smart.probeInterval)
	}
	if budget := smart.requestedProbeBudget(now); budget != defaultSmartColdProbeBudget {
		t.Fatalf("cold active requested budget = %d, want %d", budget, defaultSmartColdProbeBudget)
	}
	if budget := smart.scheduledProbeBudget(now); budget != defaultSmartActiveProbeBudget {
		t.Fatalf("active scheduled budget = %d, want %d", budget, defaultSmartActiveProbeBudget)
	}
	smart.phase.Store(uint32(smartPhaseProfiling))
	if budget := smart.requestedProbeBudget(now); budget != defaultSmartActiveProbeBudget {
		t.Fatalf("profiling active requested budget = %d, want %d", budget, defaultSmartActiveProbeBudget)
	}
	select {
	case <-smart.probeNow:
		t.Fatal("real traffic launched a foreground URLTest sweep")
	default:
	}

	// Additional traffic inside the activity window must not enqueue a probe
	// per connection; that would turn a busy group into a probe storm.
	smart.noteTrafficActivity()
	select {
	case <-smart.probeNow:
		t.Fatal("active traffic enqueued a duplicate immediate probe")
	default:
	}

	smart.lastActivityUnixNano.Store(time.Now().Add(-defaultSmartActivityWindow - time.Second).UnixNano())
	smart.noteTrafficActivity()
	select {
	case <-smart.probeNow:
		t.Fatal("traffic after idle launched a foreground URLTest sweep")
	default:
	}
}

func TestSmartManualProbeUsesDashboardBudget(t *testing.T) {
	// A configured positive bound must still narrow the manual probe.
	smart := &Smart{probeNow: make(chan struct{}, 1), dashboardProbeBudget: defaultSmartDashboardProbeBudget}
	smart.PerformUpdateCheck()
	if budget := smart.manualProbeBudget.Load(); budget != int32(defaultSmartDashboardProbeBudget) {
		t.Fatalf("manual probe budget = %d, want %d", budget, defaultSmartDashboardProbeBudget)
	}
	select {
	case <-smart.probeNow:
	default:
		t.Fatal("manual delay test did not wake Smart probe worker")
	}
	// A normal traffic wakeup must not replace the smaller control-plane cap.
	smart.requestProbeWithBudget(defaultSmartActiveProbeBudget)
	if budget := smart.manualProbeBudget.Load(); budget != int32(defaultSmartDashboardProbeBudget) {
		t.Fatalf("traffic wakeup widened manual budget to %d", budget)
	}
}

func TestSmartManualProbeUnboundedByDefault(t *testing.T) {
	// Default (no dashboard_probe_budget) restores the native panel behavior:
	// a manual group test probes the full catalog through the refactored
	// probeWithBudget pipeline.
	smart := &Smart{probeNow: make(chan struct{}, 1)}
	smart.PerformUpdateCheck()
	if budget := smart.manualProbeBudget.Load(); budget != 0 {
		t.Fatalf("default manual probe budget = %d, want 0 (unbounded)", budget)
	}
	select {
	case <-smart.probeNow:
	default:
		t.Fatal("manual delay test did not wake Smart probe worker")
	}
}

func TestSmartProbeBudgetRotatesWithoutOverlap(t *testing.T) {
	registry := &nodeProfileRegistry{
		ctx:     context.Background(),
		cancel:  func() {},
		entries: make(map[string]*nodeProfileEntry),
		slots:   make(chan struct{}, 5),
		probe: func(_ context.Context, _ string, _ adapter.Outbound) (uint16, error) {
			return 10, nil
		},
	}
	candidates := make([]adapter.Outbound, 10)
	byTag := make(map[string]adapter.Outbound, len(candidates))
	probeKeys := make(map[string]string, len(candidates))
	for index := range candidates {
		tag := "node-" + itoaSmall(index)
		leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil)}
		candidates[index] = leaf
		byTag[tag] = leaf
		probeKeys[tag] = tag
	}
	smart := &Smart{
		ctx:              context.Background(),
		control:          &smartControlState{},
		store:            newSmartStore(time.Hour, 3, time.Minute),
		probeURL:         probe.GoogleConnectivityURL,
		probeInterval:    time.Minute,
		probeTimeout:     time.Second,
		probeRegistry:    registry,
		candidates:       candidates,
		candidateByTag:   byTag,
		lastSelected:     make(map[string]string),
		affinity:         make(map[string]smartAffinity),
		switchChallenges: make(map[string]smartSwitchChallenge),
		halfOpen:         make(map[string]struct{}),
	}
	setSmartCandidateIdentities(smart, probeKeys)
	// Background testing follows Surge's small-catalog full-scan rule. This test
	// exercises the bounded dashboard window, whose explicit budget must rotate.
	probeCtx := withSmartDashboardProbe(context.Background())
	first, err := smart.probeWithBudget(probeCtx, 4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := smart.probeWithBudget(probeCtx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("unexpected budget result sizes: first=%d second=%d", len(first), len(second))
	}
	for tag := range first {
		if _, exists := second[tag]; exists {
			t.Fatalf("consecutive rotating windows overlapped on %s", tag)
		}
	}
	if cursor := smart.probeCursor.Load(); cursor != 8 {
		t.Fatalf("probe cursor = %d, want 8", cursor)
	}
}

func TestSmartProbeRegistryFullDefersWithoutBypassingBounds(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	busy := &nodeProfileEntry{inflight: true, done: make(chan struct{})}
	registry.access.Lock()
	for index := 0; index < nodeProfileRegistryLimit; index++ {
		registry.entries["busy-"+itoaSmall(index)] = busy
	}
	registry.access.Unlock()

	called := false
	_, err := registry.runProbe(context.Background(), "overflow", time.Second, time.Minute, func(context.Context) (uint16, error) {
		called = true
		return 1, nil
	})
	if !errors.Is(err, errSharedNodeProbeDeferred) {
		t.Fatalf("full registry error = %v, want deferred", err)
	}
	if called {
		t.Fatal("full registry bypassed the bounded single-flight path")
	}
}

func TestSmartProbeRegistryDistinguishesFreshAndCachedResults(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	var calls atomic.Int32
	registry.probe = func(context.Context, string, adapter.Outbound) (uint16, error) {
		calls.Add(1)
		return 12, nil
	}

	if _, err, fresh := registry.runWithMeta(context.Background(), "node", "https://probe", time.Second, time.Hour, nil); err != nil || !fresh {
		t.Fatalf("first probe = err %v, fresh %v; want fresh success", err, fresh)
	}
	if _, err, fresh := registry.runWithMeta(context.Background(), "node", "https://probe", time.Second, time.Hour, nil); err != nil || fresh {
		t.Fatalf("cached probe = err %v, fresh %v; want cached success", err, fresh)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe executed %d times, want once", got)
	}

	failureRegistry := newNodeProfileRegistry(context.Background())
	defer failureRegistry.close()
	var failureCalls atomic.Int32
	failureRegistry.probe = func(context.Context, string, adapter.Outbound) (uint16, error) {
		failureCalls.Add(1)
		return 0, errors.New("offline")
	}
	if _, err, fresh := failureRegistry.runWithMeta(context.Background(), "node", "https://probe", time.Second, time.Hour, nil); err == nil || !fresh {
		t.Fatalf("first failed probe = err %v, fresh %v; want fresh failure", err, fresh)
	}
	if _, err, fresh := failureRegistry.runWithMeta(context.Background(), "node", "https://probe", time.Second, time.Hour, nil); err == nil || fresh {
		t.Fatalf("cached failed probe = err %v, fresh %v; want cached failure", err, fresh)
	}
	if got := failureCalls.Load(); got != 1 {
		t.Fatalf("failed probe executed %d times, want once", got)
	}
}

func TestSmartProbeRegistryCancellationDoesNotCacheFailure(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	started := make(chan struct{})
	var calls atomic.Int32
	registry.probe = func(ctx context.Context, _ string, _ adapter.Outbound) (uint16, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return 9, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err, fresh := registry.runWithMeta(ctx, "cancelled", "https://probe", time.Second, time.Minute, nil)
		if fresh {
			firstDone <- errors.New("cancelled probe reported fresh evidence")
			return
		}
		firstDone <- err
	}()
	<-started
	cancel()
	if err := <-firstDone; !errors.Is(err, errSharedNodeProbeDeferred) {
		t.Fatalf("cancelled probe error = %v, want deferred", err)
	}

	if _, err, fresh := registry.runWithMeta(context.Background(), "cancelled", "https://probe", time.Second, time.Minute, nil); err != nil || !fresh {
		t.Fatalf("retry after cancellation = err %v, fresh %v; want fresh success", err, fresh)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe executed %d times, want cancellation not cached", got)
	}
}

func TestSmartProbeRegistrySerializesTracksPerEndpoint(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := registry.runProbeForEndpoint(context.Background(), "endpoint", "tcp", time.Second, time.Minute, func(context.Context) (uint16, error) {
			close(started)
			<-release
			return 1, nil
		})
		firstDone <- err
	}()
	<-started

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		_, err := registry.runProbeForEndpoint(context.Background(), "endpoint", "udp", time.Second, time.Minute, func(context.Context) (uint16, error) {
			close(secondStarted)
			return 2, nil
		})
		secondDone <- err
	}()
	select {
	case <-secondStarted:
		t.Fatal("different probe tracks ran concurrently for one endpoint")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second endpoint track did not run after the first completed")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestSmartProbeRegistryRecoveryKeepsEndpointLock(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := registry.runProbeForEndpoint(context.Background(), "endpoint", "tcp", time.Second, time.Minute, func(context.Context) (uint16, error) {
			close(firstStarted)
			<-firstRelease
			return 0, errors.New("first probe failed")
		})
		firstDone <- err
	}()
	<-firstStarted

	recoveryStarted := make(chan struct{})
	recoveryRelease := make(chan struct{})
	recoveryDone := make(chan error, 1)
	go func() {
		_, err := registry.runRecoveryForEndpoint(context.Background(), "endpoint", "tcp", time.Second, time.Minute, func(context.Context) (uint16, error) {
			close(recoveryStarted)
			<-recoveryRelease
			return 2, nil
		})
		recoveryDone <- err
	}()

	close(firstRelease)
	if err := <-firstDone; err == nil {
		t.Fatal("first probe unexpectedly succeeded")
	}
	select {
	case <-recoveryStarted:
	case <-time.After(time.Second):
		t.Fatal("forced recovery did not start")
	}
	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		_, err := registry.runProbeForEndpoint(context.Background(), "endpoint", "udp", time.Second, time.Minute, func(context.Context) (uint16, error) {
			close(secondStarted)
			return 3, nil
		})
		secondDone <- err
	}()
	select {
	case <-secondStarted:
		t.Fatal("different track ran while forced recovery owned the endpoint")
	case <-time.After(20 * time.Millisecond):
	}
	close(recoveryRelease)
	if err := <-recoveryDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("different track did not run after recovery released the endpoint")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestSmartProbePurposePolicy(t *testing.T) {
	tests := []struct {
		name          string
		purpose       smartProbePurpose
		advisory      bool
		force         bool
		retryInflight bool
		publishLatest bool
		allowPenalty  bool
	}{
		{"background", smartProbeBackground, false, false, false, true, true},
		{"dashboard", smartProbeDashboard, true, false, false, false, false},
		{"recovery", smartProbeRecovery, false, true, true, true, true},
		{"transport coverage", smartProbeTransportCoverage, false, false, false, true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := test.purpose.policy()
			if policy.advisory != test.advisory || policy.force != test.force ||
				policy.retryAfterInflight != test.retryInflight || policy.publishLatest != test.publishLatest ||
				policy.allowPenalty != test.allowPenalty {
				t.Fatalf("unexpected policy: %+v", policy)
			}
		})
	}
}

func TestSmartExecuteProbePurposeControlsCadence(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	smart := &Smart{probeRegistry: registry}
	request := smartProbeRequest{
		purpose:     smartProbeDashboard,
		endpointKey: "endpoint",
		profileKey:  "profile",
		timeout:     time.Second,
		ttl:         time.Minute,
	}
	probeCalls := 0
	probe := func(context.Context) (uint16, error) {
		probeCalls++
		return uint16(probeCalls), nil
	}
	if delay, err, performed := smart.executeProbe(context.Background(), request, probe); err != nil || delay != 1 || !performed {
		t.Fatalf("first dashboard probe = (%d, %v, %v)", delay, err, performed)
	}
	if delay, err, performed := smart.executeProbe(context.Background(), request, probe); err != nil || delay != 1 || performed {
		t.Fatalf("cached dashboard probe = (%d, %v, %v)", delay, err, performed)
	}
	request.purpose = smartProbeRecovery
	if delay, err, performed := smart.executeProbe(context.Background(), request, probe); err != nil || delay != 2 || !performed {
		t.Fatalf("forced recovery probe = (%d, %v, %v)", delay, err, performed)
	}
	if probeCalls != 2 {
		t.Fatalf("probe calls = %d, want 2", probeCalls)
	}
}

func TestSmartReliabilityUsesConfidence(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(1000, 0)
	initial := store.estimate(now, "eth0", "", "a", "tcp", 3)
	store.observeDial(now, "eth0", "", "a", "tcp", true, 100*time.Millisecond)
	oneSuccess := store.estimate(now, "eth0", "", "a", "tcp", 3)
	for range 20 {
		store.observeDial(now, "eth0", "", "a", "tcp", true, 100*time.Millisecond)
	}
	manySuccesses := store.estimate(now, "eth0", "", "a", "tcp", 3)
	if !(initial.Reliability < oneSuccess.Reliability && oneSuccess.Reliability < manySuccesses.Reliability) {
		t.Fatalf("unexpected reliability ordering: initial=%f one=%f many=%f", initial.Reliability, oneSuccess.Reliability, manySuccesses.Reliability)
	}
}

func TestSmartTailLatencyKeepsSingleSpikeVisible(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(1500, 0)
	for range 8 {
		store.observeDial(now, "ethernet", "", "node-a", "tcp", true, 50*time.Millisecond)
	}
	store.observeFirstByte(now, "ethernet", "", "node-a", "tcp", 80*time.Millisecond)
	store.observeFirstByte(now, "ethernet", "", "node-a", "tcp", 2*time.Second)
	estimate := store.estimate(now, "ethernet", "", "node-a", "tcp", 3)
	if estimate.FirstByteP95MS <= estimate.FirstByteMS {
		t.Fatalf("tail estimate should retain a spike: p50=%f p95=%f", estimate.FirstByteMS, estimate.FirstByteP95MS)
	}
	if smartScoreForProfile(estimate, smartProfileInteractive, 0, estimate.Samples) <= 0 {
		t.Fatal("tail-aware score must remain finite")
	}
}

func TestSmartScoreUsesTailLatencyForInteractiveTraffic(t *testing.T) {
	steady := smartEstimate{Reliability: .99, ConnectMS: 50, ConnectP95MS: 60, FirstByteMS: 100, FirstByteP95MS: 120, Samples: 12, State: "healthy", HasConnect: true, HasConnectP95: true, HasFirstByte: true, HasFirstByteP95: true}
	spiky := steady
	spiky.ConnectP95MS = 900
	spiky.FirstByteP95MS = 3500
	if smartScoreForProfile(spiky, smartProfileInteractive, 0, 24) <= smartScoreForProfile(steady, smartProfileInteractive, 0, 24) {
		t.Fatal("interactive score should penalize a high p95 tail")
	}
}

func TestSmartRetransmitPenaltyIsBoundedAndAdditive(t *testing.T) {
	if got := smartRetransmitPenaltyMS(0.01); got != 50 {
		t.Fatalf("one percent retransmit penalty = %vms, want 50ms", got)
	}
	if got := smartRetransmitPenaltyMS(2); got != 5000 {
		t.Fatalf("pathological retransmit penalty = %vms, want cap 5000ms", got)
	}
	if got := smartRetransmitPenaltyMS(-1); got != 0 {
		t.Fatalf("negative retransmit penalty = %vms, want 0", got)
	}
}

func TestSmartRetransmitPenaltyUsesEvidenceConfidence(t *testing.T) {
	full := smartRetransmitPenaltyMS(0.12)
	if got := smartRetransmitPenaltyMSWithConfidence(0.12, 1); got != full/3 {
		t.Fatalf("one retransmit sample penalty = %vms, want %vms", got, full/3)
	}
	if got := smartRetransmitPenaltyMSWithConfidence(0.12, 2); got != full*2/3 {
		t.Fatalf("two retransmit samples penalty = %vms, want %vms", got, full*2/3)
	}
	if got := smartRetransmitPenaltyMSWithConfidence(0.12, 3); got != full {
		t.Fatalf("settled retransmit penalty = %vms, want %vms", got, full)
	}
	if got := smartRetransmitPenaltyMSWithConfidence(0.12, 0); got != 0 {
		t.Fatalf("missing retransmit samples penalty = %vms, want 0", got)
	}
}

func TestSmartRetransmitEvidenceIsScopedAndDecayed(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(1750, 0)
	store.observeRetransmit(now, "ethernet", "video.example", "node-a", N.NetworkTCP, 0.02)
	estimate := store.estimate(now, "ethernet", "video.example", "node-a", N.NetworkTCP, 3)
	if !estimate.HasRetransmit || estimate.RetransmitRatio != 0.02 {
		t.Fatalf("retransmit evidence not recorded: %+v", estimate)
	}
	other := store.estimate(now, "ethernet", "video.example", "node-b", N.NetworkTCP, 3)
	if other.HasRetransmit {
		t.Fatalf("retransmit evidence leaked to another candidate: %+v", other)
	}
	aged := store.estimate(now.Add(4*time.Hour), "ethernet", "video.example", "node-a", N.NetworkTCP, 3)
	if aged.RetransmitSamples >= estimate.RetransmitSamples {
		t.Fatalf("retransmit samples did not decay: now=%f aged=%f", estimate.RetransmitSamples, aged.RetransmitSamples)
	}
}

func TestSmartModeDefaultsAndLegacyAliases(t *testing.T) {
	modePointer := func(value uint8) *uint8 { return &value }
	tests := []struct {
		mode   *uint8
		legacy string
		want   smartSelectionMode
	}{
		{want: smartSelectionSpread},
		{mode: modePointer(1), want: smartSelectionSpread},
		{mode: modePointer(0), want: smartSelectionFixed},
		{legacy: "adaptive", want: smartSelectionFixed},
		{legacy: "unified", want: smartSelectionFixed},
		{legacy: "primary_backup", want: smartSelectionFixed},
		{legacy: "primary-backup", want: smartSelectionFixed},
		{legacy: "balanced", want: smartSelectionSpread},
		{legacy: "balance", want: smartSelectionSpread},
		{legacy: "random", want: smartSelectionSpread},
		{legacy: "scatter", want: smartSelectionSpread},
		{legacy: "fixed", want: smartSelectionFixed},
	}
	for _, test := range tests {
		got, err := normalizeSmartSelectionMode(test.mode, test.legacy)
		if err != nil || got != test.want {
			t.Fatalf("normalizeSmartSelectionMode(%v, %q) = %v, %v; want %v, nil", test.mode, test.legacy, got, err, test.want)
		}
	}
	if _, err := normalizeSmartSelectionMode(modePointer(2), ""); err == nil {
		t.Fatal("invalid numeric mode was accepted")
	}
	if _, err := normalizeSmartSelectionMode(modePointer(0), "fixed"); err == nil {
		t.Fatal("conflicting mode options were accepted")
	}
	if _, err := normalizeSmartSelectionMode(nil, "latency_race"); err == nil {
		t.Fatal("invalid selection mode was accepted")
	}
}

func TestSmartNumericModeConfig(t *testing.T) {
	var omitted option.SmartOutboundOptions
	if err := json.Unmarshal([]byte(`{"type":"smart"}`), &omitted); err != nil {
		t.Fatal(err)
	}
	mode, err := normalizeSmartSelectionMode(omitted.Mode, omitted.SelectionMode)
	if err != nil || mode != smartSelectionSpread {
		t.Fatalf("omitted mode = %d, %v; want default 1", mode, err)
	}

	var fixed option.SmartOutboundOptions
	if err := json.Unmarshal([]byte(`{"type":"smart","mode":0}`), &fixed); err != nil {
		t.Fatal(err)
	}
	mode, err = normalizeSmartSelectionMode(fixed.Mode, fixed.SelectionMode)
	if err != nil || mode != smartSelectionFixed {
		t.Fatalf("explicit mode 0 = %d, %v; want fixed", mode, err)
	}
}

func TestSmartStatusReportsNumericMode(t *testing.T) {
	smart := newTestSmart()
	smart.selectionMode = smartSelectionSpread
	if got := smart.SmartStatus().Mode; got != 1 {
		t.Fatalf("Smart status mode = %d, want 1", got)
	}
	smart.selectionMode = smartSelectionFixed
	if got := smart.SmartStatus().Mode; got != 0 {
		t.Fatalf("Smart status mode = %d, want 0", got)
	}
}

func TestSmartMetricDecayDropsStaleEvidenceClasses(t *testing.T) {
	metric := smartMetric{
		ConnectMS: 900, ConnectP95MS: 1200, JitterMS: 80, ConnectSamples: 1,
		FirstByteMS: 700, FirstByteP95MS: 1000, FirstByteSamples: 1,
		ThroughputLog: 20, ThroughputSamples: 1,
		RetransmitRatio: 0.12, RetransmitSamples: 1,
		Successes: 4, Failures: 1, LastUpdated: time.Unix(1000, 0),
	}
	metric.decay(time.Unix(1000, 0).Add(4*time.Hour), time.Hour)
	if metric.ConnectSamples != 0 || metric.ConnectMS != 0 || metric.ConnectP95MS != 0 || metric.JitterMS != 0 {
		t.Fatalf("stale connect evidence survived decay: %+v", metric)
	}
	if metric.FirstByteSamples != 0 || metric.FirstByteMS != 0 || metric.FirstByteP95MS != 0 {
		t.Fatalf("stale first-byte evidence survived decay: %+v", metric)
	}
	if metric.ThroughputSamples != 0 || metric.ThroughputLog != 0 || metric.RetransmitSamples != 0 || metric.RetransmitRatio != 0 {
		t.Fatalf("stale bulk/loss evidence survived decay: %+v", metric)
	}
	if metric.Successes <= 0 || metric.Failures <= 0 {
		t.Fatalf("reliability prior was incorrectly discarded: %+v", metric)
	}
}

func TestSmartSpreadAffinityIsStableAndHealthBounded(t *testing.T) {
	smart := &Smart{switchMargin: 0.15}
	ranks := []smartRank{
		{identity: "endpoint-a", eligible: true, status: adapter.SmartCandidateStatus{State: "healthy", Score: 0.40, Samples: 3}},
		{identity: "endpoint-b", eligible: true, status: adapter.SmartCandidateStatus{State: "healthy", Score: 0.42, Samples: 3}},
		{identity: "endpoint-c", eligible: true, status: adapter.SmartCandidateStatus{State: "suspect", Score: 0.10, Samples: 3}},
	}
	first := smart.stableAffinityIndex(ranks, "network\x00example.com\x00tcp", "")
	second := smart.stableAffinityIndex(ranks, "network\x00example.com\x00tcp", "")
	if first < 0 || first != second || first == 2 {
		t.Fatalf("spread affinity was not stable and health bounded: first=%d second=%d", first, second)
	}
	if got := smart.stableAffinityIndex(ranks, "network\x00example.com\x00tcp", "endpoint-b"); got != 1 {
		t.Fatalf("healthy incumbent was not retained in spread pool: got=%d", got)
	}
	ranks[1].eligible = false
	if got := smart.stableAffinityIndex(ranks, "network\x00example.com\x00tcp", "endpoint-b"); got == 1 || got < 0 {
		t.Fatalf("failed incumbent was retained by spread affinity: got=%d", got)
	}
}

func TestSmartStoreBoundsPruneOnConfiguration(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	store.observeDial(now.Add(-2*time.Hour), "ethernet", "", "old", "tcp", true, time.Millisecond)
	store.observeDial(now.Add(-time.Minute), "ethernet", "", "new-a", "tcp", true, time.Millisecond)
	store.observeDial(now, "ethernet", "", "new-b", "tcp", true, time.Millisecond)
	store.setBounds(time.Hour, 1)
	store.access.RLock()
	defer store.access.RUnlock()
	if len(store.metrics) != 1 {
		t.Fatalf("store bounds retained %d metrics, want 1", len(store.metrics))
	}
	if _, loaded := store.metrics[smartMetricKey{Network: "ethernet", Candidate: "new-b", Transport: "tcp"}]; !loaded {
		t.Fatal("store bounds did not retain newest metric")
	}
}

func TestSmartExplorationUsesBestHealthTierSamples(t *testing.T) {
	ranks := []smartRank{
		{eligible: true, estimate: smartEstimate{Samples: 2}, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{eligible: true, estimate: smartEstimate{Samples: 100}, status: adapter.SmartCandidateStatus{State: "warming"}},
		{eligible: false, estimate: smartEstimate{Samples: 200}, status: adapter.SmartCandidateStatus{State: "healthy"}},
		{eligible: true, estimate: smartEstimate{Samples: 300}, status: adapter.SmartCandidateStatus{State: "open"}},
	}
	if got := smartTotalSamplesForBestTier(ranks); got != 2 {
		t.Fatalf("exploration samples = %v, want best-tier total 2", got)
	}
}

func TestSmartColdPhaseUsesFastHedgeAndSteadyPhaseDampsIt(t *testing.T) {
	smart := &Smart{maxAttempts: 3, attemptTimeout: 4 * time.Second}
	smart.phaseInitialized.Store(true)
	smart.phase.Store(uint32(smartPhaseCold))
	if got := smart.smartHedgeDelay(); got != minSmartHedgeDelay {
		t.Fatalf("cold hedge delay = %v, want %v", got, minSmartHedgeDelay)
	}
	smart.phase.Store(uint32(smartPhaseSteady))
	if got := smart.smartHedgeDelay(); got <= minSmartHedgeDelay {
		t.Fatalf("steady hedge delay = %v, want longer than cold delay", got)
	}
}

func TestSmartAbsoluteImprovementRequiresComparableLatency(t *testing.T) {
	best := smartRank{status: adapter.SmartCandidateStatus{FirstByteP95MS: 700}}
	current := smartRank{status: adapter.SmartCandidateStatus{FirstByteP95MS: 850}}
	if !smartAbsoluteImprovement(best, current, 100*time.Millisecond) {
		t.Fatal("expected a 150ms p95 improvement to pass the floor")
	}
	current.status.FirstByteP95MS = 760
	if smartAbsoluteImprovement(best, current, 100*time.Millisecond) {
		t.Fatal("sub-threshold improvement must retain the incumbent")
	}
	current.status.FirstByteP95MS = 0
	current.status.ConnectP95MS = 0
	if smartAbsoluteImprovement(best, current, 100*time.Millisecond) {
		t.Fatal("missing comparable latency must not trigger a performance switch")
	}
}

func TestSmartConnectivity204RTTFeedsEWMAAndJitter(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	store.observeDial(now, "network", "", "node", N.NetworkTCP, true, 100*time.Millisecond)
	first := store.estimate(now, "network", "", "node", N.NetworkTCP, 3)
	store.observeDial(now.Add(time.Second), "network", "", "node", N.NetworkTCP, true, 300*time.Millisecond)
	second := store.estimate(now.Add(time.Second), "network", "", "node", N.NetworkTCP, 3)
	if !first.HasConnect || first.ConnectMS != 100 {
		t.Fatalf("first connectivity RTT was not recorded: %+v", first)
	}
	if second.ConnectMS <= first.ConnectMS || second.ConnectMS >= 300 {
		t.Fatalf("connectivity RTT must be smoothed by EWMA: first=%f second=%f", first.ConnectMS, second.ConnectMS)
	}
	if second.JitterMS <= 0 {
		t.Fatalf("connectivity RTT variation must update jitter: %+v", second)
	}
}

func TestSmartBreakerHalfOpenAndRecovery(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(2000, 0)
	for range 3 {
		store.observeDial(now, "eth0", "", "a", "tcp", false, time.Second)
	}
	open := store.estimate(now, "eth0", "", "a", "tcp", 3)
	if open.State != "open" {
		t.Fatalf("expected open, got %s", open.State)
	}
	halfOpen := store.estimate(now.Add(time.Minute+time.Second), "eth0", "", "a", "tcp", 3)
	if halfOpen.State != "half_open" {
		t.Fatalf("expected half_open, got %s", halfOpen.State)
	}
	store.observeDial(now.Add(time.Minute+time.Second), "eth0", "", "a", "tcp", true, 80*time.Millisecond)
	recovered := store.estimate(now.Add(time.Minute+time.Second), "eth0", "", "a", "tcp", 3)
	if recovered.State == "open" || recovered.State == "half_open" {
		t.Fatalf("expected recovered state, got %s", recovered.State)
	}
}

func TestSmartSiteHistoryOverridesGlobalGradually(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(3000, 0)
	for range 20 {
		store.observeDial(now, "eth0", "", "a", "tcp", true, 50*time.Millisecond)
	}
	for range 6 {
		store.observeDial(now, "eth0", "video.example", "a", "tcp", false, time.Second)
	}
	global := store.estimate(now, "eth0", "", "a", "tcp", 3)
	site := store.estimate(now, "eth0", "video.example", "a", "tcp", 3)
	if site.Reliability >= global.Reliability {
		t.Fatalf("site reliability should be lower: site=%f global=%f", site.Reliability, global.Reliability)
	}
}

func TestSmartThroughputAffectsScore(t *testing.T) {
	slow := smartEstimate{
		Reliability:   0.99,
		ConnectMS:     80,
		ThroughputBPS: 512 * 1024,
		Samples:       10,
		State:         "healthy",
		HasConnect:    true,
		HasThroughput: true,
	}
	fast := slow
	fast.ThroughputBPS = 32 * 1024 * 1024
	if smartScoreForProfile(fast, smartProfileBulk, 0, 20) >= smartScoreForProfile(slow, smartProfileBulk, 0, 20) {
		t.Fatal("faster candidate should have a lower score")
	}
}

func TestSmartSiteFailuresDoNotOpenGlobalCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(4000, 0)
	for range 3 {
		store.observeDial(now, "wifi", "bank.example", "a", "tcp", false, time.Second)
	}
	global := store.estimate(now, "wifi", "", "a", "tcp", 3)
	site := store.estimate(now, "wifi", "bank.example", "a", "tcp", 3)
	if global.State == "open" {
		t.Fatal("site-specific failures opened the global circuit")
	}
	if site.State != "suspect" || !store.siteFailedRecently(now, "wifi", "bank.example", "a", "tcp", time.Hour) {
		t.Fatalf("expected a Surge-style site stain, got %+v", site)
	}
}

func TestSmartDataPlaneFailureQuarantinesOnlyAffectedSite(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(4500, 0)
	store.observeDial(now, "wifi", "", "node-a", N.NetworkTCP, true, 20*time.Millisecond)
	store.quarantineDataPlaneFailure(now, "wifi", "service:jp", "node-a", N.NetworkTCP, 30*time.Second)

	local := store.estimate(now, "wifi", "service:jp", "node-a", N.NetworkTCP, 3)
	if local.State != "open" || !local.CircuitUntil.Equal(now.Add(30*time.Second)) {
		t.Fatalf("data-plane failure did not quarantine local service: %+v", local)
	}
	global := store.estimate(now, "wifi", "", "node-a", N.NetworkTCP, 3)
	if global.State == "open" {
		t.Fatalf("site-local data-plane failure poisoned global endpoint: %+v", global)
	}
	other := store.estimate(now, "wifi", "service:us", "node-a", N.NetworkTCP, 3)
	if other.State == "open" {
		t.Fatalf("site-local data-plane failure poisoned another service: %+v", other)
	}
}

func TestSmartFailuresAcrossSitesNeverOpenGlobalCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, 2*time.Minute)
	now := time.Unix(5000, 0)
	for index, site := range []string{"api-a.example", "api-b.example", "api-c.example", "api-d.example"} {
		store.observeDial(now.Add(time.Duration(index)*time.Second), "wifi", site, "node-a", "tcp", false, time.Second)
	}
	global := store.estimate(now.Add(40*time.Second), "wifi", "", "node-a", "tcp", 3)
	if global.State == "open" || global.State == "half_open" {
		t.Fatalf("Surge site stains leaked into the global endpoint circuit: %+v", global)
	}
}

func TestSmartSpreadOrderingBandsAndSiteAffinity(t *testing.T) {
	ranks := []smartRank{
		{policyID: 1, eligible: true, status: adapter.SmartCandidateStatus{Tag: "fast", Score: 100, Weight: 1}},
		{policyID: 2, eligible: true, siteSuccesses: 2, siteDelayMS: 120, status: adapter.SmartCandidateStatus{Tag: "site", Score: 130, Weight: 1}},
		{policyID: 3, eligible: true, siteTainted: true, status: adapter.SmartCandidateStatus{Tag: "tainted", Score: 120, Weight: 1}},
		{policyID: 4, eligible: true, activeProbeDegraded: true, status: adapter.SmartCandidateStatus{Tag: "failed-test", Score: 300, Weight: 1}},
	}
	(&Smart{}).applySurgeOrdering(ranks, "site-key", "", time.Unix(9000, 0))
	if ranks[0].status.Tag != "site" || ranks[0].status.Reason != "spread site affinity" {
		t.Fatalf("site best was not promoted inside tier A: %+v", ranks)
	}
	bandByTag := make(map[string]uint8, len(ranks))
	for _, rank := range ranks {
		bandByTag[rank.status.Tag] = rank.surgeBand
	}
	if bandByTag["fast"] != 0 || bandByTag["site"] != 0 || bandByTag["tainted"] != 1 || bandByTag["failed-test"] != 2 {
		t.Fatalf("unexpected candidate bands: %+v", bandByTag)
	}
}

func TestSmartSpreadSiteAffinityUsesCompleteCandidateCoverage(t *testing.T) {
	ranks := []smartRank{
		{policyID: 1, eligible: true, status: adapter.SmartCandidateStatus{Tag: "fast", Score: 100, Weight: 1}},
		{policyID: 2, eligible: true, status: adapter.SmartCandidateStatus{Tag: "a-backup", Score: 130, Weight: 1}},
		{policyID: 3, eligible: true, siteSuccesses: 1, siteDelayMS: 120, status: adapter.SmartCandidateStatus{Tag: "site-b", Score: 250, Weight: 1}},
		{policyID: 4, eligible: true, activeProbeDegraded: true, status: adapter.SmartCandidateStatus{Tag: "c", Score: 350, Weight: 1}},
	}
	(&Smart{}).applySurgeOrdering(ranks, "site-key", "", time.Unix(9001, 0))
	if ranks[0].status.Tag != "site-b" || ranks[0].status.Reason != "spread site affinity" {
		t.Fatalf("credible site record outside tier A was not promoted: %+v", ranks)
	}
}

func TestSmartSpreadScoreUsesDelayAndLossPenalty(t *testing.T) {
	estimate := smartEstimate{FirstByteMS: 100, RetransmitRatio: 0.02}
	if score := smartSurgeScore(estimate); score != 200 {
		t.Fatalf("score=%v, want 200", score)
	}
	if score := smartSurgeScore(smartEstimate{}); score != 0 {
		t.Fatalf("unknown score=%v, want 0", score)
	}
	if score := smartSurgeScore(smartEstimate{ConnectMS: 5}); score != 0 {
		t.Fatalf("dial latency incorrectly replaced missing first-response history: %v", score)
	}
}

func TestSmartSurgeHistoryMatchesTwentySlotFiveMinuteContract(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(10_000, 0)
	store.observeFirstByte(now, "wifi", "example.com", "node-a", N.NetworkTCP, 100*time.Millisecond)
	store.observeFirstByte(now.Add(time.Second), "wifi", "example.com", "node-a", N.NetworkTCP, 300*time.Millisecond)
	delay, _ := store.surgeScoreSnapshot("wifi", "node-a", N.NetworkTCP)
	if math.Abs(delay-200) > 0.001 {
		t.Fatalf("same-site 300-second EWMA=%v, want 200", delay)
	}
	store.observeRetransmit(now.Add(2*time.Second), "wifi", "example.com", "node-a", N.NetworkTCP, 0.02)
	_, loss := store.surgeScoreSnapshot("wifi", "node-a", N.NetworkTCP)
	if math.Abs(loss-0.02) > 0.000001 {
		t.Fatalf("loss history=%v, want 0.02", loss)
	}
}

func TestSmartCandidateDeadRequiresRecentGlobalConsecutiveFailures(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Now()
	for range 2 {
		store.observeDial(now, "ethernet", "", "node-a", "tcp", false, time.Second)
	}
	if store.candidateDead("ethernet", "", "node-a", "tcp", now) {
		t.Fatal("two failures must not mark candidate dead")
	}
	store.observeDial(now, "ethernet", "", "node-a", "tcp", false, time.Second)
	if !store.candidateDead("ethernet", "", "node-a", "tcp", now) {
		t.Fatal("three recent failures must mark candidate dead")
	}
	store.observeDial(now, "ethernet", "", "node-a", "tcp", true, time.Millisecond)
	if store.candidateDead("ethernet", "", "node-a", "tcp", now) {
		t.Fatal("success must clear candidate death")
	}
	for range 3 {
		store.observeDial(now.Add(-time.Minute), "ethernet", "", "node-a", "tcp", false, time.Second)
	}
	if store.candidateDead("ethernet", "", "node-a", "tcp", now) {
		t.Fatal("stale failures must not mark candidate dead")
	}
}

func TestSmartTCPAndUDPStateAreIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(5000, 0)
	for range 3 {
		store.observeDial(now, "ethernet", "", "a", "tcp", false, time.Second)
	}
	for range 6 {
		store.observeDial(now, "ethernet", "game.example", "a", "udp", true, 35*time.Millisecond)
	}
	tcp := store.estimate(now, "ethernet", "", "a", "tcp", 3)
	udp := store.estimate(now, "ethernet", "game.example", "a", "udp", 3)
	if tcp.State != "open" {
		t.Fatalf("expected TCP circuit open, got %s", tcp.State)
	}
	if udp.State == "open" || udp.State == "half_open" {
		t.Fatalf("TCP failures contaminated UDP state: %s", udp.State)
	}
}

func TestSmartNetworkHistoryIsIndependent(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(6000, 0)
	for range 3 {
		store.observeDial(now, "wifi", "", "a", "tcp", false, time.Second)
	}
	wifi := store.estimate(now, "wifi", "", "a", "tcp", 3)
	ethernet := store.estimate(now, "ethernet", "", "a", "tcp", 3)
	if wifi.State != "open" {
		t.Fatalf("expected wifi circuit open, got %s", wifi.State)
	}
	if ethernet.State != "unknown" {
		t.Fatalf("new network inherited stale state: %s", ethernet.State)
	}
}

func TestSmartHierarchicalSamplesAreNotDoubleCounted(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	now := time.Unix(7000, 0)
	for range 5 {
		store.observeDial(now, "ethernet", "video.example", "a", "tcp", true, 50*time.Millisecond)
	}
	estimate := store.estimate(now, "ethernet", "video.example", "a", "tcp", 3)
	if estimate.Samples != 5 {
		t.Fatalf("hierarchical samples were double counted: %f", estimate.Samples)
	}
}

func TestSmartTrafficProfilesPreferDifferentCandidates(t *testing.T) {
	lowLatency := smartEstimate{
		Reliability:       0.98,
		ConnectMS:         25,
		FirstByteMS:       55,
		ThroughputBPS:     512 * 1024,
		ThroughputSamples: 4,
		Samples:           20,
		State:             "healthy",
		HasConnect:        true,
		HasFirstByte:      true,
		HasThroughput:     true,
	}
	highThroughput := lowLatency
	highThroughput.ConnectMS = 130
	highThroughput.FirstByteMS = 180
	highThroughput.ThroughputBPS = 48 * 1024 * 1024
	if smartScoreForProfile(lowLatency, smartProfileInteractive, 0, 40) >= smartScoreForProfile(highThroughput, smartProfileInteractive, 0, 40) {
		t.Fatal("interactive profile should prefer the lower-latency candidate")
	}
	if smartScoreForProfile(highThroughput, smartProfileBulk, 0, 40) >= smartScoreForProfile(lowLatency, smartProfileBulk, 0, 40) {
		t.Fatal("bulk profile should prefer the higher-throughput candidate")
	}
}

func TestSmartDetectsBulkProfileOnlyAfterUsefulSamples(t *testing.T) {
	estimates := map[string]smartEstimate{
		"a": {ThroughputSamples: 1},
		"b": {},
	}
	if profile := detectSmartTrafficProfile("tcp", estimates); profile != smartProfileInteractive {
		t.Fatalf("single throughput sample changed the profile: %s", profile)
	}
	estimate := estimates["a"]
	estimate.ThroughputSamples = 2
	estimates["a"] = estimate
	if profile := detectSmartTrafficProfile("tcp", estimates); profile != smartProfileBulk {
		t.Fatalf("expected bulk profile, got %s", profile)
	}
	if profile := detectSmartTrafficProfile("udp", estimates); profile != smartProfileUDP {
		t.Fatalf("expected UDP profile, got %s", profile)
	}
}

func TestPassiveThroughputFloorUsesOnlyRealTrafficSamples(t *testing.T) {
	base := smartEstimate{ThroughputBPS: 64 * 1024, ThroughputSamples: 3, HasThroughput: true}
	if !passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("sustained low real-traffic throughput should trip the passive floor")
	}
	if passiveThroughputBelowFloor(base, 512*1024, 4) {
		t.Fatal("insufficient throughput samples should not trip the passive floor")
	}
	base.ThroughputBPS = 2 * 1024 * 1024
	if passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("throughput above the floor was incorrectly degraded")
	}
	base.ThroughputBPS = 2 * 1024 * 1024
	base.LocalThroughputBPS = 64 * 1024
	base.LocalThroughputSamples = 2
	if !passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("service-local low throughput must override a fast global history")
	}
	base.HasThroughput = false
	base.ThroughputBPS = 1
	if passiveThroughputBelowFloor(base, 512*1024, 2) {
		t.Fatal("missing passive observations must not degrade a candidate")
	}
}

func TestSmartWorkerStartsOnPostStart(t *testing.T) {
	smart := &Smart{
		ctx:               context.Background(),
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeInterval:     time.Hour,
		probeTimeout:      time.Millisecond,
		halfLife:          time.Hour,
		breakerFailures:   3,
		breakerCooldown:   time.Minute,
		maxHistoryEntries: 100,
	}
	if err := smart.PostStart(); err != nil {
		t.Fatal(err)
	}
	smart.lifecycleAccess.Lock()
	started := smart.workerStarted
	smart.lifecycleAccess.Unlock()
	if !started {
		t.Fatal("smart worker did not start on PostStart")
	}
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
}

type smartCloseStubOutbound struct {
	outbound.Adapter
}

func (s *smartCloseStubOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (s *smartCloseStubOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestSmartCloseDoesNotBlockIndefinitely ensures HA restart budget: Close must
// return even if the probe worker is slow to observe cancel.
func TestSmartCloseDoesNotBlockIndefinitely(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	block := make(chan struct{})
	registry := &nodeProfileRegistry{
		ctx:     ctx,
		cancel:  func() {},
		entries: make(map[string]*nodeProfileEntry),
		slots:   make(chan struct{}, 1),
		probe: func(probeCtx context.Context, _ string, _ adapter.Outbound) (uint16, error) {
			select {
			case <-probeCtx.Done():
				return 0, probeCtx.Err()
			case <-block:
				return 1, nil
			}
		},
	}
	// Occupy the single admission slot so run() waits; Close must still finish.
	registry.slots <- struct{}{}
	defer func() { <-registry.slots; close(block) }()

	leaf := &smartCloseStubOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, "leaf", []string{N.NetworkTCP}, nil)}
	smart := &Smart{
		ctx:               ctx,
		store:             newSmartStore(time.Hour, 3, time.Minute),
		probeInterval:     time.Hour,
		probeCycleTimeout: time.Minute,
		probeTimeout:      30 * time.Second,
		halfLife:          time.Hour,
		breakerFailures:   3,
		breakerCooldown:   time.Minute,
		maxHistoryEntries: 100,
		probeRegistry:     registry,
		candidates:        []adapter.Outbound{leaf},
		candidateByTag:    map[string]adapter.Outbound{"leaf": leaf},
	}
	setSmartCandidateIdentities(smart, map[string]string{"leaf": "leaf-id"})
	if err := smart.PostStart(); err != nil {
		t.Fatal(err)
	}
	// Give the worker a moment to enter cold-start probe and block on the slot.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := smart.Close(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// Bound is 2s; allow a little scheduling slack.
	if elapsed > 3*time.Second {
		t.Fatalf("smart.Close blocked too long for HA: %v", elapsed)
	}
}

func TestSmartHealthIsPerInstance(t *testing.T) {
	newInstance := func() *Smart {
		return &Smart{
			ctx:               context.Background(),
			store:             newSmartStore(time.Hour, 3, time.Minute),
			control:           &smartControlState{},
			probeInterval:     time.Hour,
			probeTimeout:      time.Millisecond,
			halfLife:          time.Hour,
			breakerFailures:   3,
			breakerCooldown:   time.Minute,
			maxHistoryEntries: 100,
		}
	}
	first := newInstance()
	if err := first.PostStart(); err != nil {
		t.Fatal(err)
	}
	first.store.observeDial(time.Now(), "network", "", "candidate-a", "tcp", true, time.Millisecond)
	first.control.pinned = "candidate-a"
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := newInstance()
	if err := second.PostStart(); err != nil {
		t.Fatal(err)
	}
	if first.store == second.store {
		t.Fatal("a new smart generation shares the previous health store")
	}
	if second.control.pinned != "" {
		t.Fatalf("a new smart generation inherited a pin: %s", second.control.pinned)
	}
	if estimate := second.store.estimate(time.Now(), "network", "", "candidate-a", "tcp", 1); estimate.State != "unknown" {
		t.Fatalf("a new smart generation inherited observations: %s", estimate.State)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSmartHealthTierPrecedesLatency(t *testing.T) {
	if smartHealthTier("healthy") >= smartHealthTier("suspect") {
		t.Fatal("healthy candidates must outrank suspect candidates regardless of latency")
	}
	if smartHealthTier("suspect") >= smartHealthTier("open") {
		t.Fatal("suspect candidates must remain a recoverable backup ahead of open candidates")
	}
}
