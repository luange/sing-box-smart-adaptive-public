package group

import (
	"context"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

func TestNodeHealthStoreIsSharedPerOutboundManager(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	config := smartHealthStoreConfig{
		halfLife:        time.Hour,
		breakerFailures: 3,
		breakerCooldown: time.Minute,
		retention:       time.Hour,
		maxEntries:      64,
	}
	first, releaseFirst, matchingFirst := acquireSmartHealthStore(context.Background(), manager, config)
	second, releaseSecond, matchingSecond := acquireSmartHealthStore(context.Background(), manager, config)
	defer releaseFirst()
	defer releaseSecond()
	if !matchingFirst || !matchingSecond {
		t.Fatal("identical Smart groups did not accept the core health policy")
	}
	if first != second {
		t.Fatal("Smart groups with one outbound manager received separate health stores")
	}

	other := config
	other.breakerFailures++
	policyRevision := first.policyRevision
	reloaded, releaseOther, matchingOther := acquireSmartHealthStore(context.Background(), manager, other)
	defer releaseOther()
	if !matchingOther || reloaded != first || first.breakerFailures != other.breakerFailures || first.policyRevision <= policyRevision {
		t.Fatalf("new Smart configuration did not take authoritative ownership: matching=%v store=%p expected=%p policy=%+v", matchingOther, reloaded, first, first)
	}
	if status, initialized := SharedNodeHealthStatus(manager); !initialized || status.GroupCount != 0 {
		t.Fatalf("shared health status missing after store acquisition: initialized=%v status=%+v", initialized, status)
	}
}

func TestNodeHealthStorePromotesDefaultPoolToFirstSmartPolicy(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, releaseExternal := acquireNodeHealthStore(manager)
	policy := smartHealthStoreConfig{
		halfLife:        17 * time.Minute,
		breakerFailures: 2,
		breakerCooldown: 3 * time.Minute,
		retention:       9 * time.Hour,
		maxEntries:      73,
	}
	smartStore, releaseSmart, matching := acquireSmartHealthStore(context.Background(), manager, policy)
	if !matching || smartStore != store {
		t.Fatalf("first Smart owner did not adopt existing policy pool: matching=%v store=%p smart=%p", matching, store, smartStore)
	}
	if store.halfLife != policy.halfLife || store.breakerFailures != policy.breakerFailures || store.breakerCooldown != policy.breakerCooldown || store.retention != policy.retention || store.maxEntries != policy.maxEntries {
		t.Fatalf("Smart policy did not replace provisional defaults: %+v", store)
	}
	releaseSmart()
	releaseExternal()
	if _, initialized := SharedNodeHealthStatus(manager); initialized {
		t.Fatal("shared health pool leaked after all policy references closed")
	}
}

func TestSelectorHealthPoolLifecycleDoesNotReleaseSmartOwner(t *testing.T) {
	first := newSmartFakeOutbound("first", nil)
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{first.Tag(): first}}
	selector := &Selector{
		outbound:   manager,
		tags:       []string{first.Tag()},
		defaultTag: first.Tag(),
		outbounds:  make(map[string]adapter.Outbound),
	}
	scope := adapter.NewScope(context.Background(), nil)
	if err := selector.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatalf("start selector: %v", err)
	}
	before, initialized := SharedNodeHealthStatus(manager)
	if !initialized {
		t.Fatal("selector did not initialize shared health pool")
	}
	smartStore, releaseSmart, matching := acquireSmartHealthStore(context.Background(), manager, defaultNodeHealthStoreConfig())
	if !matching || smartStore == nil {
		t.Fatalf("Smart could not join selector-owned health pool: matching=%v store=%p", matching, smartStore)
	}
	if err := scope.Close(); err != nil {
		t.Fatalf("close selector scope: %v", err)
	}
	after, initialized := SharedNodeHealthStatus(manager)
	if !initialized || after.MaxEntries != before.MaxEntries {
		t.Fatalf("selector shutdown released or replaced Smart-owned health pool: before=%+v after=%+v initialized=%v", before, after, initialized)
	}
	releaseSmart()
	if _, initialized := SharedNodeHealthStatus(manager); initialized {
		t.Fatal("health pool leaked after selector and Smart references closed")
	}
}

func TestNodeHealthGateOnlyRejectsConfirmedOpenCircuit(t *testing.T) {
	store := newSmartStore(time.Hour, 3, time.Minute)
	candidate := newSmartFakeOutbound("candidate-a", nil)
	now := time.Now()
	if nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", now) {
		t.Fatal("unknown candidate was rejected by shared health gate")
	}
	store.openEndpointCircuit(now, "network-default", candidate.Tag(), "tcp")
	if !nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", now) {
		t.Fatal("open core circuit was not shared with another policy method")
	}
}

func TestSharedHealthEntriesAreBoundedAndCredentialSafe(t *testing.T) {
	store := newSmartStore(time.Hour, 1, time.Minute)
	now := time.Now()
	store.observeDial(now, "network-default", "", "dial:secret-credential", "tcp", true, 25*time.Millisecond)
	store.openEndpointCircuit(now, "network-default", "dial:secret-credential", "tcp")
	entries := store.entries(1)
	if len(entries) != 1 {
		t.Fatalf("unexpected health entries: %#v", entries)
	}
	entry := entries[0]
	if entry.ProfileID == "" || strings.Contains(entry.ProfileID, "secret") || strings.Contains(entry.Site, "secret") || entry.State != "open" || entry.CircuitUntil.IsZero() {
		t.Fatalf("unsafe or incomplete shared health entry: %+v", entry)
	}
}

func TestSharedHealthEventsAreBoundedAndCredentialSafe(t *testing.T) {
	store := newSmartStore(time.Hour, 1, time.Minute)
	store.setPolicy(time.Hour, 1, time.Minute)
	store.openEndpointCircuit(time.Now(), "network-default", "dial:secret-credential", "tcp")
	events := store.events(2)
	if len(events) != 2 || events[0].Type != "circuit_opened" || events[0].ProfileID == "" || strings.Contains(events[0].ProfileID, "secret") || events[1].Type != "policy_updated" {
		t.Fatalf("unsafe or incomplete shared health events: %+v", events)
	}
}

func TestSharedHealthEventsTrackRealDialCircuitTransitions(t *testing.T) {
	store := newSmartStore(time.Hour, 1, time.Minute)
	now := time.Now()
	store.observeDialWithFailureType(now, "network-default", "", "dial:credential", "tcp", false, time.Millisecond, "hard_transport")
	store.observeDial(now.Add(time.Millisecond), "network-default", "", "dial:credential", "tcp", true, time.Millisecond)
	events := store.events(2)
	if len(events) != 2 || events[0].Type != "circuit_recovered" || events[1].Type != "circuit_opened" {
		t.Fatalf("real dial circuit events missing or out of order: %+v", events)
	}
}

func TestSharedHealthConcurrentDialAndReloadContract(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, releaseExternal := acquireNodeHealthStore(manager)
	defer releaseExternal()
	firstPolicy := smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 3, breakerCooldown: time.Minute, retention: time.Hour, maxEntries: 8}
	_, releaseFirst, matching := acquireSmartHealthStore(context.Background(), manager, firstPolicy)
	if !matching {
		t.Fatal("first Smart policy was not accepted")
	}
	defer releaseFirst()
	candidate := newSmartFakeOutbound("concurrent-leaf", nil)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for sample := 0; sample < 64; sample++ {
				if (index+sample)%11 == 0 {
					recordSharedNodeHealthDial(manager, nil, candidate, "tcp", syscall.ECONNREFUSED, time.Millisecond, context.Background())
				} else {
					recordSharedNodeHealthDial(manager, nil, candidate, "tcp", nil, time.Millisecond, context.Background())
				}
			}
		}(worker)
	}
	secondPolicy := firstPolicy
	secondPolicy.breakerFailures = 2
	secondPolicy.maxEntries = 4
	_, releaseSecond, matching := acquireSmartHealthStore(context.Background(), manager, secondPolicy)
	if !matching {
		t.Fatal("replacement Smart policy was not accepted")
	}
	workers.Wait()
	status, initialized := SharedNodeHealthStatus(manager)
	if !initialized || status.PolicyRevision < 2 || status.MaxEntries != secondPolicy.maxEntries || status.MetricEntries > secondPolicy.maxEntries {
		t.Fatalf("concurrent reload violated shared health contract: %+v initialized=%v", status, initialized)
	}
	releaseSecond()
	if store == nil {
		t.Fatal("shared store unexpectedly lost during concurrent reload")
	}
}

func TestURLTestSuccessFeedsSharedHealthAsAdvisoryOnly(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 3, breakerCooldown: time.Minute})
	defer release()
	candidate := newSmartFakeOutbound("candidate-a", nil)
	group := &URLTestGroup{outbound: manager, outbounds: []adapter.Outbound{candidate}}
	group.recordSharedHealthEvidence(map[string]uint16{candidate.Tag(): 25})
	metric, ok := store.metricCopy(smartMetricKey{Network: "network-default", Candidate: candidate.Tag(), Transport: "tcp"}, time.Now())
	if !ok || metric.Successes <= 0 || !metric.CircuitUntil.IsZero() {
		t.Fatalf("URLTest did not contribute advisory-only shared health: %+v loaded=%v", metric, ok)
	}
}

func TestURLTestNestedProbeEvidenceUsesLeafResultTag(t *testing.T) {
	leaf := newSmartFakeOutbound("nested-leaf", nil)
	wrapper := &healthSelectedFakeGroup{smartFakeOutbound: newSmartFakeOutbound("nested-wrapper", nil), selected: leaf}
	manager := &smartFakeOutboundManager{byTag: map[string]adapter.Outbound{leaf.Tag(): leaf, wrapper.Tag(): wrapper}}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 3, breakerCooldown: time.Minute})
	defer release()
	group := &URLTestGroup{outbound: manager, outbounds: []adapter.Outbound{wrapper}}
	group.recordSharedHealthEvidence(map[string]uint16{leaf.Tag(): 25})
	metric, ok := store.metricCopy(smartMetricKey{Network: "network-default", Candidate: nodeHealthProfileIDForNetwork(leaf, "tcp"), Transport: "tcp"}, time.Now())
	if !ok || metric.Successes <= 0 {
		t.Fatalf("nested URLTest leaf evidence was discarded: %+v loaded=%v", metric, ok)
	}
}

func TestSelectorRealDialEvidenceUsesSharedHealthFailurePolicy(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	candidate := newSmartFakeOutbound("candidate-a", nil)
	selector := &Selector{outbound: manager}
	selector.recordSharedHealth(candidate, "tcp", syscall.ECONNREFUSED, time.Millisecond, context.Background())
	if !nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", time.Now()) {
		t.Fatal("selector hard dial failure did not open shared health circuit")
	}
	// A caller-owned cancellation is not endpoint evidence and must not alter
	// the already-recorded circuit state.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	selector.recordSharedHealth(candidate, "tcp", context.Canceled, time.Millisecond, canceled)
	if !nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", time.Now()) {
		t.Fatal("selector request cancellation changed shared health circuit")
	}
}

func TestURLTestRealDialEvidenceUsesSharedHealthFailurePolicy(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	candidate := newSmartFakeOutbound("candidate-a", nil)
	group := &URLTestGroup{outbound: manager}
	group.recordSharedHealth(candidate, "tcp", syscall.ECONNREFUSED, time.Millisecond, context.Background())
	if !nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", time.Now()) {
		t.Fatal("URLTest hard dial failure did not open shared health circuit")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	group.recordSharedHealth(candidate, "tcp", context.Canceled, time.Millisecond, canceled)
	if !nodeHealthCircuitOpen(store, "network-default", candidate, "tcp", time.Now()) {
		t.Fatal("URLTest request cancellation changed shared health circuit")
	}
}

func TestSharedHealthProfileMatchesSmartDialIdentity(t *testing.T) {
	candidate := newSmartFakeOutbound("provider/renamed-node", nil)
	candidate.dialIdentity = "credential-profile-a"
	smart := newTestSmart(candidate)
	setSmartCandidateIdentities(smart, map[string]string{candidate.Tag(): candidate.dialIdentity})
	if got, want := nodeHealthProfileID(candidate), smart.candidateProfileID(candidate.Tag()); got != want {
		t.Fatalf("cross-policy health profile mismatch: group=%q smart=%q", got, want)
	}
}

type healthSelectedFakeGroup struct {
	*smartFakeOutbound
	selected adapter.Outbound
}

func (g *healthSelectedFakeGroup) Selected(network string) adapter.Outbound { return g.selected }

func TestNestedPolicyHealthUsesActualDialLeaf(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	leaf := newSmartFakeOutbound("leaf", nil)
	leaf.dialIdentity = "leaf-credential"
	wrapper := &healthSelectedFakeGroup{smartFakeOutbound: newSmartFakeOutbound("urltest-wrapper", nil), selected: leaf}
	if got, want := nodeHealthProfileIDForNetwork(wrapper, "tcp"), nodeHealthProfileIDForNetwork(leaf, "tcp"); got != want {
		t.Fatalf("nested policy used wrapper identity: got=%q want=%q", got, want)
	}
	recordSharedNodeHealthDial(manager, nil, wrapper, "tcp", syscall.ECONNREFUSED, time.Millisecond, context.Background())
	if !nodeHealthCircuitOpen(store, "network-default", leaf, "tcp", time.Now()) {
		t.Fatal("nested policy failure did not open the actual leaf circuit")
	}
}

func TestURLTestSelectSkipsSharedOpenCircuitButKeepsRecoveryPath(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	first := newSmartFakeOutbound("fast-but-open", nil)
	second := newSmartFakeOutbound("healthy-backup", nil)
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	history.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	group := &URLTestGroup{outbound: manager, outbounds: []adapter.Outbound{first, second}, history: history, tolerance: 50}
	store.openEndpointCircuit(time.Now(), "network-default", first.Tag(), "tcp")
	selected, ok := group.Select("tcp")
	if !ok || selected != second {
		t.Fatalf("URLTest did not skip shared open circuit: selected=%v ok=%v", selected, ok)
	}
	store.openEndpointCircuit(time.Now(), "network-default", second.Tag(), "tcp")
	selected, ok = group.Select("tcp")
	if !ok || selected != first {
		t.Fatalf("URLTest lost all-open recovery path: selected=%v ok=%v", selected, ok)
	}
}

func TestURLTestProbesUseSharedHealthCandidatesButKeepRecoveryPath(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	first := newSmartFakeOutbound("open-candidate", nil)
	second := newSmartFakeOutbound("healthy-candidate", nil)
	group := &URLTestGroup{outbound: manager, outbounds: []adapter.Outbound{first, second}}
	store.openEndpointCircuit(time.Now(), "network-default", first.Tag(), "tcp")
	eligible := group.healthEligibleOutbounds("tcp")
	if len(eligible) != 1 || eligible[0] != second {
		t.Fatalf("URLTest probe set ignored shared health gate: %#v", eligible)
	}
	store.openEndpointCircuit(time.Now(), "network-default", second.Tag(), "tcp")
	eligible = group.healthEligibleOutbounds("tcp")
	if len(eligible) != 2 || eligible[0] != first || eligible[1] != second {
		t.Fatalf("URLTest probe set lost all-open recovery path: %#v", eligible)
	}
}

func TestURLTestCachedSelectionRechecksSharedHealth(t *testing.T) {
	manager := &smartFakeOutboundManager{}
	store, release, _ := acquireSmartHealthStore(context.Background(), manager, smartHealthStoreConfig{halfLife: time.Hour, breakerFailures: 1, breakerCooldown: time.Minute})
	defer release()
	first := newSmartFakeOutbound("cached-candidate", nil)
	second := newSmartFakeOutbound("healthy-backup", nil)
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	history.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	group := &URLTestGroup{outbound: manager, outbounds: []adapter.Outbound{first, second}, history: history, tolerance: 50}
	if selected, ok := group.currentOrSelect(first, "tcp"); !ok || selected != first {
		t.Fatalf("healthy cached candidate was not retained: selected=%v ok=%v", selected, ok)
	}
	store.openEndpointCircuit(time.Now(), "network-default", first.Tag(), "tcp")
	if selected, ok := group.currentOrSelect(first, "tcp"); !ok || selected != second {
		t.Fatalf("cached URLTest selection bypassed shared open circuit: selected=%v ok=%v", selected, ok)
	}
}
