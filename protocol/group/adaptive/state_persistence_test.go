package adaptive

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adaptiveSIGKILLHelperEnv = "SING_BOX_ADAPTIVE_SIGKILL_HELPER"

func TestAdaptiveStateSurvivesSIGKILLAndRestarts(t *testing.T) {
	if path := os.Getenv(adaptiveSIGKILLHelperEnv); path != "" {
		runAdaptiveSIGKILLHelper(t, path)
		return
	}

	path := filepath.Join(t.TempDir(), "adaptive-state")
	command := exec.Command(os.Args[0], "-test.run=^TestAdaptiveStateSurvivesSIGKILLAndRestarts$")
	command.Env = append(os.Environ(), adaptiveSIGKILLHelperEnv+"="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	defer func() {
		if !killed && command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "READY" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("SIGKILL helper did not become ready: stdout=%q scanErr=%v stderr=%s", scanner.Text(), scanner.Err(), stderr.String())
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killed = true
	if err = command.Wait(); err == nil {
		t.Fatal("SIGKILL helper exited successfully instead of being killed")
	}

	state, err := readAdaptiveState(path + ".json")
	if err != nil {
		t.Fatalf("durable state was unreadable after SIGKILL: %v", err)
	}
	if state.Identity == nil || len(state.Identity.Lineage) != 1 || len(state.Health) != 0 || len(state.Leases) != 0 {
		t.Fatalf("SIGKILL restored a partial snapshot: identity=%+v health=%d", state.Identity, len(state.Health))
	}
	if state.LatestTag != "" {
		t.Fatalf("runtime selection survived SIGKILL: latest=%q", state.LatestTag)
	}

	manager := NewRuntimeManager()
	health := NewHealthStore(time.Hour, 8)
	leases := NewSessionLeaseManager(8)
	control := new(ControlState)
	if err = manager.RestorePersistence("sigkill", health, leases, control, state.Identity); err != nil {
		t.Fatal(err)
	}
	oldEpoch := state.Identity.NextEpoch
	if _, err = manager.AcquireEpoch("sigkill", oldEpoch); err == nil {
		t.Fatal("restart restored an active epoch from disk")
	}
	nodeID := NodeID{121}
	previous := state.Identity.Lineage[0].Handle
	prepared, err := manager.PrepareEpoch("sigkill", health, leases, control, identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	if err != nil {
		t.Fatal(err)
	}
	_, restarted, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if restarted.EpochID <= oldEpoch || restarted.Revision <= state.Identity.NextRevision || restarted.Handles[nodeID] != previous {
		t.Fatalf("restart did not preserve lineage and advance counters: previous=%+v restarted=%+v", previous, restarted)
	}
}

func runAdaptiveSIGKILLHelper(t *testing.T, path string) {
	t.Helper()
	manager := NewRuntimeManager()
	manager.RegisterGroup("sigkill")
	health := NewHealthStore(time.Hour, 8)
	leases := NewSessionLeaseManager(8)
	control := &ControlState{latestTag: "durable"}
	nodeID := NodeID{121}
	prepared, err := manager.PrepareEpoch("sigkill", health, leases, control, identitySnapshot(1, IdentityNode{NodeID: nodeID, IdentityStable: true}))
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := prepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	handle := identity.Handles[nodeID]
	health.Observe(Observation{NodeID: nodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainEndpoint, Outcome: OutcomeSuccess, At: time.Now()})
	pool := &AdaptivePool{statePath: path, groupID: "sigkill", runtimeManager: manager, health: health, leases: leases, control: control}
	pool.stateWriter = newAdaptiveStateWriter(pool)
	if err = pool.persistStateDurable(); err != nil {
		t.Fatal(err)
	}
	control.access.Lock()
	control.latestTag = "pending"
	control.access.Unlock()
	pool.persistState()
	_, _ = fmt.Fprintln(os.Stdout, "READY")
	for {
		time.Sleep(time.Hour)
	}
}

func TestAdaptiveStateRestoresControlButNotHealthOrLeases(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "adaptive-state")
	openHandle := NodeHandle{NodeID: NodeID{91}, Slot: 1, Version: 2}
	halfOpenHandle := NodeHandle{NodeID: NodeID{92}, Slot: 2, Version: 3}
	validKey := SessionKey{1}
	expiredKey := SessionKey{2}
	state := persistedAdaptiveState{
		Health: []persistedHealthRecord{
			{NodeID: openHandle.NodeID, NodeSlot: openHandle.Slot, NodeVersion: openHandle.Version, Domain: DomainEndpoint, Health: HealthUnreachable, Breaker: BreakerOpen, LastUpdated: now, ThroughputBPS: 4 << 20, ThroughputSamples: 3, Failures: 3, ConsecutiveFailures: 3, OpenUntil: now.Add(time.Minute), Backoff: time.Minute},
			{NodeID: halfOpenHandle.NodeID, NodeSlot: halfOpenHandle.Slot, NodeVersion: halfOpenHandle.Version, Domain: DomainService, Service: youtubeProbeServiceID, Health: HealthDegraded, Breaker: BreakerHalfOpen, LastUpdated: now, Failures: 1, ConsecutiveFailures: 1, OpenUntil: now.Add(time.Minute)},
		},
		Leases: []SessionLease{
			{Key: validKey, NodeID: openHandle.NodeID, NodeSlot: openHandle.Slot, NodeVersion: openHandle.Version, ServiceID: "video", Mode: ModeAdaptive, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)},
			{Key: expiredKey, NodeID: halfOpenHandle.NodeID, NodeSlot: halfOpenHandle.Slot, NodeVersion: halfOpenHandle.Version, ServiceID: "expired", Mode: ModeAdaptive, UpdatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second)},
		},
		Pinned: openHandle.NodeID, PinnedTag: "node-a", LatestTag: "node-b", BulkSequence: 13,
	}
	if err := writeAdaptiveState(path+".json", state); err != nil {
		t.Fatal(err)
	}
	health := NewHealthStore(time.Hour, 16)
	leases := NewSessionLeaseManager(16)
	control := new(ControlState)
	pool := &AdaptivePool{statePath: path, health: health, leases: leases, control: control}
	pool.loadPersistentState()
	if pool.statePersistenceFailures.Load() != 0 {
		t.Fatal("valid state was reported as a persistence failure")
	}
	if status := health.EndpointHandle(openHandle); status.Health != HealthUnknown || status.Failures != 0 || status.Breaker != BreakerClosed {
		t.Fatalf("health observation survived process restart: %+v", status)
	}
	if status := health.StatusHandle(halfOpenHandle, DomainService, "", youtubeProbeServiceID); status.Health != HealthUnknown || status.Failures != 0 || status.Breaker != BreakerClosed {
		t.Fatalf("service observation survived process restart: %+v", status)
	}
	if lease, loaded := leases.Peek(validKey, now); loaded {
		t.Fatalf("lease survived process restart: %+v", lease)
	}
	if _, loaded := leases.Peek(expiredKey, now); loaded {
		t.Fatal("expired lease survived restart")
	}
	control.access.RLock()
	pinned, pinnedTag, latestTag := control.pinned, control.pinnedTag, control.latestTag
	control.access.RUnlock()
	if pinned != openHandle.NodeID || pinnedTag != "node-a" || latestTag != "" {
		t.Fatalf("control state was not restored: pinned=%v pinnedTag=%q latest=%q", pinned, pinnedTag, latestTag)
	}
	if control.bulkSequence.Load() != 13 {
		t.Fatalf("bulk sequence was not restored: %d", control.bulkSequence.Load())
	}
	info, err := os.Stat(path + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file permissions are not private: mode=%v", info.Mode().Perm())
	}
}

func TestAdaptiveStateRejectsCorruptionWithoutBlockingPool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive-state") + ".json"
	if err := writeAdaptiveState(path, persistedAdaptiveState{Pinned: NodeID{93}, PinnedTag: "node"}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-2] ^= 1
	if err = os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := &AdaptivePool{statePath: strings.TrimSuffix(path, ".json"), health: NewHealthStore(time.Hour, 8), leases: NewSessionLeaseManager(8), control: new(ControlState)}
	pool.loadPersistentState()
	if pool.statePersistenceFailures.Load() != 1 {
		t.Fatalf("corrupt state was not reported: %d", pool.statePersistenceFailures.Load())
	}
	if pool.control.pinned != (NodeID{}) {
		t.Fatal("corrupt state partially restored control data")
	}
}

func TestAdaptiveStateSnapshotExcludesPrivateTextAndWritesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive-state")
	pool := &AdaptivePool{statePath: path, health: NewHealthStore(time.Hour, 8), leases: NewSessionLeaseManager(8), control: &ControlState{pinned: NodeID{94}, pinnedTag: "https://secret.example/?token=private", latestTag: "node-safe"}}
	pool.persistState()
	content, err := os.ReadFile(path + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("secret.example")) || bytes.Contains(content, []byte("token=")) || bytes.Contains(content, []byte("private")) {
		t.Fatalf("private control text entered persisted state: %s", content)
	}
	state, err := readAdaptiveState(path + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pinned != (NodeID{94}) || state.PinnedTag != "" || state.LatestTag != "" {
		t.Fatalf("safe control snapshot changed: %+v", state)
	}
	if len(state.Health) != 0 || len(state.Leases) != 0 {
		t.Fatalf("process-local health or leases entered durable state: health=%d leases=%d", len(state.Health), len(state.Leases))
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".adaptive-state-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("atomic writer left temporary files: %v err=%v", matches, err)
	}
}

func TestAdaptiveStateWriterCoalescesAndCloseFlushesLatestState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive-state")
	pool := &AdaptivePool{statePath: path, health: NewHealthStore(time.Hour, 8), leases: NewSessionLeaseManager(8), control: new(ControlState)}
	pool.stateWriter = newAdaptiveStateWriter(pool)
	for index := 0; index < 100; index++ {
		pool.control.access.Lock()
		pool.control.pinnedTag = "node-pinned"
		pool.control.access.Unlock()
		pool.persistState()
	}
	pool.stateWriter.Close()
	state, err := readAdaptiveState(path + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if state.PinnedTag != "node-pinned" || state.LatestTag != "" || pool.statePersistenceFailures.Load() != 0 {
		t.Fatalf("coalesced writer did not flush latest state: state=%+v failures=%d", state, pool.statePersistenceFailures.Load())
	}
}

func TestRuntimeIdentityLineageSurvivesRestartWithoutRestoringEpoch(t *testing.T) {
	firstManager := NewRuntimeManager()
	health := NewHealthStore(time.Hour, 16)
	leases := NewSessionLeaseManager(16)
	control := new(ControlState)
	stableID, unstableID, removedID := NodeID{101}, NodeID{102}, NodeID{103}
	firstPrepared, err := firstManager.PrepareEpoch("durable-lineage", health, leases, control, identitySnapshot(1,
		IdentityNode{NodeID: stableID, IdentityStable: true},
		IdentityNode{NodeID: unstableID, IdentityStable: false},
		IdentityNode{NodeID: removedID, IdentityStable: true},
	))
	if err != nil {
		t.Fatal(err)
	}
	_, first, err := firstPrepared.Commit()
	if err != nil {
		t.Fatal(err)
	}
	removedV1 := first.Handles[removedID]
	revision, err := firstManager.PrepareRevision("durable-lineage", first.EpochID, identitySnapshot(2,
		IdentityNode{NodeID: stableID, IdentityStable: true},
		IdentityNode{NodeID: unstableID, IdentityStable: false},
	))
	if err != nil {
		t.Fatal(err)
	}
	_, current, err := revision.Commit()
	if err != nil {
		t.Fatal(err)
	}
	persisted := firstManager.PersistenceSnapshot("durable-lineage")
	if persisted == nil {
		t.Fatal("published lineage did not produce a persistence snapshot")
	}

	secondManager := NewRuntimeManager()
	secondHealth := NewHealthStore(time.Hour, 16)
	secondLeases := NewSessionLeaseManager(16)
	secondControl := new(ControlState)
	if err = secondManager.RestorePersistence("durable-lineage", secondHealth, secondLeases, secondControl, persisted); err != nil {
		t.Fatal(err)
	}
	if _, err = secondManager.AcquireEpoch("durable-lineage", first.EpochID); err == nil {
		t.Fatal("persisted process restored an old active epoch")
	}
	restarted, err := secondManager.PrepareEpoch("durable-lineage", secondHealth, secondLeases, secondControl, identitySnapshot(1,
		IdentityNode{NodeID: stableID, IdentityStable: true},
		IdentityNode{NodeID: unstableID, IdentityStable: false},
		IdentityNode{NodeID: removedID, IdentityStable: true},
	))
	if err != nil {
		t.Fatal(err)
	}
	_, restored, err := restarted.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if restored.EpochID <= current.EpochID || restored.Revision <= current.Revision {
		t.Fatalf("restart counters did not advance: before=%+v after=%+v", current, restored)
	}
	if restored.Handles[stableID] != current.Handles[stableID] {
		t.Fatalf("stable continuous node changed handle: before=%+v after=%+v", current.Handles[stableID], restored.Handles[stableID])
	}
	if restored.Handles[unstableID].Slot != current.Handles[unstableID].Slot || restored.Handles[unstableID].Version != current.Handles[unstableID].Version+1 {
		t.Fatalf("unstable node did not advance version: before=%+v after=%+v", current.Handles[unstableID], restored.Handles[unstableID])
	}
	if restored.Handles[removedID].Slot != removedV1.Slot || restored.Handles[removedID].Version != removedV1.Version+1 {
		t.Fatalf("remove/re-add node did not advance version: before=%+v after=%+v", removedV1, restored.Handles[removedID])
	}
}

func TestRuntimeIdentityPersistenceRejectsInvalidSeedAndDoesNotOverwriteLiveGroup(t *testing.T) {
	manager := NewRuntimeManager()
	health := NewHealthStore(time.Hour, 8)
	leases := NewSessionLeaseManager(8)
	control := new(ControlState)
	invalid := &persistedIdentityState{NextEpoch: 1, NextRevision: 1, NextSlot: 1, Lineage: []persistedIdentityLineage{
		{NodeID: NodeID{111}, Handle: NodeHandle{NodeID: NodeID{111}, Slot: 1, Version: 1, BornRevision: 1}, PresentInLatest: true},
		{NodeID: NodeID{112}, Handle: NodeHandle{NodeID: NodeID{112}, Slot: 1, Version: 1, BornRevision: 1}, PresentInLatest: true},
	}}
	if err := manager.RestorePersistence("invalid-lineage", health, leases, control, invalid); err == nil {
		t.Fatal("duplicate persisted slot was accepted")
	}
	valid := &persistedIdentityState{NextEpoch: 3, NextRevision: 4, NextSlot: 1, Lineage: []persistedIdentityLineage{{NodeID: NodeID{113}, Handle: NodeHandle{NodeID: NodeID{113}, Slot: 1, Version: 2, BornRevision: 2}, PresentInLatest: true}}}
	if err := manager.RestorePersistence("live-lineage", health, leases, control, valid); err != nil {
		t.Fatal(err)
	}
	before := manager.PersistenceSnapshot("live-lineage")
	staleDisk := &persistedIdentityState{NextEpoch: 999, NextRevision: 999, NextSlot: 999}
	if err := manager.RestorePersistence("live-lineage", NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), staleDisk); err != nil {
		t.Fatal(err)
	}
	after := manager.PersistenceSnapshot("live-lineage")
	if before.NextEpoch != after.NextEpoch || before.NextRevision != after.NextRevision || before.NextSlot != after.NextSlot || len(before.Lineage) != len(after.Lineage) {
		t.Fatalf("disk seed overwrote live manager: before=%+v after=%+v", before, after)
	}
}

func TestRuntimePublishRequiresDurableIdentityBeforeCatalogCommit(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "durable-publish")
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool.statePath = filepath.Join(blocker, "adaptive-state")
	if err := pool.OnRuntimeEpochPublish(); err == nil {
		t.Fatal("identity publish succeeded without durable state")
	}
	if pool.catalog.load() != nil {
		t.Fatal("execution catalog committed before durable identity")
	}
	manager.access.RLock()
	_, retained := manager.groups["durable-publish"]
	manager.access.RUnlock()
	if retained {
		t.Fatal("failed durable publish retained committed identity")
	}
	if pool.statePersistenceFailures.Load() == 0 {
		t.Fatal("durable publish failure was not observable")
	}
	pool.catalogAccess.Lock()
	preparedIdentity, preparedExecution := pool.preparedIdentity, pool.preparedExecution
	pool.catalogAccess.Unlock()
	if preparedIdentity != nil || preparedExecution != nil {
		t.Fatal("failed durable publish retained a consumed preparation")
	}
}

func TestAdaptiveStateMigratesV1WithSafeThroughputAndCursorDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive-state.json")
	state := persistedAdaptiveState{LatestTag: "node"}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	envelope, err := json.Marshal(adaptiveStateEnvelope{Version: 1, WrittenAt: time.Now(), Checksum: hex.EncodeToString(digest[:]), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := readAdaptiveState(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.BulkSequence != 0 || restored.LatestTag != "node" || len(restored.Health) != 0 {
		t.Fatalf("v1 state did not migrate into v2 shape: %+v", restored)
	}
}
