package adaptive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const adaptiveStateSchemaVersion = 3
const adaptiveStateFlushInterval = 250 * time.Millisecond

type persistedHealthRecord struct {
	NodeID              NodeID        `json:"node_id"`
	NodeSlot            uint64        `json:"node_slot"`
	NodeVersion         uint64        `json:"node_version"`
	Domain              FailureDomain `json:"domain"`
	Transport           string        `json:"transport,omitempty"`
	Service             string        `json:"service,omitempty"`
	Health              HealthState   `json:"health"`
	Breaker             BreakerState  `json:"breaker"`
	LastUpdated         time.Time     `json:"last_updated"`
	LastDelay           time.Duration `json:"last_delay,omitempty"`
	ThroughputBPS       float64       `json:"throughput_bps,omitempty"`
	ThroughputSamples   uint64        `json:"throughput_samples,omitempty"`
	Successes           uint64        `json:"successes,omitempty"`
	Failures            uint64        `json:"failures,omitempty"`
	NonBreakerSuccesses uint64        `json:"non_breaker_successes,omitempty"`
	NonBreakerFailures  uint64        `json:"non_breaker_failures,omitempty"`
	EvidenceWeight      float64       `json:"evidence_weight,omitempty"`
	ConsecutiveFailures int           `json:"consecutive_failures,omitempty"`
	OpenUntil           time.Time     `json:"open_until,omitempty"`
	Backoff             time.Duration `json:"backoff,omitempty"`
	ReopenCount         int           `json:"reopen_count,omitempty"`
}

type persistedAdaptiveState struct {
	Health          []persistedHealthRecord `json:"health,omitempty"`
	Leases          []SessionLease          `json:"leases,omitempty"`
	Identity        *persistedIdentityState `json:"identity,omitempty"`
	Pinned          NodeID                  `json:"pinned,omitempty"`
	PinnedTag       string                  `json:"pinned_tag,omitempty"`
	LatestTag       string                  `json:"latest_tag,omitempty"`
	BulkSequence    uint64                  `json:"bulk_sequence,omitempty"`
	ControlRevision uint64                  `json:"control_revision,omitempty"`
}

type persistedIdentityState struct {
	NextEpoch    RuntimeEpochID             `json:"next_epoch"`
	NextRevision CatalogRevision            `json:"next_revision"`
	NextSlot     uint64                     `json:"next_slot"`
	Lineage      []persistedIdentityLineage `json:"lineage,omitempty"`
}

type persistedIdentityLineage struct {
	NodeID          NodeID     `json:"node_id"`
	Handle          NodeHandle `json:"handle"`
	PresentInLatest bool       `json:"present_in_latest"`
}

type adaptiveStateEnvelope struct {
	Version   int             `json:"version"`
	WrittenAt time.Time       `json:"written_at"`
	Checksum  string          `json:"checksum"`
	Payload   json.RawMessage `json:"payload"`
}

type adaptiveStateWriter struct {
	pool  *AdaptivePool
	dirty chan struct{}
	flush chan chan error
	stop  chan struct{}
	done  chan struct{}
	close sync.Once
}

func newAdaptiveStateWriter(pool *AdaptivePool) *adaptiveStateWriter {
	w := &adaptiveStateWriter{pool: pool, dirty: make(chan struct{}, 1), flush: make(chan chan error), stop: make(chan struct{}), done: make(chan struct{})}
	go w.run()
	return w
}

func (w *adaptiveStateWriter) Flush() error {
	if w == nil {
		return nil
	}
	reply := make(chan error, 1)
	select {
	case w.flush <- reply:
		return <-reply
	case <-w.done:
		return errors.New("adaptive state writer is closed")
	}
}

func (w *adaptiveStateWriter) Submit() {
	if w == nil {
		return
	}
	select {
	case w.dirty <- struct{}{}:
	default:
	}
}

func (w *adaptiveStateWriter) Close() {
	if w == nil {
		return
	}
	w.close.Do(func() { close(w.stop) })
	<-w.done
}

func (w *adaptiveStateWriter) run() {
	defer close(w.done)
	var timer *time.Timer
	var timerChannel <-chan time.Time
	dirty := false
	flush := func(force bool) error {
		if !dirty {
			if !force {
				return nil
			}
		}
		dirty = false
		err := writeAdaptiveState(w.pool.persistentStatePath(), w.pool.persistenceSnapshot(time.Now()))
		if err != nil {
			w.pool.statePersistenceFailures.Add(1)
		}
		return err
	}
	for {
		select {
		case <-w.dirty:
			dirty = true
			if timer == nil {
				timer = time.NewTimer(adaptiveStateFlushInterval)
				timerChannel = timer.C
			} else if timerChannel == nil {
				timer.Reset(adaptiveStateFlushInterval)
				timerChannel = timer.C
			}
		case <-timerChannel:
			timerChannel = nil
			_ = flush(false)
		case reply := <-w.flush:
			if timer != nil && timerChannel != nil {
				timer.Stop()
				timerChannel = nil
			}
			reply <- flush(true)
		case <-w.stop:
			if timer != nil {
				timer.Stop()
			}
			select {
			case <-w.dirty:
				dirty = true
			default:
			}
			_ = flush(false)
			return
		}
	}
}

func (p *AdaptivePool) persistStateDurable() error {
	health, leases, _, _ := p.runtimeSnapshot()
	if p == nil || p.statePath == "" || health == nil || leases == nil {
		return nil
	}
	if p.stateWriter != nil {
		return p.stateWriter.Flush()
	}
	p.statePersistenceAccess.Lock()
	err := writeAdaptiveState(p.persistentStatePath(), p.persistenceSnapshot(time.Now()))
	if err != nil {
		p.statePersistenceFailures.Add(1)
	}
	p.statePersistenceAccess.Unlock()
	return err
}

func (p *AdaptivePool) persistentStatePath() string { return p.statePath + ".json" }

func (p *AdaptivePool) persistenceSnapshot(now time.Time) persistedAdaptiveState {
	// Health, breaker and lease state is deliberately process-local. A new
	// process must prove every candidate again instead of trusting observations
	// made by an earlier process. Only stable identity and explicit control state
	// are durable.
	state := persistedAdaptiveState{}
	if p.runtimeManager != nil && p.groupID != "" {
		state.Identity = p.runtimeManager.PersistenceSnapshot(p.groupID)
	}
	_, _, control, _ := p.runtimeSnapshot()
	if control != nil {
		control.access.RLock()
		state.Pinned, state.PinnedTag = control.pinned, safePersistentTag(control.pinnedTag)
		control.access.RUnlock()
		state.BulkSequence = control.bulkSequence.Load()
		state.ControlRevision = control.revision.Load()
	}
	return state
}

func safePersistentTag(value string) string {
	lower := strings.ToLower(value)
	if len(value) > 256 || strings.Contains(value, "://") || strings.Contains(value, "?") || strings.Contains(lower, "token=") || strings.Contains(lower, "sig=") || strings.Contains(lower, "expire=") {
		return ""
	}
	return value
}

func (p *AdaptivePool) persistState() {
	health, leases, _, _ := p.runtimeSnapshot()
	if p == nil || p.statePath == "" || health == nil || leases == nil {
		return
	}
	if p.stateWriter != nil {
		p.stateWriter.Submit()
		return
	}
	p.statePersistenceAccess.Lock()
	if err := writeAdaptiveState(p.persistentStatePath(), p.persistenceSnapshot(time.Now())); err != nil {
		p.statePersistenceFailures.Add(1)
	}
	p.statePersistenceAccess.Unlock()
}

func (p *AdaptivePool) loadPersistentState() {
	health, leases, control, _ := p.runtimeSnapshot()
	if p == nil || p.statePath == "" || health == nil || leases == nil {
		return
	}
	state, err := readAdaptiveState(p.persistentStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		p.statePersistenceFailures.Add(1)
		return
	}
	if state.Identity != nil && p.runtimeManager != nil && p.groupID != "" {
		if err = p.runtimeManager.RestorePersistence(p.groupID, health, leases, control, state.Identity); err != nil {
			p.statePersistenceFailures.Add(1)
			return
		}
	}
	if control != nil {
		control.access.Lock()
		control.pinned, control.pinnedTag = state.Pinned, state.PinnedTag
		control.latestTag = ""
		control.access.Unlock()
		control.bulkSequence.Store(state.BulkSequence)
		control.revision.Store(state.ControlRevision)
	}
}

func writeAdaptiveState(path string, state persistedAdaptiveState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	envelope, err := json.Marshal(adaptiveStateEnvelope{Version: adaptiveStateSchemaVersion, WrittenAt: time.Now(), Checksum: hex.EncodeToString(digest[:]), Payload: payload})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".adaptive-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(envelope)
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

func readAdaptiveState(path string) (persistedAdaptiveState, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return persistedAdaptiveState{}, err
	}
	var envelope adaptiveStateEnvelope
	if err = json.Unmarshal(content, &envelope); err != nil || (envelope.Version != 1 && envelope.Version != 2 && envelope.Version != adaptiveStateSchemaVersion) || len(envelope.Payload) == 0 {
		return persistedAdaptiveState{}, errors.New("adaptive persisted state envelope is invalid")
	}
	digest := sha256.Sum256(envelope.Payload)
	if envelope.Checksum != hex.EncodeToString(digest[:]) {
		return persistedAdaptiveState{}, errors.New("adaptive persisted state checksum mismatch")
	}
	var state persistedAdaptiveState
	if err = json.Unmarshal(envelope.Payload, &state); err != nil {
		return persistedAdaptiveState{}, errors.New("adaptive persisted state payload is invalid")
	}
	return state, nil
}
