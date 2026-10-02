package adaptive

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type memSnapshot struct {
	HeapInuse  uint64
	HeapAlloc  uint64
	Sys        uint64
	NumGC      uint32
	Goroutines int
}

func readMemSnapshot() memSnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return memSnapshot{
		HeapInuse:  stats.HeapInuse,
		HeapAlloc:  stats.HeapAlloc,
		Sys:        stats.Sys,
		NumGC:      stats.NumGC,
		Goroutines: runtime.NumGoroutine(),
	}
}

func writeHeapProfile(t *testing.T, path string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = pprof.WriteHeapProfile(file); err != nil {
		t.Fatal(err)
	}
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%dB", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f%ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatBytesSigned(value int64) string {
	if value < 0 {
		return "-" + formatBytes(uint64(-value))
	}
	return "+" + formatBytes(uint64(value))
}

// TestGateReloadHeapBounded measures adaptive lifecycle memory across 1000
// same-group publish/retire cycles with sticky/observation/status activity.
//
// Profiles are written for offline pprof. Full-process RSS on a production VM
// still needs the packaged binary; this gate bounds AdaptivePool control-plane
// heap retention per reload.
func TestGateReloadHeapBounded(t *testing.T) {
	const cycles = 1000
	const nodeCount = 32

	outDir := os.Getenv("ADAPTIVE_HEAP_OUT")
	if outDir == "" {
		outDir = t.TempDir()
	} else if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	manager := NewRuntimeManager()
	groupID := "reload-heap-gate"

	canonical := make([]CanonicalNode, nodeCount)
	for i := 0; i < nodeCount; i++ {
		canonical[i] = portNode(NodeID{byte(i + 1)}, fmt.Sprintf("node-%d", i))
	}

	runtime.GC()
	runtime.GC()
	base := readMemSnapshot()
	writeHeapProfile(t, filepath.Join(outDir, "adaptive-reload-0.pb.gz"))

	for cycle := 0; cycle < cycles; cycle++ {
		manager.RegisterGroup(groupID)
		pool := preparedReloadPool(t, manager, groupID, uint64(cycle+1), canonical)
		if err := pool.OnRuntimeEpochPublish(); err != nil {
			t.Fatalf("cycle %d publish: %v", cycle, err)
		}
		pool.OnRuntimeEpochPublishCommit()

		now := time.Now()
		snap := pool.catalog.load()
		if snap == nil || len(snap.Candidates) == 0 {
			t.Fatalf("cycle %d missing candidates", cycle)
		}
		for _, candidate := range snap.Candidates {
			pool.health.Observe(Observation{
				NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version,
				Scope: DomainEndpoint, Outcome: OutcomeSuccess,
				Delay: time.Duration(20+int(candidate.Handle.Slot)) * time.Millisecond, At: now,
			})
			if candidate.Handle.Slot%4 == 0 {
				pool.health.Observe(Observation{
					NodeID: candidate.ID, NodeSlot: candidate.Handle.Slot, NodeVersion: candidate.Handle.Version,
					Scope: DomainTransport, Transport: "udp_dns/ipv4", Outcome: OutcomeSuccess,
					Delay: 12 * time.Millisecond, At: now,
				})
			}
		}
		svc := ServiceContext{
			ID: "chatgpt_web", AffinityID: "chatgpt_web",
			Session: SessionKey{byte(cycle % 7), 1}, Mode: ModeAdaptive,
			Transport: N.NetworkTCP, HealthTransport: "tcp/ipv4",
		}
		pool.rememberPolicySelectionWithReason(svc, snap.Candidates[cycle%len(snap.Candidates)], ReasonRanked)
		_ = pool.AdaptiveStatus()

		if err := pool.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", cycle, err)
		}

		if cycle == 0 {
			runtime.GC()
			writeHeapProfile(t, filepath.Join(outDir, "adaptive-reload-1.pb.gz"))
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	final := readMemSnapshot()
	writeHeapProfile(t, filepath.Join(outDir, "adaptive-reload-1000.pb.gz"))

	groups, schedulers, users := manager.RuntimeStats()
	if groups != 0 || schedulers != 0 || users != 0 {
		t.Fatalf("runtime residue after reload gate: groups=%d schedulers=%d users=%d", groups, schedulers, users)
	}

	heapDelta := int64(final.HeapInuse) - int64(base.HeapInuse)
	allocDelta := int64(final.HeapAlloc) - int64(base.HeapAlloc)
	sysDelta := int64(final.Sys) - int64(base.Sys)

	report := fmt.Sprintf(
		"reload_heap_gate cycles=%d nodes=%d\n"+
			"base  heap_inuse=%s heap_alloc=%s sys=%s num_gc=%d goroutines=%d\n"+
			"final heap_inuse=%s heap_alloc=%s sys=%s num_gc=%d goroutines=%d\n"+
			"delta heap_inuse=%s heap_alloc=%s sys=%s\n"+
			"profiles dir=%s\n"+
			"files: adaptive-reload-0.pb.gz adaptive-reload-1.pb.gz adaptive-reload-1000.pb.gz\n",
		cycles, nodeCount,
		formatBytes(base.HeapInuse), formatBytes(base.HeapAlloc), formatBytes(base.Sys), base.NumGC, base.Goroutines,
		formatBytes(final.HeapInuse), formatBytes(final.HeapAlloc), formatBytes(final.Sys), final.NumGC, final.Goroutines,
		formatBytesSigned(heapDelta), formatBytesSigned(allocDelta), formatBytesSigned(sysDelta),
		outDir,
	)
	t.Log(report)
	if err := os.WriteFile(filepath.Join(outDir, "adaptive-reload-heap-summary.txt"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}

	// Absolute budget after 1000 reloads with 32-node activity.
	const maxHeapInuseGrowth = 24 << 20
	if heapDelta > maxHeapInuseGrowth {
		t.Fatalf("heap_inuse growth %s exceeds budget %s after %d reloads", formatBytesSigned(heapDelta), formatBytes(maxHeapInuseGrowth), cycles)
	}
	if final.Goroutines > base.Goroutines+64 {
		t.Fatalf("goroutine growth %d -> %d suggests leak", base.Goroutines, final.Goroutines)
	}
}

func preparedReloadPool(t *testing.T, manager *RuntimeManager, groupID string, generation uint64, nodes []CanonicalNode) *AdaptivePool {
	t.Helper()
	health := NewHealthStore(time.Hour, 256)
	pool := &AdaptivePool{
		ctx:                 context.Background(),
		groupID:             groupID,
		runtimeManager:      manager,
		health:              health,
		leases:              NewSessionLeaseManager(256),
		control:             new(ControlState),
		policy:              NewPolicyEngine(health, 3, "fallback").BindSwitchStability(0.15, 2*time.Minute),
		policyMaxAttempts:   3,
		manualFailure:       "fallback",
		catalog:             NewCatalogPort(),
		publishPhase:        publishPhasePrepared,
		switchAudit:         NewSwitchAuditStore(),
		selectionMemory:     make(map[selectionMemoryKey]selectionMemoryEntry),
		observationIngestor: NewObservationIngestor(nil, nil, time.Minute, 4096),
		defaultMode:         ModeAdaptive,
	}
	source := portSource(generation, nodes...)
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	pool.preparedIdentity, err = manager.PrepareEpoch(groupID, pool.health, pool.leases, pool.control, identitySource)
	if err != nil {
		t.Fatal(err)
	}
	pool.preparedExecution, err = pool.catalog.PrepareCommitted(source, pool.preparedIdentity.Identity())
	if err != nil {
		t.Fatal(err)
	}
	return pool
}
