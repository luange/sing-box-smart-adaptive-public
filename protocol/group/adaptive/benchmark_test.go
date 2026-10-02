package adaptive

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type benchmarkExecutionPort struct{}

func (benchmarkExecutionPort) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, context.Canceled
}
func (benchmarkExecutionPort) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func BenchmarkCatalogPrepareCommitScales(b *testing.B) {
	for _, size := range []int{500, 10_000, 100_000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			nodes := make([]CanonicalNode, size)
			bindings := make(map[NodeID]ExecutionPort, size)
			handles := make(map[NodeID]NodeHandle, size)
			port := benchmarkExecutionPort{}
			for index := range size {
				value := index + 1
				id := NodeID{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}
				nodes[index] = CanonicalNode{NodeID: id, SourceKey: "node-" + strconv.Itoa(index), Aliases: []string{"node-" + strconv.Itoa(index)}, Transport: []string{N.NetworkTCP}, IdentityStable: true}
				bindings[id] = port
				handles[id] = NodeHandle{NodeID: id, Slot: uint64(index + 1), Version: 1, BornRevision: 1}
			}
			source := SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 1, Nodes: nodes}, Bindings: bindings}
			identity := RuntimeIdentity{EpochID: 1, Revision: 1, SourceGeneration: 1, Handles: handles}
			catalog := NewCatalogPort()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				prepared, err := catalog.PrepareCommitted(source, identity)
				if err != nil {
					b.Fatal(err)
				}
				if catalog.CommitPrepared(prepared) == nil {
					b.Fatal("catalog commit returned nil view")
				}
			}
		})
	}
}

func BenchmarkCatalogBuildFiveHundred(b *testing.B) {
	hasher := benchmarkIdentityHasher(b)
	roots := make([]A48SourceRoot, 0, 500)
	manager := make(map[string]adapter.Outbound, 500)
	for index := range 500 {
		tag := "node-" + strconv.Itoa(index)
		candidate := newTestOutbound(tag)
		manager[tag] = candidate
		options := option.Outbound{Type: "test", Options: struct {
			Server string `json:"server"`
		}{Server: tag + ".example"}}
		roots = append(roots, A48SourceRoot{Outbound: candidate, Options: &options, Source: "provider"})
	}
	sourceAdapter := NewA48SourceAdapterV1(1, hasher, roots, func(tag string) (adapter.Outbound, bool) {
		candidate, loaded := manager[tag]
		return candidate, loaded
	})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := sourceAdapter.Snapshot(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyPlanFiveHundred(b *testing.B) {
	health := NewHealthStore(time.Hour, 1024)
	candidates := make([]Candidate, 500)
	byID := make(map[NodeID]int, len(candidates))
	for index := range candidates {
		id := NodeID{byte(index), byte(index >> 8)}
		candidates[index] = Candidate{ID: id, PrimaryTag: "node-" + strconv.Itoa(index)}
		byID[id] = index
		health.Observe(Observation{NodeID: id, Scope: ScopeEndpoint, Outcome: OutcomeSuccess, Delay: time.Duration(index+1) * time.Millisecond})
	}
	engine := NewPolicyEngine(health, 3, "fallback")
	snapshot := &ExecutionSnapshot{Generation: 1, Candidates: candidates, ByID: byID}
	service := ServiceContext{ID: "benchmark", Transport: N.NetworkTCP, Mode: ModeAdaptive}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := engine.Plan(snapshot, service, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeasePeek(b *testing.B) {
	manager := NewSessionLeaseManager(8192)
	key := SessionKey{1}
	manager.Replace(key, NodeID{}, NodeID{2}, "benchmark", ModeAdaptive, time.Hour, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, loaded := manager.Peek(key, time.Now()); !loaded {
			b.Fatal("lease disappeared")
		}
	}
}

func benchmarkIdentityHasher(b *testing.B) *IdentityHasher {
	b.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	hasher, err := NewIdentityHasher(key)
	if err != nil {
		b.Fatal(err)
	}
	return hasher
}
