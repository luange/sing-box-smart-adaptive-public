package adaptive

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/sagernet/sing-box/common/nodefilter"
)

// CanonicalNode is the only node shape consumed by the future catalog. It has
// no dependency on option.Outbound or provider slice layout.
type CanonicalNode struct {
	NodeID NodeID
	// EndpointID deliberately excludes credentials. NodeID remains credential
	// specific; EndpointID only groups competing credentials for one endpoint.
	EndpointID            NodeID
	EndpointConflictCount int
	SourceKey             string
	Aliases               []string
	Transport             []string
	Metadata              map[string]string
	IdentityStable        bool
}

type SourceSnapshot struct {
	Generation           uint64
	Nodes                []CanonicalNode
	InputLeafCount       int
	DuplicatesSuppressed int
}

// SourcePublication is the anti-corruption handoff. Its embedded snapshot is
// pure canonical data; bindings are consumed only by CatalogPort prepare.
type SourcePublication struct {
	SourceSnapshot
	Bindings map[NodeID]ExecutionPort
}

type SourceDelta struct {
	Generation uint64
	Upserts    []CanonicalNode
	Removes    []NodeID
}

type SourceDeltaPublication struct {
	SourceDelta
	Bindings             map[NodeID]ExecutionPort
	InputLeafCount       int
	DuplicatesSuppressed int
}

type SourceAdapter interface {
	Snapshot(context.Context) (SourcePublication, error)
}

// SourceRuntime owns the upstream provider/group lifecycle. AdaptivePool only
// sees canonical snapshots and never stores upstream array objects.
type SourceRuntime interface {
	Start(func() error) error
	Close() error
	Snapshot(context.Context, uint64) (SourcePublication, error)
}

type IncrementalSourceRuntime interface {
	SourceRuntime
	Delta(context.Context, uint64) (SourceDeltaPublication, error)
}

type SourceRuntimeConfig struct {
	StaticTags           []string
	ProviderTags         []string
	UseAll               bool
	ProviderPollInterval time.Duration
	Include              *regexp.Regexp
	Exclude              *regexp.Regexp
	ManualExclude        *nodefilter.Matcher
}

type SourceDeltaAdapter interface {
	SourceAdapter
	Subscribe(context.Context, func(SourceDelta) error) error
}

var ErrSourceGenerationOutOfOrder = errors.New("adaptive source generation is not newer")

func DiffSourcePublication(previous, current SourcePublication) (SourceDeltaPublication, error) {
	if current.Generation == 0 || previous.Generation == 0 || current.Generation <= previous.Generation {
		return SourceDeltaPublication{}, ErrSourceGenerationOutOfOrder
	}
	previousNodes := make(map[NodeID]CanonicalNode, len(previous.Nodes))
	for _, node := range previous.Nodes {
		previousNodes[node.NodeID] = node
	}
	delta := SourceDeltaPublication{SourceDelta: SourceDelta{Generation: current.Generation}, Bindings: make(map[NodeID]ExecutionPort), InputLeafCount: current.InputLeafCount, DuplicatesSuppressed: current.DuplicatesSuppressed}
	seen := make(map[NodeID]struct{}, len(current.Nodes))
	for _, node := range current.Nodes {
		seen[node.NodeID] = struct{}{}
		old, loaded := previousNodes[node.NodeID]
		if !loaded || !canonicalNodeEqual(old, node) || !executionPortEqual(previous.Bindings[node.NodeID], current.Bindings[node.NodeID]) {
			delta.Upserts = append(delta.Upserts, cloneCanonicalNode(node))
			delta.Bindings[node.NodeID] = current.Bindings[node.NodeID]
		}
	}
	for _, node := range previous.Nodes {
		if _, loaded := seen[node.NodeID]; !loaded {
			delta.Removes = append(delta.Removes, node.NodeID)
		}
	}
	return delta, nil
}

func ApplySourceDelta(previous SourcePublication, delta SourceDeltaPublication) (SourcePublication, error) {
	if previous.Generation == 0 || delta.Generation <= previous.Generation {
		return SourcePublication{}, ErrSourceGenerationOutOfOrder
	}
	byID := make(map[NodeID]CanonicalNode, len(previous.Nodes)+len(delta.Upserts))
	order := make([]NodeID, 0, len(previous.Nodes)+len(delta.Upserts))
	bindings := make(map[NodeID]ExecutionPort, len(previous.Bindings)+len(delta.Bindings))
	for _, node := range previous.Nodes {
		byID[node.NodeID] = cloneCanonicalNode(node)
		order = append(order, node.NodeID)
		bindings[node.NodeID] = previous.Bindings[node.NodeID]
	}
	removed := make(map[NodeID]struct{}, len(delta.Removes))
	for _, id := range delta.Removes {
		removed[id] = struct{}{}
		delete(byID, id)
		delete(bindings, id)
	}
	for _, node := range delta.Upserts {
		if node.NodeID == (NodeID{}) || delta.Bindings[node.NodeID] == nil {
			return SourcePublication{}, errors.New("adaptive source delta upsert is invalid")
		}
		if _, loaded := byID[node.NodeID]; !loaded {
			order = append(order, node.NodeID)
		}
		byID[node.NodeID] = cloneCanonicalNode(node)
		bindings[node.NodeID] = delta.Bindings[node.NodeID]
	}
	nodes := make([]CanonicalNode, 0, len(byID))
	for _, id := range order {
		if _, deleted := removed[id]; deleted {
			continue
		}
		if node, loaded := byID[id]; loaded {
			nodes = append(nodes, node)
			delete(byID, id)
		}
	}
	for _, node := range delta.Upserts {
		if remaining, loaded := byID[node.NodeID]; loaded {
			nodes = append(nodes, remaining)
			delete(byID, node.NodeID)
		}
	}
	return SourcePublication{SourceSnapshot: SourceSnapshot{Generation: delta.Generation, Nodes: nodes, InputLeafCount: delta.InputLeafCount, DuplicatesSuppressed: delta.DuplicatesSuppressed}, Bindings: bindings}, nil
}

func cloneCanonicalNode(node CanonicalNode) CanonicalNode {
	node.Aliases = append([]string(nil), node.Aliases...)
	node.Transport = append([]string(nil), node.Transport...)
	if node.Metadata != nil {
		metadata := make(map[string]string, len(node.Metadata))
		for key, value := range node.Metadata {
			metadata[key] = value
		}
		node.Metadata = metadata
	}
	return node
}

func canonicalNodeEqual(first, second CanonicalNode) bool {
	return first.NodeID == second.NodeID && first.EndpointID == second.EndpointID && first.EndpointConflictCount == second.EndpointConflictCount && first.SourceKey == second.SourceKey && first.IdentityStable == second.IdentityStable && stringSlicesEqual(first.Aliases, second.Aliases) && stringSlicesEqual(first.Transport, second.Transport) && stringMapsEqual(first.Metadata, second.Metadata)
}

func stringSlicesEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func stringMapsEqual(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range first {
		if second[key] != value {
			return false
		}
	}
	return true
}

func executionPortEqual(first, second ExecutionPort) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	firstValue, secondValue := reflect.ValueOf(first), reflect.ValueOf(second)
	return firstValue.Type() == secondValue.Type() && firstValue.Type().Comparable() && firstValue.Interface() == secondValue.Interface()
}
