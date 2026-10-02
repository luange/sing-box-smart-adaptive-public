package adaptive

import (
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func portNode(id NodeID, tag string) CanonicalNode {
	return CanonicalNode{NodeID: id, SourceKey: tag, Aliases: []string{tag}, Transport: []string{"tcp"}, IdentityStable: true}
}

func portSource(generation uint64, nodes ...CanonicalNode) SourcePublication {
	bindings := make(map[NodeID]ExecutionPort, len(nodes))
	for _, node := range nodes {
		bindings[node.NodeID] = newTestOutbound(node.SourceKey)
	}
	return SourcePublication{SourceSnapshot: SourceSnapshot{Generation: generation, Nodes: nodes}, Bindings: bindings}
}

type catalogTestPublisher struct {
	manager *RuntimeManager
	groupID string
	epochID RuntimeEpochID
}

func newCatalogTestPublisher() *catalogTestPublisher {
	return &catalogTestPublisher{manager: NewRuntimeManager(), groupID: "test-group"}
}

func (p *catalogTestPublisher) publish(port *CatalogPort, source SourcePublication) (*ExecutionSnapshot, error) {
	identitySource, err := IdentityFromSource(source.SourceSnapshot)
	if err != nil {
		return nil, err
	}
	var preparedIdentity *PreparedIdentity
	if p.epochID == 0 {
		preparedIdentity, err = p.manager.PrepareEpoch(p.groupID, NewHealthStore(time.Hour, 8), NewSessionLeaseManager(8), new(ControlState), identitySource)
	} else {
		preparedIdentity, err = p.manager.PrepareRevision(p.groupID, p.epochID, identitySource)
	}
	if err != nil {
		return nil, err
	}
	preparedExecution, err := port.PrepareCommitted(source, preparedIdentity.Identity())
	if err != nil {
		return nil, err
	}
	_, identity, err := preparedIdentity.Commit()
	if err != nil {
		return nil, err
	}
	p.epochID = identity.EpochID
	return port.CommitPrepared(preparedExecution), nil
}

func TestCatalogPortFailedPrepareIsAtomicAndGenerationRetryable(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	if _, err := publisher.publish(port, portSource(1, portNode(NodeID{1}, "one"))); err != nil {
		t.Fatal(err)
	}
	bad := portNode(NodeID{}, "bad")
	if _, err := publisher.publish(port, portSource(2, bad)); err == nil {
		t.Fatal("malformed prepare succeeded")
	}
	if port.Snapshot().Generation != 1 {
		t.Fatal("failed prepare changed execution view")
	}
	if _, err := publisher.publish(port, portSource(2, portNode(NodeID{2}, "two"))); err != nil {
		t.Fatalf("generation retry failed: %v", err)
	}
}

func TestCatalogPortAuthoritativeEmptyNeverCallsRetiredOutbound(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	tcpOutbound := newDialTestOutbound("old-tcp", 0, nil)
	tcpPort, publisher := NewCatalogPort(), newCatalogTestPublisher()
	node := CanonicalNode{NodeID: NodeID{10}, SourceKey: "old-tcp", Aliases: []string{"old-tcp"}, Transport: []string{"tcp"}, IdentityStable: true}
	if _, err := publisher.publish(tcpPort, SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 1, Nodes: []CanonicalNode{node}}, Bindings: map[NodeID]ExecutionPort{node.NodeID: tcpOutbound}}); err != nil {
		t.Fatal(err)
	}
	if empty, err := publisher.publish(tcpPort, SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 2}}); err != nil || len(empty.Candidates) != 0 {
		t.Fatalf("empty publish failed: view=%+v err=%v", empty, err)
	}
	pool := &AdaptivePool{resolver: NewServiceResolver(testIdentityHasher(t), ModeAdaptive), leases: NewSessionLeaseManager(32), health: health, policy: NewPolicyEngine(health, 1, "fallback"), runner: NewAttemptRunner(time.Second, time.Second, tcpPort), catalog: tcpPort}
	if conn, err := pool.DialContext(udpFlowContext(1200), N.NetworkTCP, M.ParseSocksaddr("example.com:443")); err == nil || conn != nil {
		t.Fatalf("dial used retired candidate: conn=%v err=%v", conn, err)
	}
	if tcpOutbound.dials.Load() != 0 {
		t.Fatalf("retired outbound called %d times", tcpOutbound.dials.Load())
	}
}

func TestCatalogPortStatsAliasesSnapshotAndManagerHandleAreStable(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	node := portNode(NodeID{55}, "primary")
	node.Aliases = []string{"alias"}
	source := portSource(1, node)
	source.InputLeafCount, source.DuplicatesSuppressed = 2, 1
	view, err := publisher.publish(port, source)
	if err != nil {
		t.Fatal(err)
	}
	identity := publisher.manager.groups[publisher.groupID].epochs[publisher.epochID].handles[node.NodeID]
	if view.Candidates[0].Handle != identity || view.RuntimeEpochID != publisher.epochID || view.DuplicatesSuppressed != 1 || view.AliasToID["primary"] != node.NodeID || view.AliasToID["alias"] != node.NodeID {
		t.Fatalf("committed identity/stats lost: %+v", view)
	}
	view.Candidates[0].Aliases[0] = "changed"
	delete(view.AliasToID, "primary")
	current := port.Snapshot()
	if current.AliasToID["primary"] != node.NodeID || current.Candidates[0].Aliases[0] == "changed" {
		t.Fatal("execution snapshot leaked mutable state")
	}
}
