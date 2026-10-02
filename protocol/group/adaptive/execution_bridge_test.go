package adaptive

import (
	"testing"
)

func TestExecutionBridgeRejectsWrongEpochRevisionAndHandle(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	view, err := publisher.publish(port, portSource(1, portNode(NodeID{1}, "one")))
	if err != nil {
		t.Fatal(err)
	}
	token := ExecutionToken{RuntimeEpochID: view.RuntimeEpochID, CatalogRevision: view.CatalogRevision, Handle: view.Candidates[0].Handle}
	if execution, loaded := port.ResolveExecution(token); !loaded || execution == nil {
		t.Fatal("committed full handle did not resolve")
	}
	wrongEpoch := token
	wrongEpoch.RuntimeEpochID++
	wrongRevision := token
	wrongRevision.CatalogRevision++
	wrongVersion := token
	wrongVersion.Handle.Version++
	for name, candidate := range map[string]ExecutionToken{"epoch": wrongEpoch, "revision": wrongRevision, "version": wrongVersion} {
		if _, loaded := port.ResolveExecution(candidate); loaded {
			t.Fatalf("wrong %s resolved an execution binding", name)
		}
	}
}

func TestExecutionBridgeFailedPrepareKeepsCommittedBinding(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	view, err := publisher.publish(port, portSource(1, portNode(NodeID{2}, "stable")))
	if err != nil {
		t.Fatal(err)
	}
	token := ExecutionToken{RuntimeEpochID: view.RuntimeEpochID, CatalogRevision: view.CatalogRevision, Handle: view.Candidates[0].Handle}
	before, loaded := port.ResolveExecution(token)
	if !loaded {
		t.Fatal("initial binding missing")
	}
	bad := portSource(2, portNode(NodeID{3}, "bad"))
	bad.Bindings = nil
	if _, err = publisher.publish(port, bad); err == nil {
		t.Fatal("prepare without binding succeeded")
	}
	after, loaded := port.ResolveExecution(token)
	if !loaded || after != before || port.Snapshot().CatalogRevision != view.CatalogRevision {
		t.Fatal("failed prepare changed committed catalog or binding")
	}
}

func TestExecutionBridgeRemoveReaddCannotReuseOldVersion(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	v1, err := publisher.publish(port, portSource(1, portNode(NodeID{4}, "v1")))
	if err != nil {
		t.Fatal(err)
	}
	oldToken := ExecutionToken{RuntimeEpochID: v1.RuntimeEpochID, CatalogRevision: v1.CatalogRevision, Handle: v1.Candidates[0].Handle}
	if _, err = publisher.publish(port, SourcePublication{SourceSnapshot: SourceSnapshot{Generation: 2}}); err != nil {
		t.Fatal(err)
	}
	v2, err := publisher.publish(port, portSource(3, portNode(NodeID{4}, "v2")))
	if err != nil {
		t.Fatal(err)
	}
	newToken := ExecutionToken{RuntimeEpochID: v2.RuntimeEpochID, CatalogRevision: v2.CatalogRevision, Handle: v2.Candidates[0].Handle}
	if newToken.Handle.Version <= oldToken.Handle.Version {
		t.Fatalf("remove/re-add did not advance version: old=%+v new=%+v", oldToken.Handle, newToken.Handle)
	}
	if _, loaded := port.ResolveExecution(oldToken); loaded {
		t.Fatal("remove/re-add reused old execution token")
	}
	if _, loaded := port.ResolveExecution(newToken); !loaded {
		t.Fatal("new execution token did not resolve")
	}
}

func TestExecutionBridgeRollbackOnlyClearsMatchingEpoch(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	view, err := publisher.publish(port, portSource(1, portNode(NodeID{5}, "active")))
	if err != nil {
		t.Fatal(err)
	}
	token := ExecutionToken{RuntimeEpochID: view.RuntimeEpochID, CatalogRevision: view.CatalogRevision, Handle: view.Candidates[0].Handle}
	port.RollbackEpoch(view.RuntimeEpochID + 1)
	if _, loaded := port.ResolveExecution(token); !loaded {
		t.Fatal("unrelated rollback cleared active binding")
	}
	port.RollbackEpoch(view.RuntimeEpochID)
	if port.Snapshot() != nil {
		t.Fatal("matching rollback retained aborted catalog")
	}
	if _, loaded := port.ResolveExecution(token); loaded {
		t.Fatal("matching rollback retained aborted binding")
	}
}

func TestExecutionBridgeRetainsAcquiredBindingUntilLastLeaseRelease(t *testing.T) {
	port, publisher := NewCatalogPort(), newCatalogTestPublisher()
	v1, err := publisher.publish(port, portSource(1, portNode(NodeID{9}, "v1")))
	if err != nil {
		t.Fatal(err)
	}
	token := ExecutionToken{RuntimeEpochID: v1.RuntimeEpochID, CatalogRevision: v1.CatalogRevision, Handle: v1.Candidates[0].Handle}
	held, loaded := port.AcquireExecution(token)
	if !loaded || held.Port == nil {
		t.Fatal("failed to acquire active execution lease")
	}
	port.access.RLock()
	oldBindings := port.current.bindings
	port.access.RUnlock()
	if _, err = publisher.publish(port, portSource(2, portNode(NodeID{10}, "v2"))); err != nil {
		t.Fatal(err)
	}
	if _, loaded = port.AcquireExecution(token); loaded {
		t.Fatal("retiring binding accepted a new execution lease")
	}
	oldBindings.access.Lock()
	retainedBeforeRelease := oldBindings.retiring && oldBindings.refs == 1 && len(oldBindings.ports) == 1
	oldBindings.access.Unlock()
	if !retainedBeforeRelease {
		t.Fatal("commit dropped a binding still protected by an execution lease")
	}
	held.Release()
	held.Release()
	oldBindings.access.Lock()
	drained := oldBindings.refs == 0 && oldBindings.ports == nil
	oldBindings.access.Unlock()
	if !drained {
		t.Fatal("last execution lease release did not clear retiring binding set")
	}
}
