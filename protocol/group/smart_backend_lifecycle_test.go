package group

import (
	"sync/atomic"
	"testing"
	"time"
)

type blockingSmartPolicyBackend struct {
	observeStarted chan struct{}
	releaseObserve chan struct{}
	closed         atomic.Bool
}

func (b *blockingSmartPolicyBackend) Choose(string, []smartPolicyCandidate, smartTrafficProfile, time.Time) smartPolicyDecision {
	return smartPolicyDecision{}
}

func (b *blockingSmartPolicyBackend) Observe(string, uint64, bool, time.Duration, time.Time) {
	close(b.observeStarted)
	<-b.releaseObserve
	if b.closed.Load() {
		panic("policy backend closed while Observe was in flight")
	}
}

func (b *blockingSmartPolicyBackend) Reset() {}

func (b *blockingSmartPolicyBackend) Close() {
	b.closed.Store(true)
}

func TestSmartPolicyBackendCloseWaitsForInFlightObserve(t *testing.T) {
	backend := &blockingSmartPolicyBackend{
		observeStarted: make(chan struct{}),
		releaseObserve: make(chan struct{}),
	}
	smart := &Smart{policyBackend: backend}

	observeDone := make(chan struct{})
	go func() {
		smart.observePolicyBackend("key", 1, true, time.Millisecond, time.Now())
		close(observeDone)
	}()
	<-backend.observeStarted

	closeDone := make(chan struct{})
	go func() {
		smart.closePolicyBackend()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("backend closed while Observe was in flight")
	case <-time.After(20 * time.Millisecond):
	}

	close(backend.releaseObserve)
	<-observeDone
	<-closeDone
	if !backend.closed.Load() {
		t.Fatal("backend was not closed after Observe completed")
	}
}
