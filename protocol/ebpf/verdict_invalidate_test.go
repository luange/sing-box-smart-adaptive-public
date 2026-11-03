//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// stubInvalidator implements the invalidate surface used by doInvalidate tests.
type stubInvalidator struct {
	failAll    bool
	failEnable bool
	invokes    atomic.Int32
	enables    atomic.Int32
	gen        uint32
}

func (s *stubInvalidator) InvalidateAll() error {
	s.invokes.Add(1)
	if s.failAll {
		return errors.New("map write failed")
	}
	s.gen++
	if s.gen == 0 {
		s.gen = 1
	}
	return nil
}

func (s *stubInvalidator) SetEnabled(bool) error {
	s.enables.Add(1)
	if s.failEnable {
		return errors.New("enable write failed")
	}
	return nil
}

func (s *stubInvalidator) Generation() uint32 { return s.gen }

// testCoord wires a coordinator that uses stub via doInvalidate override pattern:
// we test InvalidateVerdictIfNeeded / NoteBypassFingerprint fingerprint state machine
// by driving the same lock/seed logic with a thin wrapper.
func newTestCoord() *outboundCoordinator {
	return &outboundCoordinator{
		logger: nopLogger{},
	}
}

type nopLogger struct{}

func (nopLogger) Info(...any)  {}
func (nopLogger) Warn(...any)  {}
func (nopLogger) Debug(...any) {}

func TestInvalidateVerdictIfNeeded_SeedOnly(t *testing.T) {
	c := newTestCoord()
	// Without a real verdict backend, fingerprint seed still happens.
	if c.InvalidateVerdictIfNeeded("fp1", "test") {
		t.Fatal("first call must not invalidate")
	}
	c.access.RLock()
	seeded := c.fingerprintSeeded
	fp := c.lastBypassFingerprint
	c.access.RUnlock()
	if !seeded || fp != "fp1" {
		t.Fatalf("seeded=%v fp=%q", seeded, fp)
	}
	// Same fingerprint: still no invalidate.
	if c.InvalidateVerdictIfNeeded("fp1", "test") {
		t.Fatal("same fingerprint must not invalidate")
	}
}

func TestNoteBypassFingerprint_ThenIfNeededStable(t *testing.T) {
	c := newTestCoord()
	c.NoteBypassFingerprint("base")
	if c.InvalidateVerdictIfNeeded("base", "test") {
		t.Fatal("noted fingerprint must not re-invalidate")
	}
	// Change without backend → doInvalidate false, fingerprint NOT committed (N1).
	if c.InvalidateVerdictIfNeeded("changed", "test") {
		t.Fatal("no backend → false")
	}
	c.access.RLock()
	fp := c.lastBypassFingerprint
	c.access.RUnlock()
	if fp != "base" {
		t.Fatalf("failed invalidate must not commit fingerprint, got %q", fp)
	}
	// Retry same new fingerprint still attempts (still base stored).
	if c.InvalidateVerdictIfNeeded("changed", "test") {
		t.Fatal("still no backend")
	}
	c.access.RLock()
	fp = c.lastBypassFingerprint
	c.access.RUnlock()
	if fp != "base" {
		t.Fatalf("still base, got %q", fp)
	}
}

func TestDoInvalidate_NoBackend(t *testing.T) {
	c := newTestCoord()
	if c.doInvalidate("x") {
		t.Fatal("nil verdict must return false")
	}
	if c.InvalidateVerdictNow("force") {
		t.Fatal("force with nil verdict must return false")
	}
}

func TestInvalidateVerdictIfNeeded_Closed(t *testing.T) {
	c := newTestCoord()
	c.closed = true
	if c.InvalidateVerdictIfNeeded("fp", "x") {
		t.Fatal("closed coord must no-op")
	}
	_ = time.Second // keep import if needed
}
