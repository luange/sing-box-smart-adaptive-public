package adaptive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func testBusinessService(transport string) ServiceContext {
	return ServiceContext{ID: "service:test", Mode: ModeAdaptive, Transport: transport}
}

func serviceStatus(health *HealthStore, handle NodeHandle, _ string) HealthStatus {
	return health.StatusHandle(handle, DomainService, "", "service:test")
}

func TestTCPFirstByteSuccessIsTransparentAndSettledOnce(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	dialer := newDialTestOutbound("tcp-payload", 0, nil)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{81}, "tcp-payload", dialer))
	ctx := udpFlowContext(3001)
	destination := M.ParseSocksaddr("example.com:443")
	service := pool.resolver.Resolve(adapter.ContextFrom(ctx), destination, N.NetworkTCP)
	conn, err := pool.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-dialer.peers
	defer peer.Close()
	handle := snapshot.Candidates[0].Handle
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Successes != 0 {
		t.Fatalf("dial success was treated as service success: %+v", status)
	}
	for _, payload := range [][]byte{[]byte("first"), []byte("second")} {
		writeDone := make(chan error, 1)
		go func(data []byte) { _, writeErr := peer.Write(data); writeDone <- writeErr }(payload)
		read := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, read); err != nil {
			t.Fatal(err)
		}
		if err = <-writeDone; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(read, payload) {
			t.Fatalf("payload changed: got=%q want=%q", read, payload)
		}
	}
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Successes != 1 || status.Failures != 0 {
		t.Fatalf("first byte did not settle exactly once: %+v", status)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
}

func TestTCPNoPayloadDoesNotCreateServiceFailure(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{82}, "no-payload", newTestOutbound("no-payload")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle

	local, peer := net.Pipe()
	wrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], service, time.Now())
	_ = peer.Close()
	buffer := make([]byte, 1)
	if count, err := wrapped.Read(buffer); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF changed: count=%d err=%v", count, err)
	}
	_ = wrapped.Close()
	if status := serviceStatus(health, handle, N.NetworkTCP); status.Successes != 0 || status.Failures != 0 {
		t.Fatalf("EOF/close created service evidence: %+v", status)
	}
}

func TestTCPEarlyTLSResetPenalizesServiceAndInvalidatesLease(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{83}, "tls-reset", newTestOutbound("tls-reset")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle
	pool.leases.ReplaceHandle(service.Session, NodeHandle{}, handle, service.ID, service.Mode, time.Hour, time.Now())

	for attempt := 1; attempt <= 3; attempt++ {
		wrapped := pool.wrapBusinessConn(&earlyTLSErrorConn{readErr: syscall.ECONNRESET}, snapshot, snapshot.Candidates[0], service, time.Now())
		clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}
		if _, err := wrapped.Write(clientHello); err != nil {
			t.Fatal(err)
		}
		if count, err := wrapped.Read(make([]byte, 1)); count != 0 || !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("early TLS reset changed: count=%d err=%v", count, err)
		}
		_ = wrapped.Close()
		_, loaded := pool.leases.Peek(service.Session, time.Now())
		if attempt < 3 && !loaded {
			t.Fatalf("transient TLS failure %d invalidated the lease", attempt)
		}
		if attempt == 3 && loaded {
			t.Fatal("breaker-open TLS lease was retained")
		}
	}
	if status := serviceStatus(health, handle, N.NetworkTCP); status.Failures != 3 || status.Successes != 0 || status.Reason != syscall.ECONNRESET.Error() || status.Breaker != BreakerOpen {
		t.Fatalf("early TLS failures did not open the breaker: %+v", status)
	}
}

type earlyTLSErrorConn struct {
	readErr  error
	writeErr error
}

func (c *earlyTLSErrorConn) Read([]byte) (int, error) { return 0, c.readErr }
func (c *earlyTLSErrorConn) Write(payload []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(payload), nil
}
func (*earlyTLSErrorConn) Close() error                     { return nil }
func (*earlyTLSErrorConn) LocalAddr() net.Addr              { return &net.TCPAddr{Port: 1} }
func (*earlyTLSErrorConn) RemoteAddr() net.Addr             { return &net.TCPAddr{Port: 2} }
func (*earlyTLSErrorConn) SetDeadline(time.Time) error      { return nil }
func (*earlyTLSErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (*earlyTLSErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPWriteOpaqueLocalErrorDoesNotPenalizeNode(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{0x98}, "write-local", newTestOutbound("write-local")))
	service := testBusinessService(N.NetworkTCP)
	localErr := errors.New("multipart body canceled")
	wrapped := pool.wrapBusinessConn(&earlyTLSErrorConn{writeErr: localErr}, snapshot, snapshot.Candidates[0], service, time.Now())
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}
	if _, err := wrapped.Write(payload); !errors.Is(err, localErr) {
		t.Fatalf("write error changed: %v", err)
	}
	_ = wrapped.Close()
	status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP)
	if status.Failures != 0 || status.NonBreakerFailures != 0 || status.Breaker == BreakerOpen {
		t.Fatalf("opaque local Write error must not penalize node: %+v", status)
	}
}

func TestTCPWriteFailureUsesConfidenceWithoutChangingPayloadSemantics(t *testing.T) {
	tests := []struct {
		name               string
		err                error
		attempts           int
		wantBreakerFailure uint64
		wantQualityFailure uint64
		wantBreaker        BreakerState
	}{
		{name: "broken-pipe", err: syscall.EPIPE, attempts: 3, wantBreakerFailure: 3, wantBreaker: BreakerOpen},
		// Timeout is low-confidence: records quality, does not open breaker.
		{name: "timeout", err: context.DeadlineExceeded, attempts: 1, wantQualityFailure: 1, wantBreaker: BreakerClosed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := NewHealthStore(time.Hour, 32)
			pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{97}, "write-"+test.name, newTestOutbound("write-"+test.name)))
			service := testBusinessService(N.NetworkTCP)
			for range test.attempts {
				wrapped := pool.wrapBusinessConn(&earlyTLSErrorConn{writeErr: test.err}, snapshot, snapshot.Candidates[0], service, time.Now())
				payload := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}
				if count, err := wrapped.Write(payload); count != 0 || !errors.Is(err, test.err) {
					t.Fatalf("write semantics changed: count=%d err=%v", count, err)
				}
				_ = wrapped.Close()
			}
			status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP)
			if status.Failures != test.wantBreakerFailure || status.NonBreakerFailures != test.wantQualityFailure || status.Breaker != test.wantBreaker {
				t.Fatalf("write failure confidence mismatch: %+v", status)
			}
		})
	}
}

func TestTCPEarlyTLSEOFIsAmbiguousAndDoesNotPenalize(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{87}, "tls-eof", newTestOutbound("tls-eof")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle
	pool.leases.ReplaceHandle(service.Session, NodeHandle{}, handle, service.ID, service.Mode, time.Hour, time.Now())
	wrapped := pool.wrapBusinessConn(&earlyTLSErrorConn{readErr: io.EOF}, snapshot, snapshot.Candidates[0], service, time.Now())
	_, _ = wrapped.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01})
	_, _ = wrapped.Read(make([]byte, 1))
	if status := serviceStatus(health, handle, N.NetworkTCP); status.Failures != 0 {
		t.Fatalf("ambiguous TLS EOF polluted service health: %+v", status)
	}
	if _, loaded := pool.leases.Peek(service.Session, time.Now()); !loaded {
		t.Fatal("ambiguous TLS EOF invalidated the service lease")
	}
	_ = wrapped.Close()
}

func TestDestinationTransportFailureInvalidatesStickyLeaseAtBreakerThreshold(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{85}, "dial-refused", newTestOutbound("dial-refused")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle
	pool.leases.ReplaceHandle(service.Session, NodeHandle{}, handle, service.ID, service.Mode, time.Hour, time.Now())
	// Hard connect failures (not timeouts) open breakers. Dial timeouts are
	// medium-confidence quality-only (see TestDialTimeoutIsMediumConfidenceQualityOnly).
	hardErr := syscall.ECONNREFUSED
	for failure := 1; failure <= 3; failure++ {
		permit, allowed := health.TryAcquireConnectionPermitHandle(handle, service.Transport, time.Now())
		if !allowed {
			t.Fatal("transport attempt was not admitted")
		}
		attempt, err := pool.beginObservationAttempt(snapshot, snapshot.Candidates[0], permit, service.Transport)
		if err != nil {
			t.Fatal(err)
		}
		pool.completeTransportAttempt(attempt, service, M.Socksaddr{}, DialAttemptResult{
			Err: hardErr, Delay: time.Second,
		})
		_, loaded := pool.leases.Peek(service.Session, time.Now())
		if failure < 3 && !loaded {
			t.Fatalf("transient transport failure %d invalidated lease", failure)
		}
		if failure == 3 && loaded {
			t.Fatal("breaker-open destination transport lease was retained")
		}
	}
	// Bare Transport=tcp is normalized to tcp/any when no family is known.
	status := health.StatusHandle(handle, DomainTransport, "tcp/any", "")
	if status.Failures != 3 || status.Breaker != BreakerOpen {
		t.Fatalf("transport failure was not reduced: %+v", status)
	}
}

func TestTCPOrdinaryEarlyEOFDoesNotPenalizeService(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{84}, "plain-eof", newTestOutbound("plain-eof")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle
	local, peer := net.Pipe()
	wrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], service, time.Now())
	go func() { _, _ = wrapped.Write([]byte("not tls")) }()
	_, _ = io.ReadFull(peer, make([]byte, len("not tls")))
	_ = peer.Close()
	_, _ = wrapped.Read(make([]byte, 1))
	if status := serviceStatus(health, handle, N.NetworkTCP); status.Failures != 0 {
		t.Fatalf("ordinary EOF polluted service health: %+v", status)
	}
	_ = wrapped.Close()
}

func TestTCPLocalCloseDoesNotBecomeTLSFailure(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{86}, "tls-local-close", newTestOutbound("tls-local-close")))
	service := testBusinessService(N.NetworkTCP)
	handle := snapshot.Candidates[0].Handle
	pool.leases.ReplaceHandle(service.Session, NodeHandle{}, handle, service.ID, service.Mode, time.Hour, time.Now())

	local, peer := net.Pipe()
	wrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], service, time.Now())
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}
	writeDone := make(chan error, 1)
	go func() { _, writeErr := wrapped.Write(clientHello); writeDone <- writeErr }()
	read := make([]byte, len(clientHello))
	if _, err := io.ReadFull(peer, read); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, readErr := wrapped.Read(make([]byte, 1)); readDone <- readErr }()
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err == nil {
		t.Fatal("read unexpectedly succeeded after local close")
	}
	_ = peer.Close()
	if status := serviceStatus(health, handle, N.NetworkTCP); status.Failures != 0 {
		t.Fatalf("local close was misclassified as TLS failure: %+v", status)
	}
	if _, loaded := pool.leases.Peek(service.Session, time.Now()); !loaded {
		t.Fatal("local close invalidated the service lease")
	}
}

type zeroReadConn struct{ net.Conn }

func (*zeroReadConn) Read([]byte) (int, error) { return 0, nil }

func TestTCPZeroReadAndObservationPanicDoNotAffectBusiness(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{91}, "zero", newTestOutbound("zero")))
	local, peer := net.Pipe()
	zeroWrapped := pool.wrapBusinessConn(&zeroReadConn{Conn: local}, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	if count, err := zeroWrapped.Read(make([]byte, 1)); count != 0 || err != nil {
		t.Fatalf("zero read changed: count=%d err=%v", count, err)
	}
	if status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP); status.Successes != 0 || status.Failures != 0 {
		t.Fatalf("zero read created evidence: %+v", status)
	}
	_ = zeroWrapped.Close()
	_ = peer.Close()

	handle := snapshot.Candidates[0].Handle
	for range 3 {
		health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainService, Service: "service:test", Outcome: OutcomeFailure, At: time.Now().Add(-10 * time.Second)})
	}
	local, peer = net.Pipe()
	pool.observationReducerHook = func(ObservationEvidence, []DomainEvidence) error { panic("injected observer panic") }
	panicWrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	go func() { _, _ = peer.Write([]byte("ok")) }()
	payload := make([]byte, 2)
	if _, err := io.ReadFull(panicWrapped, payload); err != nil || string(payload) != "ok" {
		t.Fatalf("observer panic affected payload: %q %v", payload, err)
	}
	if pool.missedObservations.Load() != 1 {
		t.Fatalf("observer panic was not counted: %d", pool.missedObservations.Load())
	}
	if status := pool.AdaptiveStatus(); status.ObservationReducerFailureTotal != 1 || status.ObservationPanicTotal != 0 {
		t.Fatalf("recovered reducer panic reason was not exposed: %+v", status)
	}
	permit, allowed := health.TryAcquireDomainPermitHandle(handle, DomainService, "", "service:test", time.Now())
	if !allowed {
		t.Fatal("observer panic leaked service half-open token")
	}
	permit.ReleaseDeferred()
	_ = panicWrapped.Close()
	_ = peer.Close()
}

type payloadEOFConn struct {
	payload []byte
	read    atomic.Bool
}

func (c *payloadEOFConn) Read(payload []byte) (int, error) {
	if !c.read.CompareAndSwap(false, true) {
		return 0, io.EOF
	}
	return copy(payload, c.payload), io.EOF
}
func (*payloadEOFConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (*payloadEOFConn) Close() error                      { return nil }
func (*payloadEOFConn) LocalAddr() net.Addr               { return &net.TCPAddr{Port: 1} }
func (*payloadEOFConn) RemoteAddr() net.Addr              { return &net.TCPAddr{Port: 2} }
func (*payloadEOFConn) SetDeadline(time.Time) error       { return nil }
func (*payloadEOFConn) SetReadDeadline(time.Time) error   { return nil }
func (*payloadEOFConn) SetWriteDeadline(time.Time) error  { return nil }

func TestTCPPayloadWithEOFSucceedsThenReleasesEpochWithoutClose(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{90}, "payload-eof", newTestOutbound("payload-eof")))
	wrapped := pool.wrapBusinessConn(&payloadEOFConn{payload: []byte("final")}, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	pool.runtimeManager.RetireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	payload := make([]byte, 5)
	count, err := wrapped.Read(payload)
	if count != 5 || !errors.Is(err, io.EOF) || string(payload) != "final" {
		t.Fatalf("payload+EOF changed: count=%d payload=%q err=%v", count, payload, err)
	}
	if status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP); status.Successes != 1 {
		t.Fatalf("payload preceding EOF was not observed: %+v", status)
	}
	pool.runtimeManager.access.RLock()
	state := pool.runtimeManager.groups[pool.groupID]
	retained := false
	if state != nil {
		_, retained = state.epochs[snapshot.RuntimeEpochID]
	}
	pool.runtimeManager.access.RUnlock()
	if retained {
		t.Fatal("terminal EOF without Close retained runtime epoch")
	}
}

func TestTCPBulkPayloadPublishesOneThroughputSample(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{91}, "bulk", newTestOutbound("bulk")))
	service := testBusinessService(N.NetworkTCP)
	payload := bytes.Repeat([]byte{1}, 64*1024)
	wrapped := pool.wrapBusinessConn(&payloadEOFConn{payload: payload}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second))
	buffer := make([]byte, len(payload))
	if count, err := wrapped.Read(buffer); count != len(payload) || !errors.Is(err, io.EOF) {
		t.Fatalf("bulk payload changed: count=%d err=%v", count, err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID)
	if status.ThroughputSamples != 1 || status.ThroughputBPS <= 0 || status.Successes != 1 {
		t.Fatalf("bulk throughput did not pass observation pipeline: %+v", status)
	}
	_ = wrapped.Close()
	if status = health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); status.ThroughputSamples != 1 {
		t.Fatalf("EOF plus Close duplicated throughput evidence: %+v", status)
	}
}

func TestTCPShortPayloadDoesNotPolluteThroughput(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{92}, "short", newTestOutbound("short")))
	service := testBusinessService(N.NetworkTCP)
	wrapped := pool.wrapBusinessConn(&payloadEOFConn{payload: bytes.Repeat([]byte{1}, 63*1024)}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second))
	_, _ = wrapped.Read(make([]byte, 64*1024))
	if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); status.ThroughputSamples != 0 {
		t.Fatalf("short response polluted throughput EWMA: %+v", status)
	}
}

func TestTCPThroughputReducerFailureDoesNotPolluteHealth(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{93}, "reducer", newTestOutbound("reducer")))
	pool.observationReducerHook = func(evidence ObservationEvidence, _ []DomainEvidence) error {
		if evidence.Source == SourceThroughput {
			return errors.New("injected throughput reducer failure")
		}
		return nil
	}
	service := testBusinessService(N.NetworkTCP)
	payload := bytes.Repeat([]byte{1}, 64*1024)
	wrapped := pool.wrapBusinessConn(&payloadEOFConn{payload: payload}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second))
	_, _ = wrapped.Read(make([]byte, len(payload)))
	if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); status.ThroughputSamples != 0 || status.Successes != 1 {
		t.Fatalf("failed throughput transaction polluted health: %+v", status)
	}
	if pool.missedObservations.Load() != 1 {
		t.Fatalf("throughput reducer failure was not observable: %d", pool.missedObservations.Load())
	}
	if status := pool.AdaptiveStatus(); status.ObservationReducerFailureTotal != 1 {
		t.Fatalf("throughput reducer failure reason was not exposed: %+v", status)
	}
}

type extendedMemoryConn struct {
	readPayload []byte
	readErr     error
	writeErr    error
	readIndex   int
	local       net.Addr
	remote      net.Addr
	deadline    time.Time
	readDL      time.Time
	writeDL     time.Time
	closeCalls  atomic.Int32
	lastWrite   *buf.Buffer
}

func (c *extendedMemoryConn) Read(payload []byte) (int, error) {
	if c.readIndex >= len(c.readPayload) {
		return 0, io.EOF
	}
	count := copy(payload, c.readPayload[c.readIndex:])
	c.readIndex += count
	return count, nil
}
func (*extendedMemoryConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *extendedMemoryConn) Close() error                    { c.closeCalls.Add(1); return nil }
func (c *extendedMemoryConn) LocalAddr() net.Addr             { return c.local }
func (c *extendedMemoryConn) RemoteAddr() net.Addr            { return c.remote }
func (c *extendedMemoryConn) SetDeadline(at time.Time) error  { c.deadline = at; return nil }
func (c *extendedMemoryConn) SetReadDeadline(at time.Time) error {
	c.readDL = at
	return nil
}
func (c *extendedMemoryConn) SetWriteDeadline(at time.Time) error {
	c.writeDL = at
	return nil
}
func (c *extendedMemoryConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.readIndex >= len(c.readPayload) {
		if c.readErr != nil {
			return c.readErr
		}
		return io.EOF
	}
	_, _ = buffer.Write(c.readPayload[c.readIndex:])
	c.readIndex = len(c.readPayload)
	return nil
}

func TestExtendedConnAmbiguousTLSErrorsDoNotOpenBreaker(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantQualityFail uint64
	}{
		{name: "eof", err: io.EOF},
		{name: "canceled", err: context.Canceled},
		{name: "timeout", err: context.DeadlineExceeded, wantQualityFail: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := NewHealthStore(time.Hour, 32)
			pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{96}, "extended-"+test.name, newTestOutbound("extended-"+test.name)))
			service := testBusinessService(N.NetworkTCP)
			underlying := &extendedMemoryConn{readErr: test.err, local: &net.TCPAddr{Port: 1001}, remote: &net.TCPAddr{Port: 443}}
			wrapped := pool.wrapBusinessConn(underlying, snapshot, snapshot.Candidates[0], service, time.Now())
			extended := wrapped.(N.ExtendedConn)
			clientHello := buf.As([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01})
			if err := extended.WriteBuffer(clientHello); err != nil {
				t.Fatal(err)
			}
			buffer := buf.New()
			err := extended.ReadBuffer(buffer)
			buffer.Release()
			if !errors.Is(err, test.err) {
				t.Fatalf("extended error changed: %v", err)
			}
			status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP)
			if status.Failures != 0 || status.NonBreakerFailures != test.wantQualityFail || status.Breaker != BreakerClosed {
				t.Fatalf("ambiguous extended error polluted breaker: %+v", status)
			}
			_ = wrapped.Close()
		})
	}
}
func (c *extendedMemoryConn) WriteBuffer(buffer *buf.Buffer) error {
	c.lastWrite = buffer
	return c.writeErr
}
func (c *extendedMemoryConn) ReadFrom(reader io.Reader) (int64, error) {
	return io.Copy(io.Discard, reader)
}
func (c *extendedMemoryConn) WriteTo(writer io.Writer) (int64, error) {
	count, err := writer.Write(c.readPayload[c.readIndex:])
	c.readIndex += count
	return int64(count), err
}

func TestExtendedConnPreservesCapabilitiesAndReadBufferPayload(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{83}, "extended", newTestOutbound("extended")))
	underlying := &extendedMemoryConn{readPayload: []byte("extended-payload"), local: &net.TCPAddr{Port: 1001}, remote: &net.TCPAddr{Port: 443}}
	wrapped := pool.wrapBusinessConn(underlying, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	extended, loaded := wrapped.(N.ExtendedConn)
	if !loaded {
		t.Fatal("N.ExtendedConn capability was lost")
	}
	if _, loaded = wrapped.(io.ReaderFrom); !loaded {
		t.Fatal("io.ReaderFrom capability was lost")
	}
	if _, loaded = wrapped.(io.WriterTo); !loaded {
		t.Fatal("io.WriterTo capability was lost")
	}
	upstream, loaded := wrapped.(common.WithUpstream)
	if !loaded || upstream.Upstream() != underlying {
		t.Fatal("upstream capability was not preserved")
	}
	if wrapped.LocalAddr() != underlying.local || wrapped.RemoteAddr() != underlying.remote {
		t.Fatal("connection addresses changed")
	}
	deadline := time.Unix(9000, 0)
	if err := wrapped.SetDeadline(deadline); err != nil || underlying.deadline != deadline {
		t.Fatal("deadline was not forwarded")
	}
	if err := wrapped.SetReadDeadline(deadline.Add(time.Second)); err != nil || underlying.readDL != deadline.Add(time.Second) {
		t.Fatal("read deadline was not forwarded")
	}
	if err := wrapped.SetWriteDeadline(deadline.Add(2 * time.Second)); err != nil || underlying.writeDL != deadline.Add(2*time.Second) {
		t.Fatal("write deadline was not forwarded")
	}
	buffer := buf.New()
	defer buffer.Release()
	if err := extended.ReadBuffer(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer.Bytes()) != "extended-payload" {
		t.Fatalf("ReadBuffer payload changed: %q", buffer.Bytes())
	}
	if status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP); status.Successes != 1 {
		t.Fatalf("ReadBuffer did not publish service success: %+v", status)
	}
	writeBuffer := buf.As([]byte("write"))
	if err := extended.WriteBuffer(writeBuffer); err != nil || underlying.lastWrite != writeBuffer {
		t.Fatal("WriteBuffer semantics changed")
	}
	readFrom := wrapped.(io.ReaderFrom)
	if count, err := readFrom.ReadFrom(bytes.NewBufferString("upload")); err != nil || count != 6 {
		t.Fatalf("ReaderFrom semantics changed: count=%d err=%v", count, err)
	}
	underlying.readPayload, underlying.readIndex = []byte("writer-to"), 0
	var copied bytes.Buffer
	if count, err := wrapped.(io.WriterTo).WriteTo(&copied); err != nil || count != 9 || copied.String() != "writer-to" {
		t.Fatalf("WriterTo semantics changed: count=%d payload=%q err=%v", count, copied.String(), err)
	}
	_ = wrapped.Close()
	_ = wrapped.Close()
	if underlying.closeCalls.Load() != 1 {
		t.Fatalf("underlying close called %d times", underlying.closeCalls.Load())
	}
}

type packetMemoryConn struct {
	payload     []byte
	source      net.Addr
	destination M.Socksaddr
	readOnce    atomic.Bool
	closeCalls  atomic.Int32
	lastBuffer  *buf.Buffer
	deadline    time.Time
	readDL      time.Time
	writeDL     time.Time
}

func (c *packetMemoryConn) takePayload() ([]byte, bool) {
	if !c.readOnce.CompareAndSwap(false, true) {
		return nil, false
	}
	return c.payload, len(c.payload) > 0
}
func (c *packetMemoryConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	data, loaded := c.takePayload()
	if !loaded {
		return 0, nil, context.DeadlineExceeded
	}
	return copy(payload, data), c.source, nil
}
func (*packetMemoryConn) WriteTo(payload []byte, _ net.Addr) (int, error) { return len(payload), nil }
func (c *packetMemoryConn) Close() error                                  { c.closeCalls.Add(1); return nil }
func (*packetMemoryConn) LocalAddr() net.Addr                             { return &net.UDPAddr{Port: 5353} }
func (c *packetMemoryConn) SetDeadline(at time.Time) error                { c.deadline = at; return nil }
func (c *packetMemoryConn) SetReadDeadline(at time.Time) error            { c.readDL = at; return nil }
func (c *packetMemoryConn) SetWriteDeadline(at time.Time) error           { c.writeDL = at; return nil }
func (c *packetMemoryConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	data, loaded := c.takePayload()
	if !loaded {
		return M.Socksaddr{}, context.DeadlineExceeded
	}
	c.lastBuffer = buffer
	_, _ = buffer.Write(data)
	return c.destination, nil
}
func (*packetMemoryConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return nil }

type packetResponseOutbound struct {
	outbound.Adapter
	conn net.PacketConn
}

type failingPacketConn struct{ err error }

func (c *failingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.err }
func (c *failingPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, c.err }
func (*failingPacketConn) Close() error                             { return nil }
func (*failingPacketConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (*failingPacketConn) SetDeadline(time.Time) error              { return nil }
func (*failingPacketConn) SetReadDeadline(time.Time) error          { return nil }
func (*failingPacketConn) SetWriteDeadline(time.Time) error         { return nil }

func newPacketResponseOutbound(tag string, conn net.PacketConn) *packetResponseOutbound {
	return &packetResponseOutbound{Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkUDP}, nil), conn: conn}
}

func (o *packetResponseOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return o.conn, nil
}

func (*packetResponseOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("tcp unsupported")
}

func TestUDPActualResponseReadFromAndReadPacketSettleOnce(t *testing.T) {
	for _, usePacketReader := range []bool{false, true} {
		t.Run(map[bool]string{false: "ReadFrom", true: "ReadPacket"}[usePacketReader], func(t *testing.T) {
			health := NewHealthStore(time.Hour, 32)
			underlying := &packetMemoryConn{payload: []byte("udp-response"), source: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53}, destination: M.ParseSocksaddr("192.0.2.10:53")}
			pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{84}, "udp", newPacketResponseOutbound("udp", underlying)))
			ctx := udpFlowContext(uint16(3100 + map[bool]int{false: 0, true: 1}[usePacketReader]))
			destination := M.ParseSocksaddr("example.com:443")
			service := pool.resolver.Resolve(adapter.ContextFrom(ctx), destination, N.NetworkUDP)
			wrapped, err := pool.ListenPacket(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); status.Successes != 0 {
				t.Fatalf("packet setup became service success: %+v", status)
			}
			if usePacketReader {
				reader, loaded := wrapped.(N.PacketReader)
				if !loaded {
					t.Fatal("N.PacketReader capability was lost")
				}
				if _, loaded = wrapped.(N.PacketWriter); !loaded {
					t.Fatal("N.PacketWriter capability was lost")
				}
				buffer := buf.NewPacket()
				defer buffer.Release()
				destination, err := reader.ReadPacket(buffer)
				if err != nil || destination != underlying.destination || string(buffer.Bytes()) != "udp-response" || underlying.lastBuffer != buffer {
					t.Fatalf("ReadPacket semantics changed: destination=%v payload=%q err=%v", destination, buffer.Bytes(), err)
				}
			} else {
				payload := make([]byte, 64)
				count, source, err := wrapped.ReadFrom(payload)
				if err != nil || source != underlying.source || string(payload[:count]) != "udp-response" {
					t.Fatalf("ReadFrom semantics changed: source=%v payload=%q err=%v", source, payload[:count], err)
				}
			}
			if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); status.Successes != 1 || status.Failures != 0 {
				t.Fatalf("UDP response did not settle once: %+v", status)
			}
			_ = wrapped.Close()
			_ = wrapped.Close()
			if underlying.closeCalls.Load() != 1 {
				t.Fatalf("packet close called %d times", underlying.closeCalls.Load())
			}
		})
	}
}

func TestUDPTimeoutCreatesOnlyLowConfidencePathEvidence(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{85}, "udp-timeout", newTestOutbound("udp-timeout")))
	underlying := &packetMemoryConn{}
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/any"
	wrapped := pool.wrapBusinessPacketConn(underlying, snapshot, snapshot.Candidates[0], service, time.Now())
	pool.runtimeManager.RetireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	payload := make([]byte, 1)
	if count, _, err := wrapped.ReadFrom(payload); count != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("UDP timeout changed: count=%d err=%v", count, err)
	}
	if status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkUDP); status.Successes != 0 || status.Failures != 0 {
		t.Fatalf("UDP timeout created service evidence: %+v", status)
	}
	// Low-confidence timeout is metrics-only: counters/weight, no Health flip.
	if status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/any", ""); status.Failures != 0 || status.NonBreakerFailures != 1 || status.Breaker != BreakerClosed || status.Health == HealthUnreachable {
		t.Fatalf("UDP timeout was not retained as low-confidence path evidence: %+v", status)
	}
	pool.runtimeManager.access.RLock()
	state := pool.runtimeManager.groups[pool.groupID]
	_, retained := state.epochs[snapshot.RuntimeEpochID]
	pool.runtimeManager.access.RUnlock()
	if !retained {
		t.Fatal("UDP timeout released connection epoch before Close")
	}
	_ = wrapped.Close()
	pool.runtimeManager.access.RLock()
	state = pool.runtimeManager.groups[pool.groupID]
	retained = false
	if state != nil {
		_, retained = state.epochs[snapshot.RuntimeEpochID]
	}
	pool.runtimeManager.access.RUnlock()
	if retained {
		t.Fatal("UDP Close did not release retired epoch")
	}
}

func TestUDPExplicitNetworkFailureUpdatesOnlyDataPath(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{94}, "udp-refused", newTestOutbound("udp-refused")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	wrapped := pool.wrapBusinessPacketConn(&failingPacketConn{err: syscall.ECONNREFUSED}, snapshot, snapshot.Candidates[0], service, time.Now())
	if _, _, err := wrapped.ReadFrom(make([]byte, 1)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("explicit UDP error changed: %v", err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if status.Failures != 1 || status.Health != HealthDegraded {
		t.Fatalf("explicit UDP error did not update data path: %+v", status)
	}
	if dns := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_dns/ipv4", ""); dns.Failures != 0 || dns.NonBreakerFailures != 0 {
		t.Fatalf("UDP data error contaminated DNS path: %+v", dns)
	}
	_ = wrapped.Close()
}

func TestServiceHalfOpenPermitIsAcquiredOnlyAfterPayload(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	dialer := newDialTestOutbound("half-open", 0, nil)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{86}, "half-open", dialer))
	handle := snapshot.Candidates[0].Handle
	ctx := udpFlowContext(3200)
	destination := M.ParseSocksaddr("example.com:443")
	service := pool.resolver.Resolve(adapter.ContextFrom(ctx), destination, N.NetworkTCP)
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeFailure, At: time.Now().Add(-time.Second)})
	wrapped, err := pool.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-dialer.peers
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Breaker == BreakerHalfOpen {
		t.Fatalf("service token was held before payload: %+v", status)
	}
	go func() { _, _ = peer.Write([]byte("ok")) }()
	payload := make([]byte, 2)
	if _, err = io.ReadFull(wrapped, payload); err != nil {
		t.Fatal(err)
	}
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Breaker != BreakerHalfOpen || status.Successes != 1 || status.RecoverySuccesses != 1 {
		t.Fatalf("payload did not enter service recovery confirmation: %+v", status)
	}
	_ = wrapped.Close()
	_ = peer.Close()
}

func TestBusinessObservationUsesConnectionEpochAndRejectsReaddedHandle(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{87}, "v1", newTestOutbound("v1")))
	v1 := snapshot.Candidates[0].Handle
	health.Observe(Observation{NodeID: v1.NodeID, NodeSlot: v1.Slot, NodeVersion: v1.Version, Scope: DomainService, Service: "service:test", Outcome: OutcomeFailure, At: time.Now().Add(-time.Second)})
	local, peer := net.Pipe()
	wrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	for generation, nodes := range [][]IdentityNode{{}, {{NodeID: v1.NodeID, IdentityStable: true}}} {
		prepared, err := pool.runtimeManager.PrepareRevision(pool.groupID, snapshot.RuntimeEpochID, identitySnapshot(uint64(generation+2), nodes...))
		if err != nil {
			t.Fatal(err)
		}
		_, identity, err := prepared.Commit()
		if err != nil {
			t.Fatal(err)
		}
		pool.runtimeIdentity = identity
	}
	go func() { _, _ = peer.Write([]byte("stale")) }()
	payload := make([]byte, 5)
	if _, err := io.ReadFull(wrapped, payload); err != nil || string(payload) != "stale" {
		t.Fatalf("stale observation affected payload: %q %v", payload, err)
	}
	if status := serviceStatus(health, v1, N.NetworkTCP); status.Breaker == BreakerClosed || status.Successes != 0 {
		t.Fatalf("stale v1 evidence recovered breaker: %+v", status)
	}
	_ = wrapped.Close()
	_ = peer.Close()
}

func TestRetiringConnectionLeaseAcceptsPayloadAndCloseReclaimsEpoch(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{88}, "retiring", newTestOutbound("retiring")))
	local, peer := net.Pipe()
	wrapped := pool.wrapBusinessConn(local, snapshot, snapshot.Candidates[0], testBusinessService(N.NetworkTCP), time.Now())
	pool.runtimeManager.RetireEpoch(pool.groupID, snapshot.RuntimeEpochID)
	go func() { _, _ = peer.Write([]byte("retained")) }()
	payload := make([]byte, 8)
	if _, err := io.ReadFull(wrapped, payload); err != nil {
		t.Fatal(err)
	}
	if status := serviceStatus(health, snapshot.Candidates[0].Handle, N.NetworkTCP); status.Successes != 1 {
		t.Fatalf("retiring retained payload was rejected: %+v", status)
	}
	pool.runtimeManager.access.RLock()
	state := pool.runtimeManager.groups[pool.groupID]
	_, retained := state.epochs[snapshot.RuntimeEpochID]
	pool.runtimeManager.access.RUnlock()
	if !retained {
		t.Fatal("connection epoch was reclaimed before Close")
	}
	_ = wrapped.Close()
	_ = peer.Close()
	pool.runtimeManager.access.RLock()
	state = pool.runtimeManager.groups[pool.groupID]
	retained = false
	if state != nil {
		_, retained = state.epochs[snapshot.RuntimeEpochID]
	}
	pool.runtimeManager.access.RUnlock()
	if retained {
		t.Fatal("connection Close did not release retired epoch")
	}
}

func TestObservationInitializationFailureReturnsTransparentConnection(t *testing.T) {
	pool := &AdaptivePool{catalog: NewCatalogPort(), leases: NewSessionLeaseManager(1)}
	local, peer := net.Pipe()
	snapshot := &ExecutionSnapshot{RuntimeEpochID: 99, CatalogRevision: 99, Generation: 1}
	candidate := Candidate{ID: NodeID{89}, Handle: NodeHandle{NodeID: NodeID{89}, Slot: 1, Version: 1}}
	wrapped := pool.wrapBusinessConn(local, snapshot, candidate, testBusinessService(N.NetworkTCP), time.Now())
	if wrapped != local || pool.missedObservations.Load() != 1 {
		t.Fatalf("failed observation changed connection: wrapped=%T missed=%d", wrapped, pool.missedObservations.Load())
	}
	if status := pool.AdaptiveStatus(); status.MissedObservations != 1 {
		t.Fatalf("missed observation counter not exposed: %+v", status)
	}
	if status := pool.AdaptiveStatus(); status.ObservationIdentityFailureTotal != 1 {
		t.Fatalf("identity failure reason not exposed: %+v", status)
	}
	go func() { _, _ = peer.Write([]byte("ok")) }()
	payload := make([]byte, 2)
	if _, err := io.ReadFull(wrapped, payload); err != nil || string(payload) != "ok" {
		t.Fatalf("transparent connection failed: %q %v", payload, err)
	}
	_ = wrapped.Close()
	_ = peer.Close()
}

func TestObservationReasonCountersSeparateDeferredAndMissedEvidence(t *testing.T) {
	pool := new(AdaptivePool)
	pool.recordObservationResult(IngestAccepted, nil)
	pool.recordObservationResult(IngestDuplicate, nil)
	pool.recordObservationResult(IngestStale, nil)
	pool.recordObservationResult(IngestBackpressure, nil)
	pool.recordObservationResult("", errors.New("injected reducer failure"))
	pool.recordObservationIdentityFailure()
	pool.recordObservationPanic()
	pool.observationPermitBusy.Add(1)
	if pool.missedObservations.Load() != 4 || pool.observationDuplicate.Load() != 1 || pool.observationStale.Load() != 1 || pool.observationBackpressure.Load() != 1 || pool.observationReducerFailure.Load() != 1 || pool.observationIdentityFailure.Load() != 1 || pool.observationPanic.Load() != 1 || pool.observationPermitBusy.Load() != 1 {
		t.Fatalf("observation reasons were not classified: missed=%d duplicate=%d stale=%d backpressure=%d reducer=%d identity=%d panic=%d permit=%d", pool.missedObservations.Load(), pool.observationDuplicate.Load(), pool.observationStale.Load(), pool.observationBackpressure.Load(), pool.observationReducerFailure.Load(), pool.observationIdentityFailure.Load(), pool.observationPanic.Load(), pool.observationPermitBusy.Load())
	}
}

var (
	_ N.ExtendedConn = (*extendedMemoryConn)(nil)
	_ io.ReaderFrom  = (*extendedMemoryConn)(nil)
	_ io.WriterTo    = (*extendedMemoryConn)(nil)
	_ net.PacketConn = (*packetMemoryConn)(nil)
	_ N.PacketReader = (*packetMemoryConn)(nil)
	_ N.PacketWriter = (*packetMemoryConn)(nil)
)

func TestReadFromLocalReaderErrorsDoNotPenalizeNode(t *testing.T) {
	if !isNodeNetworkIOError(syscall.ECONNRESET) {
		t.Fatal("ECONNRESET must count as network I/O")
	}
	if isNodeNetworkIOError(io.ErrUnexpectedEOF) {
		t.Fatal("unexpected EOF from upstream reader must not count as network I/O")
	}
	if isNodeNetworkIOError(errors.New("file read failed")) {
		t.Fatal("opaque local reader errors must not count as network I/O")
	}
	// Arbitrary OpError must not count; only dial/read/write + network syscall.
	if isNodeNetworkIOError(&net.OpError{Op: "file", Err: errors.New("local open failed")}) {
		t.Fatal("non-network OpError must not count as node network I/O")
	}
	if isNodeNetworkIOError(&net.OpError{Op: "write", Err: errors.New("multipart body canceled")}) {
		t.Fatal("write OpError wrapping local reader failure must not count")
	}
	if !isNodeNetworkIOError(&net.OpError{Op: "write", Err: syscall.ECONNRESET}) {
		t.Fatal("write OpError with ECONNRESET must count as network I/O")
	}
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{0x55}, "readfrom", newTestOutbound("readfrom")))
	handle := snapshot.Candidates[0].Handle
	service := testBusinessService(N.NetworkTCP)
	// Conn Write path uses ECONNRESET via ReaderFrom simulation.
	conn := &readFromErrorConn{err: errors.New("multipart body canceled")}
	wrapped := pool.wrapBusinessConn(conn, snapshot, snapshot.Candidates[0], service, time.Now())
	// Mark TLS started so observeWriteFailure would fire if called unconditionally.
	if oc, ok := wrapped.(*observedConn); ok {
		oc.tlsStarted.Store(true)
		_, _ = oc.ReadFrom(strings.NewReader("hello"))
	} else {
		t.Fatalf("expected observedConn, got %T", wrapped)
	}
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Failures != 0 {
		t.Fatalf("local ReadFrom error penalized service health: %+v", status)
	}
	// Network class error through ReadFrom still counts.
	conn2 := &readFromErrorConn{err: syscall.ECONNRESET}
	wrapped2 := pool.wrapBusinessConn(conn2, snapshot, snapshot.Candidates[0], service, time.Now())
	if oc, ok := wrapped2.(*observedConn); ok {
		oc.tlsStarted.Store(true)
		_, _ = oc.ReadFrom(strings.NewReader("hello"))
	}
	if status := health.StatusHandle(handle, DomainService, "", service.ID); status.Failures == 0 {
		t.Fatalf("network ReadFrom error did not attribute to node: %+v", status)
	}
}

type readFromErrorConn struct {
	net.Conn
	err error
}

func (c *readFromErrorConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *readFromErrorConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *readFromErrorConn) Close() error                     { return nil }
func (c *readFromErrorConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *readFromErrorConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *readFromErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *readFromErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readFromErrorConn) SetWriteDeadline(time.Time) error { return nil }
func (c *readFromErrorConn) ReadFrom(r io.Reader) (int64, error) {
	if r != nil {
		_, _ = io.Copy(io.Discard, r)
	}
	return 0, c.err
}

func TestUDPDataSuccessUpdatesTransportPath(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{96}, "udp-data-ok", newTestOutbound("udp-data-ok")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	underlying := &packetMemoryConn{payload: []byte("payload-ok"), source: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}}
	wrapped := pool.wrapBusinessPacketConn(underlying, snapshot, snapshot.Candidates[0], service, time.Now())
	if _, _, err := wrapped.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	path := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if path.Successes != 1 || path.Failures != 0 || path.Health != HealthHealthy {
		t.Fatalf("UDP data success missing transport path evidence: %+v", path)
	}
	if dns := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_dns/ipv4", ""); dns.Successes != 0 {
		t.Fatalf("UDP data success contaminated DNS path: %+v", dns)
	}
	if svc := health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", service.ID); svc.Successes != 1 {
		t.Fatalf("UDP data success missing service evidence: %+v", svc)
	}
	_ = wrapped.Close()
}

func TestUDPDNSSuccessRequiresResponseShape(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{97}, "udp-dns-ok", newTestOutbound("udp-dns-ok")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_dns/ipv4"
	// Valid DNS response header: ID=0x1234, QR=1, rcode=0, qd=0 an=0
	dnsOK := []byte{0x12, 0x34, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	wrapped := pool.wrapBusinessPacketConn(&packetMemoryConn{payload: dnsOK, source: &net.UDPAddr{IP: net.ParseIP("198.51.100.53"), Port: 53}}, snapshot, snapshot.Candidates[0], service, time.Now())
	if _, _, err := wrapped.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	path := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_dns/ipv4", "")
	if path.Successes != 1 || path.Health != HealthHealthy {
		t.Fatalf("DNS-shaped UDP success missing path evidence: %+v", path)
	}
	_ = wrapped.Close()

	// Garbage must not elevate DNS path.
	health2 := NewHealthStore(time.Hour, 32)
	pool2, snapshot2 := newWiredObservationPool(t, health2, wired(NodeID{98}, "udp-dns-junk", newTestOutbound("udp-dns-junk")))
	service2 := testBusinessService(N.NetworkUDP)
	service2.ID = "dns-junk"
	service2.HealthTransport = "udp_dns/ipv4"
	wrapped2 := pool2.wrapBusinessPacketConn(&packetMemoryConn{payload: []byte("not-dns!!!!"), source: &net.UDPAddr{IP: net.ParseIP("198.51.100.53"), Port: 53}}, snapshot2, snapshot2.Candidates[0], service2, time.Now())
	if _, _, err := wrapped2.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if path := health2.StatusHandle(snapshot2.Candidates[0].Handle, DomainTransport, "udp_dns/ipv4", ""); path.Successes != 0 {
		t.Fatalf("non-DNS payload elevated DNS path: %+v", path)
	}
	// Garbage on a DNS path must not wash service half-open either.
	if svc := health2.StatusHandle(snapshot2.Candidates[0].Handle, DomainService, "", service2.ID); svc.Successes != 0 {
		t.Fatalf("non-DNS payload must not settle service success: %+v", svc)
	}
	_ = wrapped2.Close()
}

func TestPayloadSuccessLearnsWhenServicePermitBusy(t *testing.T) {
	// Use real wall clock: observePayload stamps evidence.At with time.Now(), and
	// HealthStore prune is keyed off that wall time (must not mix fake clocks).
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Nanosecond, MaxCooldown: time.Second, JitterFraction: 0})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{99}, "busy-learn", newTestOutbound("busy-learn")))
	handle := snapshot.Candidates[0].Handle
	service := testBusinessService(N.NetworkTCP)
	// Open service breaker then enter half-open so a token is required.
	now := time.Now()
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: handle.Slot, NodeVersion: handle.Version, Scope: DomainService, Service: service.ID, Outcome: OutcomeFailure, At: now.Add(-time.Millisecond)})
	if before := health.StatusHandle(handle, DomainService, "", service.ID); before.Breaker != BreakerOpen {
		t.Fatalf("setup open failed: %+v", before)
	}
	owner, ok := health.TryAcquireDomainPermitHandle(handle, DomainService, "", service.ID, time.Now())
	if !ok || owner == nil {
		t.Fatal("expected half-open service permit")
	}
	if mid := health.StatusHandle(handle, DomainService, "", service.ID); mid.Breaker != BreakerHalfOpen {
		t.Fatalf("expected half-open after acquire: %+v", mid)
	}
	// Concurrent payload while owner holds the token: quality learn, no steal.
	observation, err := pool.beginBusinessObservation(snapshot, snapshot.Candidates[0], service)
	if err != nil {
		t.Fatal(err)
	}
	observation.observePayload(SourceFirstByte, time.Millisecond)
	status := health.StatusHandle(handle, DomainService, "", service.ID)
	if status.NonBreakerSuccesses < 1 {
		t.Fatalf("busy payload did not quality-learn: %+v", status)
	}
	if status.Successes != 0 || status.RecoverySuccesses != 0 || status.Breaker != BreakerHalfOpen || status.Failures != 1 {
		t.Fatalf("busy learn must not settle half-open without owner token: %+v", status)
	}
	if pool.observationPermitBusy.Load() == 0 {
		t.Fatal("expected permit-busy counter increment")
	}
	owner.ReleaseDeferred()
	observation.release()
}

func TestDialTimeoutIsMediumConfidenceQualityOnly(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{100}, "dial-timeout", newTestOutbound("dial-timeout")))
	handle := snapshot.Candidates[0].Handle
	service := testBusinessService(N.NetworkTCP)
	service.HealthTransport = "tcp/ipv4"
	permit, ok := health.TryAcquireConnectionPermitHandle(handle, "tcp/ipv4", time.Now())
	if !ok {
		t.Fatal("permit")
	}
	attempt, err := pool.beginObservationAttempt(snapshot, snapshot.Candidates[0], permit, N.NetworkTCP, "tcp/ipv4")
	if err != nil {
		t.Fatal(err)
	}
	pool.completeTransportAttempt(attempt, service, M.ParseSocksaddr("1.2.3.4:443"), DialAttemptResult{
		Candidate: snapshot.Candidates[0], Err: context.DeadlineExceeded, Delay: time.Second,
	})
	status := health.StatusHandle(handle, DomainTransport, "tcp/ipv4", "")
	if status.Failures != 0 || status.NonBreakerFailures != 1 || status.Breaker != BreakerClosed || status.Health != HealthDegraded {
		t.Fatalf("single dial timeout must be quality-only medium conf: %+v", status)
	}
}

func TestDialTimeoutEscalatesToUnreachableWithoutHardErrno(t *testing.T) {
	// FailureThreshold default is 3: three medium timeouts → HealthUnreachable,
	// path leaves Plan, lease is dropped — without opening a breaker on one RTT.
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 3, BaseCooldown: time.Second, MaxCooldown: time.Minute, JitterFraction: 0})
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{101}, "timeout-hole", newTestOutbound("timeout-hole")))
	handle := snapshot.Candidates[0].Handle
	service := testBusinessService(N.NetworkTCP)
	service.HealthTransport = "tcp/ipv4"
	service.Mode = ModeAdaptive
	pool.leases.ReplaceHandle(service.Session, NodeHandle{}, handle, service.ID, service.Mode, time.Hour, time.Now())
	for i := 0; i < 3; i++ {
		permit, ok := health.TryAcquireConnectionPermitHandle(handle, "tcp/ipv4", time.Now())
		if !ok {
			t.Fatalf("permit %d", i)
		}
		attempt, err := pool.beginObservationAttempt(snapshot, snapshot.Candidates[0], permit, N.NetworkTCP, "tcp/ipv4")
		if err != nil {
			t.Fatal(err)
		}
		pool.completeTransportAttempt(attempt, service, M.ParseSocksaddr("1.2.3.4:443"), DialAttemptResult{
			Candidate: snapshot.Candidates[0], Err: context.DeadlineExceeded, Delay: time.Second,
		})
	}
	status := health.StatusHandle(handle, DomainTransport, "tcp/ipv4", "")
	if status.NonBreakerFailures != 3 || status.Health != HealthUnreachable || status.Breaker != BreakerClosed {
		t.Fatalf("timeout blackhole escalation mismatch: %+v", status)
	}
	if _, loaded := pool.leases.Peek(service.Session, time.Now()); loaded {
		t.Fatal("unreachable timeout path retained sticky lease")
	}
	if health.RequiredPathKnownBlocked(handle, service, time.Now()) != true {
		t.Fatal("unreachable timeout path still eligible in plan")
	}
}

func TestDomainPermitResolvesQualifiedTransportKey(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 1, BaseCooldown: time.Millisecond, MaxCooldown: time.Second, JitterFraction: 0})
	handle := NodeHandle{NodeID: NodeID{102}, Slot: 1, Version: 1}
	// Open the qualified ledger.
	health.Observe(Observation{NodeID: handle.NodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: "tcp/ipv4", Outcome: OutcomeFailure, At: time.Now().Add(-time.Millisecond)})
	// Acquire via bare class must resolve to the same open record (not a fresh key).
	permit, ok := health.TryAcquireDomainPermitHandle(handle, DomainTransport, N.NetworkTCP, "", time.Now())
	if !ok || permit == nil {
		t.Fatal("expected half-open via bare tcp key resolution")
	}
	status := health.StatusHandle(handle, DomainTransport, "tcp/ipv4", "")
	if status.Breaker != BreakerHalfOpen {
		t.Fatalf("bare tcp acquire missed qualified open ledger: %+v", status)
	}
	// Second acquire while token held must fail (same record).
	if _, ok := health.TryAcquireDomainPermitHandle(handle, DomainTransport, "tcp/any", "", time.Now()); ok {
		t.Fatal("second acquire bypassed half-open owner via alternate key")
	}
	permit.ReleaseDeferred()
}

func TestQualityUnreachableRecoversOnMediumSuccess(t *testing.T) {
	health := NewHealthStoreWithClock(time.Hour, 32, realClock{}, BreakerConfig{FailureThreshold: 2, BaseCooldown: time.Second, MaxCooldown: time.Minute, JitterFraction: 0})
	handle := NodeHandle{NodeID: NodeID{110}, Slot: 1, Version: 1}
	path := "tcp/ipv4"
	now := time.Now()
	for i := 0; i < 2; i++ {
		health.ObserveEvidence(Observation{
			NodeID: handle.NodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: path,
			Outcome: OutcomeFailure, At: now, Reason: "timeout",
		}, false, 0.6)
	}
	if st := health.StatusHandle(handle, DomainTransport, path, ""); st.Health != HealthUnreachable {
		t.Fatalf("setup unreachable: %+v", st)
	}
	health.ObserveEvidence(Observation{
		NodeID: handle.NodeID, NodeSlot: 1, NodeVersion: 1, Scope: DomainTransport, Transport: path,
		Outcome: OutcomeSuccess, Delay: 20 * time.Millisecond, At: now.Add(time.Second),
	}, false, 0.6)
	st := health.StatusHandle(handle, DomainTransport, path, "")
	if st.Health != HealthHealthy || st.NonBreakerFailures != 0 {
		t.Fatalf("medium success did not clear quality blackhole: %+v", st)
	}
}

func TestTransactionalUDPNoResponseIsMediumConfidence(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{185}, "udp-transaction", newTestOutbound("udp-transaction")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	service.ExpectUDPResponse = true
	wrapped := pool.wrapBusinessPacketConn(&packetMemoryConn{}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second))
	if _, err := wrapped.WriteTo([]byte("quic-initial"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if status.NonBreakerFailures != 1 || status.Health != HealthDegraded {
		t.Fatalf("transactional UDP no-response was not medium evidence: %+v", status)
	}
}

func TestOneWayUDPCloseDoesNotCreateFailure(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{186}, "udp-one-way", newTestOutbound("udp-one-way")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	wrapped := pool.wrapBusinessPacketConn(&packetMemoryConn{}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second))
	if _, err := wrapped.WriteTo([]byte("telemetry"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9000}); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if status.NonBreakerFailures != 0 || status.Failures != 0 {
		t.Fatalf("one-way UDP was falsely penalized: %+v", status)
	}
}

func TestTransactionalUDPTimeoutAndCloseOnlyCountOnce(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{187}, "udp-timeout-once", newTestOutbound("udp-timeout-once")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	service.ExpectUDPResponse = true
	conn := pool.wrapBusinessPacketConn(&packetMemoryConn{}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second)).(*observedExtendedPacketConn).observedPacketConn
	conn.writePackets.Store(1)
	conn.observeFailure(context.DeadlineExceeded)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if status.NonBreakerFailures != 1 {
		t.Fatalf("one UDP flow submitted duplicate timeout evidence: %+v", status)
	}
}

func TestTransactionalUDPIdleAfterResponseDoesNotFail(t *testing.T) {
	health := NewHealthStore(time.Hour, 32)
	pool, snapshot := newWiredObservationPool(t, health, wired(NodeID{188}, "udp-response", newTestOutbound("udp-response")))
	service := testBusinessService(N.NetworkUDP)
	service.HealthTransport = "udp_data/ipv4"
	service.ExpectUDPResponse = true
	conn := pool.wrapBusinessPacketConn(&packetMemoryConn{}, snapshot, snapshot.Candidates[0], service, time.Now().Add(-2*time.Second)).(*observedExtendedPacketConn).observedPacketConn
	conn.writePackets.Store(1)
	conn.readPackets.Store(1)
	conn.observeFailure(context.DeadlineExceeded)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	status := health.StatusHandle(snapshot.Candidates[0].Handle, DomainTransport, "udp_data/ipv4", "")
	if status.NonBreakerFailures != 0 || status.Failures != 0 {
		t.Fatalf("idle timeout after a UDP response was penalized: %+v", status)
	}
}
