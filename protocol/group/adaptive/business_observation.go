package adaptive

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var ErrObservationIdentityIncomplete = errors.New("adaptive business observation identity is incomplete")

// businessObservation keeps the runtime identity that actually created a
// connection. It never consults the active catalog to relabel old traffic.
type businessObservation struct {
	pool           *AdaptivePool
	health         *HealthStore
	leases         *SessionLeaseManager
	policy         *PolicyEngine
	lease          *RuntimeEpochIdentityLease
	guard          ObservationIdentityGuard
	evidence       ObservationEvidence
	service        ServiceContext
	payloadOnce    sync.Once
	udpPathOnce    sync.Once
	failureOnce    sync.Once
	throughputOnce sync.Once
	releaseOnce    sync.Once
}

func (o *businessObservation) observeTLSFailure(delay time.Duration, failure FailureClass, confidence ObservationConfidence, reason string) {
	if o == nil {
		return
	}
	o.failureOnce.Do(func() {
		evidence := o.evidence
		evidence.Source = SourceTLS
		evidence.Stage = StageServiceApplication
		evidence.Confidence = confidence
		evidence.Outcome = OutcomeFailure
		evidence.Failure = failure
		evidence.Delay = delay
		evidence.At = o.health.Now()
		evidence.Reason = reason
		permit, allowed := o.health.TryAcquireDomainPermitHandle(o.evidence.Handle, DomainService, "", o.service.ID, o.health.Now())
		var reducer *HealthObservationReducer
		if !allowed {
			// Half-open owner busy: still record quality (non-breaker) so concurrent
			// failures are not silently dropped — learning continues without stealing tokens.
			o.pool.observationPermitBusy.Add(1)
			if confidence > ConfidenceLow {
				evidence.Confidence = ConfidenceLow
			}
			reducer = &HealthObservationReducer{Store: o.health, BeforeReduce: o.pool.observationReducerHook}
		} else {
			reducer = &HealthObservationReducer{Store: o.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: o.pool.observationReducerHook}
		}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
		if publishErr == nil && disposition == IngestAccepted && confidence >= ConfidenceHigh && allowed {
			o.pool.businessTLSFailures.Add(1)
			earlyFailure := o.policy != nil && o.policy.ForgetSelectionAfterEarlyFailure(o.service, o.evidence.Handle, evidence.At)
			if earlyFailure {
				o.leases.Invalidate(o.service.Session, o.evidence.Handle.NodeID)
			}
			status := o.health.StatusHandle(o.evidence.Handle, DomainService, "", o.service.ID)
			if !earlyFailure && status.Breaker != BreakerOpen && status.Breaker != BreakerCooldown {
				return
			}
			if snapshot := o.pool.catalog.load(); snapshot != nil {
				if candidate, loaded := snapshot.Candidate(o.evidence.Handle.NodeID); loaded {
					o.pool.switchAudit.RecordFailure(o.service.Session, o.service.ID, candidate, FailureTLS, "business_tls", evidence.At)
					o.pool.recordFailureMemory(candidate, FailureTLS, o.service.ID, serviceHealthTransport(o.service))
				}
			}
			o.leases.Invalidate(o.service.Session, o.evidence.Handle.NodeID)
			o.pool.scheduleFailureProbe(o.evidence.Handle)
			o.pool.persistState()
		}
	})
}

func (o *businessObservation) observeUDPFailure(err error, delay time.Duration) {
	o.observeUDPFailureConfidence(err, delay, ConfidenceLow)
}

func (o *businessObservation) observeUDPFailureConfidence(err error, delay time.Duration, timeoutConfidence ObservationConfidence) {
	if o == nil || err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	o.failureOnce.Do(func() {
		confidence := ConfidenceLow
		failure := FailureConnect
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			// Ordinary timeouts stay low-confidence. Transactional UDP with a
			// confirmed write and no response may promote this to medium after the
			// client itself gives up; repeated blackholes can then leave the plan.
			failure = FailureTimeout
			confidence = timeoutConfidence
		} else if isNodeNetworkIOError(err) {
			// Strong network errors (reset/unreachable/refused/…) open transport breakers.
			confidence = ConfidenceHigh
		}
		evidence := o.evidence
		evidence.Source = SourceUDP
		evidence.Stage = StageDestinationTransport
		evidence.NetworkPath = normalizeHealthTransportPath(serviceHealthTransport(o.service))
		if evidence.NetworkPath == "" {
			evidence.NetworkPath = serviceHealthTransport(o.service)
		}
		evidence.Confidence = confidence
		evidence.Outcome = OutcomeFailure
		evidence.Failure = failure
		evidence.Delay = delay
		evidence.At = o.health.Now()
		evidence.Reason = errorReason(err)
		reducer := &HealthObservationReducer{Store: o.health, BeforeReduce: o.pool.observationReducerHook}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
		if publishErr != nil || disposition != IngestAccepted || confidence != ConfidenceHigh {
			return
		}
		o.pool.transportFailures.Add(1)
		status := o.health.StatusHandle(o.evidence.Handle, DomainTransport, evidence.NetworkPath, "")
		if status.Breaker == BreakerOpen || status.Breaker == BreakerCooldown {
			o.leases.Invalidate(o.service.Session, o.evidence.Handle.NodeID)
			o.pool.scheduleFailureProbe(o.evidence.Handle)
			o.pool.persistState()
		}
	})
}

func (p *AdaptivePool) beginBusinessObservation(snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext) (*businessObservation, error) {
	health, leases, _, policy := p.runtimeSnapshot()
	if snapshot == nil || snapshot.RuntimeEpochID == 0 || snapshot.CatalogRevision == 0 || p.runtimeManager == nil || health == nil {
		return nil, ErrObservationIdentityIncomplete
	}
	lease, err := p.runtimeManager.AcquireEpoch(p.groupID, snapshot.RuntimeEpochID)
	if err != nil {
		return nil, err
	}
	evidence := ObservationEvidence{
		RuntimeEpochID: snapshot.RuntimeEpochID, CatalogRevision: snapshot.CatalogRevision, SourceGeneration: snapshot.Generation,
		Handle: candidate.Handle, AttemptID: AttemptID(p.attemptSequence.Add(1)), ServiceID: service.ID, Transport: service.Transport,
	}
	return &businessObservation{pool: p, health: health, leases: leases, policy: policy, lease: lease, guard: RuntimeEpochObservationGuard{Lease: lease}, evidence: evidence, service: service}, nil
}

func (o *businessObservation) observePayload(source ObservationSource, delay time.Duration) {
	if o == nil {
		return
	}
	defer func() {
		if recover() != nil {
			o.pool.recordObservationPanic()
		}
	}()
	o.payloadOnce.Do(func() {
		// Half-open owner busy: still quality-learn at low confidence so concurrent
		// successes are not silently dropped (parity with observeTLSFailure).
		permit, allowed := o.health.TryAcquireDomainPermitHandle(o.evidence.Handle, DomainService, "", o.service.ID, o.health.Now())
		evidence := o.evidence
		evidence.Source = source
		evidence.Stage = StageServiceApplication
		evidence.Confidence = ConfidenceHigh
		evidence.Outcome = OutcomeSuccess
		evidence.Failure = FailureNone
		evidence.Delay = delay
		evidence.At = o.health.Now()
		var reducer *HealthObservationReducer
		if !allowed {
			o.pool.observationPermitBusy.Add(1)
			evidence.Confidence = ConfidenceLow
			reducer = &HealthObservationReducer{Store: o.health, BeforeReduce: o.pool.observationReducerHook}
		} else {
			reducer = &HealthObservationReducer{Store: o.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: o.pool.observationReducerHook}
		}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
	})
}

// observeUDPSuccess closes the passive UDP path loop:
//  1. transport/DNS path evidence so udp_dns / udp_data ledgers can recover;
//  2. service payload success only when the payload is admissible for that path
//     (DNS requires a response-shaped packet — garbage must not wash service half-open).
func (o *businessObservation) observeUDPSuccess(payload []byte, delay time.Duration) {
	if o == nil || len(payload) == 0 {
		return
	}
	pathOK := o.observeUDPPathSuccess(payload, delay)
	class, _ := splitHealthTransport(normalizeHealthTransportPath(serviceHealthTransport(o.service)))
	if class == healthTransportUDPDNS && !pathOK {
		// Non-DNS bytes on a DNS path: no transport success and no service success.
		return
	}
	o.observePayload(SourceUDP, delay)
}

// observeUDPPathSuccess reports whether the payload is admissible path evidence.
// False means the payload must not count for transport or service success.
func (o *businessObservation) observeUDPPathSuccess(payload []byte, delay time.Duration) bool {
	if o == nil || len(payload) == 0 || o.pool == nil || o.health == nil {
		return false
	}
	path := normalizeHealthTransportPath(serviceHealthTransport(o.service))
	if path == "" {
		path = serviceHealthTransport(o.service)
	}
	class, _ := splitHealthTransport(path)
	if class == healthTransportUDPDNS && !looksLikeDNSResponse(payload) {
		// DNS success requires a response-shaped packet (QR bit). Bare noise
		// must not wash a broken resolver path — or service half-open — clean.
		return false
	}
	defer func() {
		if recover() != nil {
			o.pool.recordObservationPanic()
		}
	}()
	o.udpPathOnce.Do(func() {
		source := SourceUDP
		stage := StageDestinationTransport
		if class == healthTransportUDPDNS {
			source = SourceDNS
			stage = StageDNSHealth
		}
		evidence := o.evidence
		evidence.Source = source
		evidence.Stage = stage
		evidence.NetworkPath = path
		evidence.Confidence = ConfidenceHigh
		evidence.Outcome = OutcomeSuccess
		evidence.Failure = FailureNone
		evidence.Delay = delay
		evidence.At = o.health.Now()
		evidence.Reason = ""
		permit, allowed := o.health.TryAcquireDomainPermitHandle(o.evidence.Handle, DomainTransport, path, "", o.health.Now())
		var reducer *HealthObservationReducer
		if !allowed {
			o.pool.observationPermitBusy.Add(1)
			evidence.Confidence = ConfidenceLow
			reducer = &HealthObservationReducer{Store: o.health, BeforeReduce: o.pool.observationReducerHook}
		} else {
			reducer = &HealthObservationReducer{Store: o.health, Settlement: AttemptPermitSettlement{Permit: permit}, BeforeReduce: o.pool.observationReducerHook}
		}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
	})
	return true
}

// looksLikeDNSResponse is a minimal passive DNS QR check. It does not parse
// questions or compare IDs (that belongs to active dns_health probes).
func looksLikeDNSResponse(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	// Header byte 2 bit 7 = QR (1 = response).
	return payload[2]&0x80 != 0
}

func (o *businessObservation) observeThroughput(bytes int64, elapsed time.Duration) {
	if o == nil || bytes < 64*1024 || elapsed < time.Second {
		return
	}
	o.throughputOnce.Do(func() {
		bps := float64(bytes) / elapsed.Seconds()
		if bps <= 0 {
			return
		}
		evidence := o.evidence
		evidence.Source = SourceThroughput
		evidence.Stage = StageServiceApplication
		evidence.Confidence = ConfidenceMedium
		evidence.Outcome = OutcomeSuccess
		evidence.Failure = FailureNone
		evidence.ThroughputBPS = bps
		evidence.At = o.health.Now()
		reducer := &HealthObservationReducer{Store: o.health, BeforeReduce: o.pool.observationReducerHook}
		disposition, publishErr := PublishSettledObservationGuarded(o.pool.sharedObservationIngestor(), o.guard, evidence, reducer)
		o.pool.recordObservationResult(disposition, publishErr)
	})
}

func (o *businessObservation) release() {
	if o == nil {
		return
	}
	o.releaseOnce.Do(o.lease.Release)
}

func (p *AdaptivePool) wrapBusinessConn(conn net.Conn, snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext, startedAt time.Time) net.Conn {
	observation, err := p.beginBusinessObservation(snapshot, candidate, service)
	if err != nil {
		p.recordObservationIdentityFailure()
		return conn
	}
	base := &observedConn{Conn: conn, startedAt: startedAt, observation: observation}
	if extended, loaded := conn.(N.ExtendedConn); loaded {
		return &observedExtendedConn{observedConn: base, extended: extended}
	}
	return base
}

type observedConn struct {
	net.Conn
	startedAt   time.Time
	observation *businessObservation
	closeOnce   sync.Once
	closeErr    error
	readBytes   atomic.Int64
	writeBytes  atomic.Int64
	tlsStarted  atomic.Bool
	localClosed atomic.Bool
}

func (c *observedConn) observeRead(count int) {
	if count > 0 {
		c.readBytes.Add(int64(count))
		c.observation.observePayload(SourceFirstByte, time.Since(c.startedAt))
	}
}

func (c *observedConn) Read(payload []byte) (int, error) {
	count, err := c.Conn.Read(payload)
	c.observeRead(count)
	if failure, confidence, actionable := classifyEarlyTLSFailure(err); count == 0 && actionable && !c.localClosed.Load() && c.readBytes.Load() == 0 && c.tlsStarted.Load() && time.Since(c.startedAt) <= 15*time.Second {
		c.observation.observeTLSFailure(time.Since(c.startedAt), failure, confidence, errorReason(err))
	}
	if errors.Is(err, io.EOF) {
		c.observeThroughput()
		c.observation.release()
	}
	return count, err
}

func classifyEarlyTLSFailure(err error) (FailureClass, ObservationConfidence, bool) {
	// EOF / local close / cancel: browsers abandon speculative races; never punish.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return FailureNone, 0, false
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
		// Timeout alone is weak for identity thrash — low confidence, no hard open
		// until the breaker policy says so via weight (typically non-opening).
		return FailureTimeout, ConfidenceLow, true
	}
	// Write/Read early path: only strong network I/O evidence may open service
	// breakers and invalidate leases. Opaque framing/local errors must not.
	// (Parity with ReadFrom's isNodeNetworkIOError gate.)
	if isNodeNetworkIOError(err) {
		return FailureTLS, ConfidenceHigh, true
	}
	return FailureNone, 0, false
}

func (c *observedConn) Close() error {
	c.closeOnce.Do(func() {
		// Browsers abandon speculative TCP/TLS connections when another address,
		// HTTP/3, or a pooled connection wins. Mark the local close first so the
		// unblocked Read cannot be misclassified as a remote TLS failure.
		c.localClosed.Store(true)
		c.observeThroughput()
		c.closeErr = c.Conn.Close()
		c.observation.release()
	})
	return c.closeErr
}

func (c *observedConn) observeThroughput() {
	c.observation.observeThroughput(c.readBytes.Load()+c.writeBytes.Load(), time.Since(c.startedAt))
}

func (c *observedConn) observeWriteFailure(err error) {
	if c == nil || err == nil || c.localClosed.Load() || !c.tlsStarted.Load() {
		return
	}
	failure, confidence, actionable := classifyEarlyTLSFailure(err)
	if !actionable {
		return
	}
	c.observation.observeTLSFailure(time.Since(c.startedAt), failure, confidence, errorReason(err))
}

func (c *observedConn) Write(payload []byte) (int, error) {
	if isTLSClientHello(payload) {
		c.tlsStarted.Store(true)
	}
	count, err := c.Conn.Write(payload)
	if count > 0 {
		c.writeBytes.Add(int64(count))
	}
	// Same network-only attribution as ReadFrom — local/body errors must not
	// open identity breakers via the Write path.
	if err != nil && isNodeNetworkIOError(err) {
		c.observeWriteFailure(err)
	}
	return count, err
}

func isTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

func (c *observedConn) ReadFrom(reader io.Reader) (int64, error) {
	if readerFrom, loaded := c.Conn.(io.ReaderFrom); loaded {
		count, err := readerFrom.ReadFrom(reader)
		if count > 0 {
			c.writeBytes.Add(count)
		}
		// ReadFrom errors may originate from the upstream reader (file/body
		// cancel) rather than the network socket. Only attribute clear network
		// I/O failures to node health.
		if err != nil && isNodeNetworkIOError(err) {
			c.observeWriteFailure(err)
		}
		if err == nil || errors.Is(err, io.EOF) {
			c.observeThroughput()
		}
		return count, err
	}
	count, err := io.Copy(c, reader)
	if err == nil || errors.Is(err, io.EOF) {
		c.observeThroughput()
	}
	return count, err
}

// isNodeNetworkIOError reports whether err is strong evidence of a network-path
// problem rather than a local/upstream reader failure (request body cancel,
// file read error, etc.).
//
// net.OpError is intentionally narrow: only dial/read/write/accept ops with a
// network-class syscall or timeout count. Arbitrary OpError wrappers around
// local failures must not mark the node unhealthy.
func isNodeNetworkIOError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return isNetworkOpError(opErr)
	}
	return isNetworkSyscallError(err)
}

func isNetworkOpError(opErr *net.OpError) bool {
	if opErr == nil {
		return false
	}
	switch opErr.Op {
	case "dial", "read", "write", "accept", "readfrom", "writeto":
	default:
		// e.g. file/path ops accidentally wrapped as OpError must not count.
		return false
	}
	if opErr.Timeout() {
		return true
	}
	if opErr.Err == nil {
		return false
	}
	if isTimeoutError(opErr.Err) || errors.Is(opErr.Err, context.DeadlineExceeded) {
		return true
	}
	if isNetworkSyscallError(opErr.Err) {
		return true
	}
	var syscallErr *os.SyscallError
	if errors.As(opErr.Err, &syscallErr) {
		return isNetworkSyscallError(syscallErr.Err)
	}
	return false
}

func isNetworkSyscallError(err error) bool {
	switch {
	case errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ETIMEDOUT),
		errors.Is(err, syscall.ECONNABORTED):
		return true
	default:
		return false
	}
}

func (c *observedConn) WriteTo(writer io.Writer) (int64, error) {
	observedWriter := &payloadObservingWriter{Writer: writer, observe: c.observeRead}
	var count int64
	var err error
	if writerTo, loaded := c.Conn.(io.WriterTo); loaded {
		count, err = writerTo.WriteTo(observedWriter)
	} else {
		count, err = io.Copy(observedWriter, struct{ io.Reader }{c.Conn})
	}
	if err == nil || errors.Is(err, io.EOF) {
		c.observeThroughput()
		c.observation.release()
	}
	return count, err
}

func (c *observedConn) Upstream() any         { return c.Conn }
func (*observedConn) ReaderReplaceable() bool { return false }
func (*observedConn) WriterReplaceable() bool { return false }

type payloadObservingWriter struct {
	io.Writer
	observe func(int)
}

func (w *payloadObservingWriter) Write(payload []byte) (int, error) {
	count, err := w.Writer.Write(payload)
	w.observe(count)
	return count, err
}

type observedExtendedConn struct {
	*observedConn
	extended N.ExtendedConn
}

func (c *observedExtendedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.extended.ReadBuffer(buffer)
	c.observeRead(buffer.Len() - before)
	if failure, confidence, actionable := classifyEarlyTLSFailure(err); buffer.Len() == before && actionable && !c.localClosed.Load() && c.readBytes.Load() == 0 && c.tlsStarted.Load() && time.Since(c.startedAt) <= 15*time.Second {
		c.observation.observeTLSFailure(time.Since(c.startedAt), failure, confidence, errorReason(err))
	}
	if errors.Is(err, io.EOF) {
		c.observation.release()
	}
	return err
}

func (c *observedExtendedConn) WriteBuffer(buffer *buf.Buffer) error {
	count := buffer.Len()
	if isTLSClientHello(buffer.Bytes()) {
		c.tlsStarted.Store(true)
	}
	err := c.extended.WriteBuffer(buffer)
	if err == nil && count > 0 {
		c.writeBytes.Add(int64(count))
	}
	if err != nil {
		c.observeWriteFailure(err)
	}
	return err
}

func (p *AdaptivePool) wrapBusinessPacketConn(conn net.PacketConn, snapshot *ExecutionSnapshot, candidate Candidate, service ServiceContext, startedAt time.Time) net.PacketConn {
	observation, err := p.beginBusinessObservation(snapshot, candidate, service)
	if err != nil {
		p.recordObservationIdentityFailure()
		return conn
	}
	base := &observedPacketConn{PacketConn: conn, startedAt: startedAt, observation: observation}
	reader, hasReader := conn.(N.PacketReader)
	writer, hasWriter := conn.(N.PacketWriter)
	switch {
	case hasReader && hasWriter:
		return &observedExtendedPacketConn{observedPacketConn: base, reader: reader, writer: writer}
	case hasReader:
		return &observedPacketReaderConn{observedPacketConn: base, reader: reader}
	case hasWriter:
		return &observedPacketWriterConn{observedPacketConn: base, writer: writer}
	default:
		return base
	}
}

func (p *AdaptivePool) recordObservationResult(disposition IngestDisposition, err error) {
	if p == nil {
		return
	}
	if err != nil {
		p.observationReducerFailure.Add(1)
		p.missedObservations.Add(1)
		return
	}
	switch disposition {
	case IngestAccepted:
	case IngestDuplicate:
		p.observationDuplicate.Add(1)
	case IngestStale:
		p.observationStale.Add(1)
	case IngestBackpressure:
		p.observationBackpressure.Add(1)
		p.missedObservations.Add(1)
	default:
		p.observationReducerFailure.Add(1)
		p.missedObservations.Add(1)
	}
}

func (p *AdaptivePool) recordObservationIdentityFailure() {
	if p == nil {
		return
	}
	p.observationIdentityFailure.Add(1)
	p.missedObservations.Add(1)
}

func (p *AdaptivePool) recordObservationPanic() {
	if p == nil {
		return
	}
	p.observationPanic.Add(1)
	p.missedObservations.Add(1)
}

type observedPacketConn struct {
	net.PacketConn
	startedAt    time.Time
	observation  *businessObservation
	closeOnce    sync.Once
	failureOnce  sync.Once
	closeErr     error
	writePackets atomic.Uint64
	readPackets  atomic.Uint64
}

func (c *observedPacketConn) observeRead(payload []byte, count int) {
	if count > 0 {
		c.readPackets.Add(1)
		c.observation.observeUDPSuccess(payload[:count], time.Since(c.startedAt))
	}
}

func (c *observedPacketConn) observeFailure(err error) {
	if c.readPackets.Load() > 0 && (errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err)) {
		// A transactional UDP exchange already produced a response. A later read
		// deadline is normal idle/teardown behavior, not evidence of a bad path.
		return
	}
	c.failureOnce.Do(func() {
		confidence := ConfidenceLow
		if c.observation.service.ExpectUDPResponse && c.writePackets.Load() > 0 && c.readPackets.Load() == 0 &&
			time.Since(c.startedAt) >= time.Second &&
			(errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err)) {
			confidence = ConfidenceMedium
		}
		c.observation.observeUDPFailureConfidence(err, time.Since(c.startedAt), confidence)
	})
}

func (c *observedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, source, err := c.PacketConn.ReadFrom(payload)
	c.observeRead(payload, count)
	if count == 0 && err != nil {
		c.observeFailure(err)
	}
	return count, source, err
}

func (c *observedPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	count, err := c.PacketConn.WriteTo(payload, destination)
	if count > 0 {
		c.writePackets.Add(1)
	}
	if count == 0 && err != nil {
		c.observation.observeUDPFailure(err, time.Since(c.startedAt))
	}
	return count, err
}

func (c *observedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.observation.service.ExpectUDPResponse && c.writePackets.Load() > 0 && c.readPackets.Load() == 0 && time.Since(c.startedAt) >= time.Second {
			c.observeFailure(context.DeadlineExceeded)
		}
		c.closeErr = c.PacketConn.Close()
		c.observation.release()
	})
	return c.closeErr
}

func (c *observedPacketConn) Upstream() any         { return c.PacketConn }
func (*observedPacketConn) ReaderReplaceable() bool { return false }
func (*observedPacketConn) WriterReplaceable() bool { return false }

type observedPacketReaderConn struct {
	*observedPacketConn
	reader N.PacketReader
}

func (c *observedPacketReaderConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	got := buffer.Len() - before
	if got > 0 {
		// ReadPacket appends into buffer; slice only the newly written bytes.
		c.observeRead(buffer.Bytes()[before:], got)
	}
	if got == 0 && err != nil {
		c.observeFailure(err)
	}
	return destination, err
}

type observedPacketWriterConn struct {
	*observedPacketConn
	writer N.PacketWriter
}

func (c *observedPacketWriterConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil && count > 0 {
		c.writePackets.Add(1)
	}
	if err != nil {
		c.observation.observeUDPFailure(err, time.Since(c.startedAt))
	}
	return err
}

type observedExtendedPacketConn struct {
	*observedPacketConn
	reader N.PacketReader
	writer N.PacketWriter
}

func (c *observedExtendedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	destination, err := c.reader.ReadPacket(buffer)
	got := buffer.Len() - before
	if got > 0 {
		c.observeRead(buffer.Bytes()[before:], got)
	}
	if got == 0 && err != nil {
		c.observeFailure(err)
	}
	return destination, err
}

func (c *observedExtendedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	count := buffer.Len()
	err := c.writer.WritePacket(buffer, destination)
	if err == nil && count > 0 {
		c.writePackets.Add(1)
	}
	if err != nil {
		c.observation.observeUDPFailure(err, time.Since(c.startedAt))
	}
	return err
}
