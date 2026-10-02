package adaptive

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsHealthPacketConn struct {
	access  sync.Mutex
	query   []byte
	readErr error
}

func (c *dnsHealthPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(c.query)
	if err != nil {
		return 0, nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return 0, nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
	if err = builder.StartQuestions(); err != nil {
		return 0, nil, err
	}
	if err = builder.Question(question); err != nil {
		return 0, nil, err
	}
	response, err := builder.Finish()
	if err != nil {
		return 0, nil, err
	}
	return copy(payload, response), &net.UDPAddr{}, nil
}

func (c *dnsHealthPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.access.Lock()
	c.query = append(c.query[:0], payload...)
	c.access.Unlock()
	return len(payload), nil
}

func (*dnsHealthPacketConn) Close() error                     { return nil }
func (*dnsHealthPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*dnsHealthPacketConn) SetDeadline(time.Time) error      { return nil }
func (*dnsHealthPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*dnsHealthPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dnsHealthDialer struct {
	access      sync.Mutex
	failures    int
	connections int
}

func (*dnsHealthDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("TCP is not used by DNS health")
}

func (d *dnsHealthDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	d.connections++
	failed := d.connections <= d.failures
	d.access.Unlock()
	if failed {
		return &dnsHealthPacketConn{readErr: context.DeadlineExceeded}, nil
	}
	return &dnsHealthPacketConn{}, nil
}

func TestDNSHealthRequiresValidMatchingResponse(t *testing.T) {
	message, id, question, err := buildDNSHealthQuery()
	if err != nil {
		t.Fatal(err)
	}
	if err = validateDNSHealthResponse(message, id, question); err == nil {
		t.Fatal("DNS query was accepted as a response")
	}
	conn := &dnsHealthPacketConn{query: message}
	response := make([]byte, 4096)
	count, _, err := conn.ReadFrom(response)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateDNSHealthResponse(response[:count], id, question); err != nil {
		t.Fatalf("valid DNS response rejected: %v", err)
	}
	response[0] ^= 0xff
	if err = validateDNSHealthResponse(response[:count], id, question); err == nil {
		t.Fatal("mismatched DNS transaction ID was accepted")
	}
}

func TestDNSHealthUsesSecondIndependentTarget(t *testing.T) {
	dialer := &dnsHealthDialer{failures: 1}
	if err := runDNSHealthTargets(context.Background(), dialer, "ipv4"); err != nil {
		t.Fatalf("second DNS target did not recover first-target failure: %v", err)
	}
	if dialer.connections != 2 {
		t.Fatalf("unexpected DNS target attempts: %d", dialer.connections)
	}
	dialer = &dnsHealthDialer{failures: 2}
	if err := runDNSHealthTargets(context.Background(), dialer, "ipv6"); err == nil {
		t.Fatal("two independent DNS target failures were accepted")
	}
}

func TestProxyFramingProbeErrorClassification(t *testing.T) {
	if !isProxyFramingProbeError(errors.New("read destination: unknown address family: 0")) {
		t.Fatal("address family framing must match")
	}
	if !isProxyFramingProbeError(errors.New("unknown version: 72")) {
		t.Fatal("version framing must match")
	}
	if isProxyFramingProbeError(errors.New("read destination: i/o timeout")) {
		t.Fatal("timeout must not be classified as framing")
	}
	if isProxyFramingProbeError(context.DeadlineExceeded) {
		t.Fatal("deadline must not be framing")
	}
}

func TestProxyFramingDNSHealthDoesNotMarkUnreachable(t *testing.T) {
	// ConfidenceLow framing must stay metrics-only even after many failures.
	store := NewHealthStore(time.Hour, 32)
	handle := NodeHandle{NodeID: NodeID{9}, Slot: 1, Version: 1}
	path := "udp_dns/ipv4"
	for range 6 {
		evidence := ObservationEvidence{
			Source: SourceDNS, Stage: StageDNSHealth, Transport: "udp", NetworkPath: path,
			Handle: handle, Outcome: OutcomeFailure, Failure: FailureProtocol,
			Confidence: ConfidenceLow, Reason: "read destination: unknown address family: 0",
			At: store.Now(),
		}
		domains, err := evidence.MapDomains()
		if err != nil {
			t.Fatal(err)
		}
		if err = (&HealthObservationReducer{Store: store}).Reduce(evidence, domains); err != nil {
			t.Fatal(err)
		}
	}
	status := store.StatusHandle(handle, DomainTransport, path, "")
	if status.Health == HealthUnreachable || status.Health == HealthDegraded {
		t.Fatalf("framing noise flipped health: %+v", status)
	}
	if status.Breaker != BreakerClosed && status.Breaker != "" {
		t.Fatalf("framing noise opened breaker: %+v", status)
	}
}

func TestProviderReplicaTagDetection(t *testing.T) {
	if !isProviderReplicaTag("airport/香港-广东专线 NeaRoute-2 (2)") {
		t.Fatal("expected replica tag")
	}
	if isProviderReplicaTag("airport/香港-广东专线 NeaRoute-2") {
		t.Fatal("primary must not be replica")
	}
	if isProviderReplicaCandidate(Candidate{PrimaryTag: "node", EndpointConflictCount: 2}) {
		t.Fatal("conflict alone without (N) suffix is not a replica")
	}
	if !isProviderReplicaCandidate(Candidate{PrimaryTag: "node (3)", EndpointConflictCount: 2}) {
		t.Fatal("replica tag must match")
	}
}
