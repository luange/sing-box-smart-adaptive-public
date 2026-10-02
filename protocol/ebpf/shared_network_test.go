//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	ebpfv3 "github.com/sagernet/sing-box/protocol/ebpf/v3"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

// sharedDataplaneStub embeds the full production surface so these tests only
// need to observe the tuple operations relevant to v2 fallback.  A lifecycle
// can remain allocated after v3 prepare fails; engineV3 must decide which
// writer is authoritative.
type sharedDataplaneStub struct {
	ECommon.SharedDataplane
	puts    int
	deletes int
}

func (s *sharedDataplaneStub) PutDirectFlow(uint8, netip.AddrPort, netip.AddrPort, time.Duration) error {
	s.puts++
	return nil
}

func (s *sharedDataplaneStub) DeleteDirectFlow(uint8, netip.AddrPort, netip.AddrPort) error {
	s.deletes++
	return nil
}

type transparentPacketConnStub struct {
	err    atomic.Value
	closed atomic.Int32
}

func (c *transparentPacketConnStub) WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error) {
	err, _ := c.err.Load().(error)
	return 0, err
}

func (c *transparentPacketConnStub) Close() error {
	c.closed.Add(1)
	return nil
}

func TestTransparentWriterTransientFailureDoesNotInvalidateSharedSocket(t *testing.T) {
	destination := M.ParseSocksaddr("192.0.2.1:53")
	connection := new(transparentPacketConnStub)
	connection.err.Store(error(unix.ENOBUFS))
	entry := &transparentWriterEntry{conn: connection, refs: 2}
	// dataPlane must be socket_assign so WritePacket uses the transparent path
	// (token mode would dereference a nil clientState).
	shared := &sharedNetwork{
		dataPlane: sharedNetworkDataPlaneSocketAssign,
		transparentWriters: map[netip.AddrPort]*transparentWriterEntry{
			destination.AddrPort(): entry,
		},
	}
	writer := &sharedPacketWriter{
		shared:      shared,
		client:      netip.MustParseAddrPort("192.0.2.2:53000"),
		bound:       destination,
		transparent: entry,
	}
	buffer := buf.New()
	_, _ = buffer.Write([]byte("dns"))
	if err := writer.WritePacket(buffer, destination); !errors.Is(err, unix.ENOBUFS) {
		t.Fatalf("unexpected write error: %v", err)
	}
	if shared.transparentWriters[destination.AddrPort()] != entry || writer.transparent != entry {
		t.Fatal("transient packet error invalidated a shared transparent socket")
	}
	if connection.closed.Load() != 0 || entry.refs != 2 {
		t.Fatalf("transient error changed shared socket lifetime: closed=%d refs=%d", connection.closed.Load(), entry.refs)
	}
}

func TestTransparentWriterFatalFailureInvalidatesSharedSocket(t *testing.T) {
	destination := M.ParseSocksaddr("192.0.2.1:53")
	connection := new(transparentPacketConnStub)
	connection.err.Store(error(unix.EBADF))
	entry := &transparentWriterEntry{conn: connection, refs: 2}
	shared := &sharedNetwork{
		dataPlane: sharedNetworkDataPlaneSocketAssign,
		transparentWriters: map[netip.AddrPort]*transparentWriterEntry{
			destination.AddrPort(): entry,
		},
	}
	writer := &sharedPacketWriter{
		shared:      shared,
		client:      netip.MustParseAddrPort("192.0.2.2:53000"),
		bound:       destination,
		transparent: entry,
	}
	buffer := buf.New()
	_, _ = buffer.Write([]byte("dns"))
	if err := writer.WritePacket(buffer, destination); !errors.Is(err, unix.EBADF) {
		t.Fatalf("unexpected write error: %v", err)
	}
	if shared.transparentWriters[destination.AddrPort()] != nil || writer.transparent != nil {
		t.Fatal("fatal socket error retained an unusable shared socket")
	}
	if connection.closed.Load() != 1 {
		t.Fatalf("fatal socket was closed %d times", connection.closed.Load())
	}
}

func TestNormalizeSharedNetworkOptions(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		Enabled:          true,
		IncludeInterface: badoption.Listable[string]{"ap0", " ap0 ", "wlan1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.IncludeInterface) != 2 ||
		options.IncludeInterface[0] != "ap0" ||
		options.IncludeInterface[1] != "wlan1" {
		t.Fatalf("unexpected interfaces: %v", options.IncludeInterface)
	}
	if options.DataPlane != sharedNetworkDataPlaneSocketAssign {
		t.Fatalf("expected socket_assign default, got %q", options.DataPlane)
	}
}

func TestV2FallbackIgnoresStaleV3Lifecycle(t *testing.T) {
	backend := &sharedDataplaneStub{}
	shared := &sharedNetwork{
		engineV3: false, // v3 prepare failed; Start selected the v2 backend.
		v3:       &ebpfv3.Lifecycle{},
		backend:  backend,
	}
	client := netip.MustParseAddrPort("192.0.2.2:53000")
	dest := netip.MustParseAddrPort("198.51.100.7:443")
	shared.learnV3Flow(ECommon.ProtocolTCP, client, dest)
	shared.revokeExactFlow(ECommon.ProtocolTCP, client, dest)
	if backend.puts != 1 || backend.deletes != 1 {
		t.Fatalf("v2 fallback did not use backend: puts=%d deletes=%d", backend.puts, backend.deletes)
	}
}

func TestNormalizeSharedNetworkOptionsDisabled(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		IncludeInterface: badoption.Listable[string]{"wlan1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Enabled || len(options.IncludeInterface) != 0 {
		t.Fatalf("disabled shared-network options were retained: %+v", options)
	}
}

func TestNormalizeSharedNetworkOptionsRejectsInvalid(t *testing.T) {
	for _, interfaces := range [][]string{
		nil,
		{""},
		{"lo"},
		{"ap0", "lo"},
	} {
		_, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
			Enabled:          true,
			IncludeInterface: interfaces,
		})
		if err == nil {
			t.Fatalf("expected interfaces to be rejected: %v", interfaces)
		}
	}
}

func TestNormalizeSharedNetworkOptionsFlowVerdictRequiresSocketAssign(t *testing.T) {
	_, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		Enabled:          true,
		IncludeInterface: []string{"eth0"},
		DataPlane:        sharedNetworkDataPlaneToken,
		FlowVerdict:      true,
	})
	if err == nil {
		t.Fatal("expected flow_verdict token-mode rejection")
	}
	got, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		Enabled:          true,
		IncludeInterface: []string{"eth0"},
		DataPlane:        "socket_assign",
		FlowVerdict:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.FlowVerdict {
		t.Fatal("flow_verdict was lost during normalization")
	}
}

func TestValidateSharedNetworkProtocols(t *testing.T) {
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{}, false, dnsModeHijack); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, true, dnsModeHijack); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, false, dnsModeHijack); err == nil {
		t.Fatal("expected shared_network DNS hijacking without UDP to be rejected")
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, false, dnsModeOff); err != nil {
		t.Fatalf("shared_network with DNS disabled should allow TCP-only mode: %v", err)
	}
}

func TestSharedNetworkTCPriorityPrecedesAndroidTethering(t *testing.T) {
	const androidTetheringIPv6Priority = 2
	if sharedNetworkTCPriorityDefault >= androidTetheringIPv6Priority {
		t.Fatalf("shared-network TC priority %d does not precede Android IPv6 tethering priority %d",
			sharedNetworkTCPriorityDefault, androidTetheringIPv6Priority)
	}
	if sharedNetworkResolveTCPriority(option.EBPFSharedNetworkOptions{}) != sharedNetworkTCPriorityDefault {
		t.Fatalf("expected default tc_priority %d", sharedNetworkTCPriorityDefault)
	}
	if sharedNetworkResolveTCPriority(option.EBPFSharedNetworkOptions{TCPriority: 10}) != 10 {
		t.Fatal("expected explicit tc_priority to be honored")
	}
	if sharedNetworkDropUDP443(option.EBPFSharedNetworkOptions{}) {
		t.Fatal("expected drop_udp_443 default false")
	}
	on := true
	if !sharedNetworkDropUDP443(option.EBPFSharedNetworkOptions{DropUDP443: &on}) {
		t.Fatal("expected drop_udp_443=true to enable explicit compatibility drop")
	}
}

func TestValidateSharedNetworkLink(t *testing.T) {
	valid := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         "ap0",
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
	}}
	if err := validateSharedNetworkLink(valid); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tun0"}}); err == nil {
		t.Fatal("expected an interface without an Ethernet address to be rejected")
	}
	if err := validateSharedNetworkLink(nil); err == nil {
		t.Fatal("expected a nil interface to be rejected")
	}
}

func TestIsSharedNetworkLinkNotFound(t *testing.T) {
	for _, err := range []error{unix.ENOENT, unix.ENODEV} {
		if !isSharedNetworkLinkNotFound(err) {
			t.Fatalf("expected %v to be treated as a missing interface", err)
		}
	}
	_, err := netlink.LinkByName("sbe-not-found")
	if err == nil {
		t.Fatal("expected the test interface to be missing")
	}
	if !isSharedNetworkLinkNotFound(err) {
		t.Fatalf("expected netlink error to be treated as a missing interface: %v", err)
	}
	if isSharedNetworkLinkNotFound(unix.EPERM) {
		t.Fatal("expected a permission error to be retained")
	}
}

func TestSharedNetworkCloseListeners(t *testing.T) {
	shared := &sharedNetwork{
		tcp4: listener.New(listener.Options{}),
	}
	if err := shared.closeListeners(); err != nil {
		t.Fatal(err)
	}
	if err := shared.closeListeners(); err != nil {
		t.Fatal(err)
	}
}
