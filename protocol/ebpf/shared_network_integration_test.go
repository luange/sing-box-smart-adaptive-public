//go:build with_ebpf && linux && cgo

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/redir"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func TestSharedNetworkDataPathIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_SHARED_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_SHARED_INTEGRATION=1 to run the root TC integration test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-network integration test requires root")
	}
	socketAssign := os.Getenv("SING_BOX_EBPF_SHARED_DATA_PLANE") == sharedNetworkDataPlaneSocketAssign

	const (
		namespace = "sb-ebpf-test"
		hostLink  = "sbe-host"
		peerLink  = "sbe-peer"
		macLink   = "sbe-mac"
	)
	runIP := func(arguments ...string) {
		t.Helper()
		command := exec.Command("ip", arguments...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
	}
	_ = exec.Command("ip", "netns", "del", namespace).Run()
	_ = exec.Command("ip", "link", "del", hostLink).Run()
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
		_ = exec.Command("ip", "link", "del", hostLink).Run()
	})
	runIP("netns", "add", namespace)
	runIP("link", "add", hostLink, "type", "veth", "peer", "name", peerLink)
	runIP("link", "set", peerLink, "netns", namespace)
	runIP("address", "add", "192.0.2.1/24", "dev", hostLink)
	runIP("-6", "address", "add", "2001:db8:1::1/64", "dev", hostLink, "nodad")
	runIP("link", "set", hostLink, "up")
	runIP("netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	runIP("netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/24", "dev", peerLink)
	runIP("netns", "exec", namespace, "ip", "address", "add", "192.0.3.2/24", "dev", peerLink)
	runIP("netns", "exec", namespace, "ip", "-6", "address", "add", "2001:db8:1::2/64", "dev", peerLink, "nodad")
	runIP("netns", "exec", namespace, "ip", "link", "set", peerLink, "up")
	if _, lookupErr := exec.LookPath("ethtool"); lookupErr == nil {
		if output, offloadErr := exec.Command(
			"ip", "netns", "exec", namespace,
			"ethtool", "-K", peerLink, "tx", "off", "tso", "off", "gso", "off", "gro", "off",
		).CombinedOutput(); offloadErr != nil {
			t.Fatalf("disable test peer offloads: %v: %s", offloadErr, output)
		}
	}
	runIP("netns", "exec", namespace, "ip", "route", "add", "default", "via", "192.0.2.1")
	runIP("link", "add", "link", hostLink, "name", macLink, "type", "macvlan", "mode", "bridge")
	runIP("address", "add", "192.0.3.1/24", "dev", macLink)
	runIP("link", "set", macLink, "up")
	if output, sysctlErr := exec.Command("sysctl", "-qw", "net.ipv4.conf."+hostLink+".arp_ignore=1").CombinedOutput(); sysctlErr != nil {
		t.Fatalf("set parent ARP isolation: %v: %s", sysctlErr, output)
	}
	// Force replies to leave through the parent, matching the VM gateway route.
	runIP("route", "replace", "192.0.3.2/32", "via", "192.0.2.2", "dev", hostLink)
	runIP("netns", "exec", namespace, "ip", "route", "replace", "8.8.4.4/32", "via", "192.0.3.1")
	runIP("netns", "exec", namespace, "ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
	// A newly raised veth may not have completed IPv6 neighbour discovery yet.
	// Prime it before the timed transparent-proxy assertions.
	primeIPv6 := exec.Command("ip", "netns", "exec", namespace, "ping", "-6", "-c", "1", "-W", "2", "2001:db8:1::1")
	if output, primeErr := primeIPv6.CombinedOutput(); primeErr != nil {
		t.Fatalf("prime IPv6 neighbour: %v: %s", primeErr, output)
	}
	tcpListener, err := listenTransparentTCP("tcp4", "0.0.0.0:0", socketAssign)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })
	bridgePort := uint16(tcpListener.Addr().(*net.TCPAddr).Port)
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(bridgePort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpListener.Close() })
	if socketAssign {
		setTransparentSocket(t, udpListener, false, true)
	}
	if err = ipv4.NewPacketConn(udpListener).SetControlMessage(ipv4.FlagDst, true); err != nil {
		t.Fatal(err)
	}
	tcp6Listener, err := listenTransparentTCP("tcp6", "[::]:"+strconv.Itoa(int(bridgePort)), socketAssign)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp6Listener.Close() })
	udp6Listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: int(bridgePort)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp6Listener.Close() })
	if socketAssign {
		setTransparentSocket(t, udp6Listener, true, true)
	}
	rawUDP6, err := udp6Listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketControlErr error
	if err = rawUDP6.Control(func(fd uintptr) {
		socketControlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if socketControlErr != nil {
		t.Fatal(socketControlErr)
	}
	if err = ipv6.NewPacketConn(udp6Listener).SetControlMessage(ipv6.FlagDst, true); err != nil {
		t.Fatal(err)
	}

	redirectPrefix := netip.MustParsePrefix("127.128.0.0/9")
	redirectPrefix6 := netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	routeOwner := &Inbound{}
	routeOwner.localRoutes, err = addLocalRoutes([]netip.Prefix{redirectPrefix, redirectPrefix6})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routeOwner.removeLocalRoutes() })
	parent, err := ECommon.Prepare(os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"), bridgePort, true, true, redirectPrefix, redirectPrefix6, ECommon.Policy{HijackDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	routingMark := uint32(0)
	if socketAssign {
		routingMark = sharedNetworkRoutingMarkDefault
	}
	backend, err := ECommon.PrepareSharedNetwork(parent, bridgePort, true, true, redirectPrefix, redirectPrefix6, true, socketAssign, routingMark)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if socketAssign {
		policyRoute, routeErr := installSharedNetworkPolicyRoute(routingMark, sharedNetworkRoutingTableDefault, true, true)
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		t.Cleanup(func() { _ = policyRoute.Close() })
		borrowedRoute, routeErr := installSharedNetworkPolicyRoute(routingMark, sharedNetworkRoutingTableDefault, true, true)
		if routeErr != nil {
			t.Fatalf("reuse exact policy route: %v", routeErr)
		}
		if routeErr = borrowedRoute.Close(); routeErr != nil {
			t.Fatalf("close borrowed policy route: %v", routeErr)
		}
		for key, connection := range []syscall.Conn{tcpListener, udpListener, tcp6Listener, udp6Listener} {
			registerTestListenerSocket(t, backend, uint32(key), connection)
		}
	}
	if err = backend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8:1::1"),
	}); err != nil {
		t.Fatal(err)
	}
	if socketAssign {
		hostDevice, linkErr := netlink.LinkByName(hostLink)
		if linkErr != nil {
			t.Fatal(linkErr)
		}
		if linkErr = ensureClsact(hostDevice); linkErr != nil {
			t.Fatal(linkErr)
		}
		if _, linkErr = attachSharedTCFilter(
			hostDevice,
			netlink.HANDLE_MIN_EGRESS,
			// Any sched_cls program is sufficient to simulate the stale token
			// filter. v2 intentionally has no egress program of its own.
			backend.IngressProgramFD(),
			"sb_share_out",
			sharedEgressFilterHandle,
			sharedNetworkTCPriorityDefault,
		); linkErr != nil {
			t.Fatalf("install stale token egress filter: %v", linkErr)
		}
	}
	manager := &sharedTCManager{
		backend:      backend,
		logger:       discardInterfaceLogger{},
		interfaces:   []string{"sbe-not-found", hostLink, macLink},
		enableIPv4:   true,
		attachEgress: !socketAssign,
		attachments:  make(map[string]*sharedTCAttachment),
	}
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 2 {
		t.Fatalf("unexpected initial TC state: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	if socketAssign {
		hostDevice, _ := netlink.LinkByName(hostLink)
		filters, filterErr := netlink.FilterList(hostDevice, netlink.HANDLE_MIN_EGRESS)
		if filterErr != nil {
			t.Fatal(filterErr)
		}
		for _, current := range filters {
			if bpfFilter, loaded := current.(*netlink.BpfFilter); loaded && bpfFilter.Name == "sb_share_out" {
				t.Fatal("socket-assignment startup retained stale token egress filter")
			}
		}
	}
	t.Cleanup(func() { _ = manager.closeAttachments() })

	tcpResult := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			tcpResult <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		redirect := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, lookupErr := backend.TakeOriginal(ECommon.ProtocolTCP, client, redirect)
		if lookupErr != nil {
			tcpResult <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("8.8.8.8:18080") {
			tcpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		if original.IngressIfIndex == 0 {
			tcpResult <- errors.New("missing TCP ingress interface index")
			return
		}
		if _, secondErr := backend.LookupOriginal(ECommon.ProtocolTCP, client, redirect); secondErr == nil {
			tcpResult <- errors.New("consumed TCP original destination remained readable")
			return
		}
		_, writeErr := conn.Write([]byte("tcp-ok"))
		tcpResult <- writeErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-w", "3", "8.8.8.8", "18080")
	tcpOutput, err := tcpCommand.Output()
	if err != nil {
		stats, _ := backend.RuntimeStats()
		t.Fatalf("TCP client: %v (stats=%+v)", err, stats)
	}
	if string(tcpOutput) != "tcp-ok" {
		t.Fatalf("unexpected TCP response: %q", tcpOutput)
	}
	if err = <-tcpResult; err != nil {
		t.Fatal(err)
	}

	macInterface, err := net.InterfaceByName(macLink)
	if err != nil {
		t.Fatal(err)
	}
	macTCPResult := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			macTCPResult <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		redirect := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, lookupErr := backend.TakeOriginal(ECommon.ProtocolTCP, client, redirect)
		if lookupErr != nil {
			macTCPResult <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("8.8.4.4:18082") {
			macTCPResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		if original.IngressIfIndex != uint32(macInterface.Index) {
			macTCPResult <- fmt.Errorf("macvlan ingress interface was not preserved: got=%d want=%d", original.IngressIfIndex, macInterface.Index)
			return
		}
		_, writeErr := conn.Write([]byte("macvlan-ok"))
		macTCPResult <- writeErr
	}()
	macTCPCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-w", "3", "8.8.4.4", "18082")
	macTCPOutput, err := macTCPCommand.Output()
	if err != nil {
		t.Fatalf("macvlan TCP client: %v", err)
	}
	if err = <-macTCPResult; err != nil {
		t.Fatal(err)
	}
	if string(macTCPOutput) != "macvlan-ok" {
		t.Fatalf("unexpected macvlan TCP response: %q", macTCPOutput)
	}

	// Exercise the reverse/egress rewrite with enough client-to-proxy data to
	// expose checksum/offload regressions that a one-packet request cannot see.
	const bulkBytes = 32 << 20
	if _, lookupErr := exec.LookPath("ethtool"); lookupErr == nil {
		if output, offloadErr := exec.Command(
			"ip", "netns", "exec", namespace,
			"ethtool", "-K", peerLink, "tx", "on", "tso", "on", "gso", "on", "gro", "on",
		).CombinedOutput(); offloadErr != nil {
			t.Fatalf("enable test peer offloads: %v: %s", offloadErr, output)
		}
	}
	retransBefore := readNamespaceTCPStat(t, namespace, "RetransSegs")
	bulkResult := make(chan error, 1)
	go func() {
		_ = tcpListener.SetDeadline(time.Now().Add(20 * time.Second))
		conn, acceptErr := tcpListener.AcceptTCP()
		if acceptErr != nil {
			bulkResult <- acceptErr
			return
		}
		defer conn.Close()
		_, copyErr := io.CopyN(io.Discard, conn, bulkBytes)
		bulkResult <- copyErr
	}()
	bulkContext, bulkCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer bulkCancel()
	bulkCommand := exec.CommandContext(
		bulkContext,
		"ip", "netns", "exec", namespace,
		"sh", "-c", "head -c 33554432 /dev/zero | nc -q 0 8.8.4.4 18083",
	)
	if output, bulkErr := bulkCommand.CombinedOutput(); bulkErr != nil {
		t.Fatalf("macvlan TCP bulk upload: %v: %s", bulkErr, output)
	}
	if err = <-bulkResult; err != nil {
		t.Fatal(err)
	}
	retransAfter := readNamespaceTCPStat(t, namespace, "RetransSegs")
	// A local veth can legitimately retransmit a small burst while its qdisc and
	// offload state settle. This gate targets the thousands-per-flow regression
	// seen in the production-shaped benchmark, not normal low double digits.
	if delta := retransAfter - retransBefore; delta > 64 {
		t.Fatalf("shared-network bulk upload caused %d TCP retransmissions", delta)
	}

	tcp6Result := make(chan error, 1)
	go func() {
		_ = tcp6Listener.SetDeadline(time.Now().Add(5 * time.Second))
		conn, acceptErr := tcp6Listener.AcceptTCP()
		if acceptErr != nil {
			tcp6Result <- acceptErr
			return
		}
		defer conn.Close()
		client := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		redirect := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		original, lookupErr := backend.TakeOriginal(ECommon.ProtocolTCP, client, redirect)
		if lookupErr != nil {
			tcp6Result <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("[2001:4860:4860::8888]:18081") {
			tcp6Result <- &unexpectedDestinationError{original.Destination}
			return
		}
		_, writeErr := conn.Write([]byte("tcp6-ok"))
		tcp6Result <- writeErr
	}()
	tcp6Context, tcp6Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer tcp6Cancel()
	tcp6Command := exec.CommandContext(
		tcp6Context,
		"ip", "netns", "exec", namespace,
		"nc", "-6", "-w", "3", "2001:4860:4860::8888", "18081",
	)
	tcp6Output, err := tcp6Command.CombinedOutput()
	if err != nil {
		t.Fatalf("IPv6 TCP client: %v: %s", err, tcp6Output)
	}
	if string(tcp6Output) != "tcp6-ok" {
		t.Fatalf("unexpected IPv6 TCP response: %q", tcp6Output)
	}
	if err = <-tcp6Result; err != nil {
		t.Fatal(err)
	}

	udpResult := make(chan error, 1)
	go func() {
		_ = udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		oob := make([]byte, 256)
		n, oobN, _, client, readErr := udpListener.ReadMsgUDPAddrPort(payload, oob)
		if readErr != nil {
			udpResult <- readErr
			return
		}
		redirectAddress, parseErr := redirectAddressFromOOB(oob[:oobN])
		redirectPort := bridgePort
		if socketAssign {
			var originalDestination netip.AddrPort
			originalDestination, parseErr = redir.GetOriginalDestinationFromOOB(oob[:oobN])
			redirectAddress = originalDestination.Addr()
			redirectPort = originalDestination.Port()
		}
		if parseErr != nil {
			udpResult <- parseErr
			return
		}
		redirect := netip.AddrPortFrom(redirectAddress, redirectPort)
		original, lookupErr := backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
		if lookupErr != nil {
			udpResult <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("192.0.2.1:53") {
			udpResult <- &unexpectedDestinationError{original.Destination}
			return
		}
		if original.IngressIfIndex == 0 {
			udpResult <- errors.New("missing UDP ingress interface index")
			return
		}
		// UDP uses one shared listener for the complete flow. Multiple queued
		// datagrams must be able to resolve the same original tuple.
		if socketAssign {
			second, secondErr := backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
			if secondErr != nil {
				udpResult <- secondErr
				return
			}
			if second.Destination != original.Destination {
				udpResult <- &unexpectedDestinationError{second.Destination}
				return
			}
		}
		if socketAssign {
			udpResult <- writeTransparentUDPResponse(original.Destination, client, append([]byte("udp-ok:"), payload[:n]...))
			return
		}
		controlMessage := (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
		_, _, writeErr := udpListener.WriteMsgUDPAddrPort(append([]byte("udp-ok:"), payload[:n]...), controlMessage, client)
		udpResult <- writeErr
	}()
	udpCommand := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "nc", "-u", "-w", "3", "192.0.2.1", "53")
	udpCommand.Stdin = strings.NewReader("dns")
	udpOutput, err := udpCommand.Output()
	if err != nil {
		t.Fatalf("UDP client: %v", err)
	}
	if err = <-udpResult; err != nil {
		t.Fatal(err)
	}
	if string(udpOutput) != "udp-ok:dns" {
		t.Fatalf("unexpected UDP response: %q", udpOutput)
	}

	udp6Result := make(chan error, 1)
	go func() {
		_ = udp6Listener.SetReadDeadline(time.Now().Add(5 * time.Second))
		payload := make([]byte, 64)
		oob := make([]byte, 256)
		n, oobN, _, client, readErr := udp6Listener.ReadMsgUDPAddrPort(payload, oob)
		if readErr != nil {
			udp6Result <- readErr
			return
		}
		redirectAddress, parseErr := redirectAddressFromOOB(oob[:oobN])
		redirectPort := bridgePort
		if socketAssign {
			var originalDestination netip.AddrPort
			originalDestination, parseErr = redir.GetOriginalDestinationFromOOB(oob[:oobN])
			redirectAddress = originalDestination.Addr()
			redirectPort = originalDestination.Port()
		}
		if parseErr != nil {
			udp6Result <- parseErr
			return
		}
		redirect := netip.AddrPortFrom(redirectAddress, redirectPort)
		original, lookupErr := backend.LookupOriginal(ECommon.ProtocolUDP, client, redirect)
		if lookupErr != nil {
			udp6Result <- lookupErr
			return
		}
		if original.Destination != netip.MustParseAddrPort("[2001:db8:1::1]:53") {
			udp6Result <- &unexpectedDestinationError{original.Destination}
			return
		}
		if socketAssign {
			udp6Result <- writeTransparentUDPResponse(original.Destination, client, append([]byte("udp6-ok:"), payload[:n]...))
			return
		}
		controlMessage := (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
		_, _, writeErr := udp6Listener.WriteMsgUDPAddrPort(
			append([]byte("udp6-ok:"), payload[:n]...),
			controlMessage,
			client,
		)
		udp6Result <- writeErr
	}()
	udp6Context, udp6Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer udp6Cancel()
	udp6Command := exec.CommandContext(
		udp6Context,
		"ip", "netns", "exec", namespace,
		"nc", "-6", "-u", "-w", "3", "2001:db8:1::1", "53",
	)
	udp6Command.Stdin = strings.NewReader("dns6")
	udp6Output, err := udp6Command.Output()
	if err != nil {
		t.Fatalf("IPv6 UDP client: %v", err)
	}
	if err = <-udp6Result; err != nil {
		t.Fatal(err)
	}
	if string(udp6Output) != "udp6-ok:dns6" {
		t.Fatalf("unexpected IPv6 UDP response: %q", udp6Output)
	}

	dhcpListener, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("192.0.2.1"),
		Port: 67,
	})
	if err != nil {
		t.Fatal(err)
	}
	{
		defer dhcpListener.Close()
		dhcpResult := make(chan error, 1)
		go func() {
			_ = dhcpListener.SetDeadline(time.Now().Add(5 * time.Second))
			payload := make([]byte, 64)
			n, client, readErr := dhcpListener.ReadFromUDPAddrPort(payload)
			if readErr != nil {
				dhcpResult <- readErr
				return
			}
			_, writeErr := dhcpListener.WriteToUDPAddrPort(append([]byte("dhcp-ok:"), payload[:n]...), client)
			dhcpResult <- writeErr
		}()
		dhcpContext, dhcpCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dhcpCancel()
		dhcpCommand := exec.CommandContext(
			dhcpContext,
			"ip", "netns", "exec", namespace,
			"nc", "-u", "-p", "68", "-w", "2", "192.0.2.1", "67",
		)
		dhcpCommand.Stdin = strings.NewReader("discover")
		dhcpOutput, dhcpErr := dhcpCommand.Output()
		if dhcpErr != nil {
			t.Fatalf("DHCP client: %v", dhcpErr)
		}
		if string(dhcpOutput) != "dhcp-ok:discover" {
			t.Fatalf("unexpected DHCP response: %q", dhcpOutput)
		}
		if err = <-dhcpResult; err != nil {
			t.Fatal(err)
		}
	}

	dataPathStats, err := backend.RuntimeStats()
	if err != nil {
		t.Fatal(err)
	}
	if socketAssign {
		if dataPathStats.SocketAssignments == 0 || dataPathStats.EgressRestores != 0 {
			t.Fatalf("socket-assignment counters did not observe ingress-only traffic: %+v", dataPathStats)
		}
	} else if dataPathStats.IngressRedirects == 0 || dataPathStats.EgressRestores == 0 {
		t.Fatalf("token counters did not observe bidirectional traffic: %+v", dataPathStats)
	}
	if dataPathStats.EgressReverseMisses != 0 || dataPathStats.TokenFailures != 0 ||
		dataPathStats.RewriteFailures != 0 || dataPathStats.SocketAssignFailures != 0 ||
		dataPathStats.FlowUpdateFailures != 0 {
		t.Fatalf("shared-network data path reported failures: %+v", dataPathStats)
	}

	runIP("link", "del", hostLink)
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if manager.enabled || len(manager.attachments) != 0 {
		t.Fatalf("TC state was retained after interface removal: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
	runIP("link", "add", hostLink, "type", "dummy")
	runIP("link", "set", hostLink, "up")
	if err = manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !manager.enabled || len(manager.attachments) != 1 {
		t.Fatalf("TC state was not restored after interface recreation: enabled=%v attachments=%d", manager.enabled, len(manager.attachments))
	}
}

func TestSharedNetworkPolicyRouteCollisionIntegration(t *testing.T) {
	if os.Getenv("SING_BOX_EBPF_SHARED_INTEGRATION") != "1" {
		t.Skip("set SING_BOX_EBPF_SHARED_INTEGRATION=1 to run the root policy-route integration test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("shared-network integration test requires root")
	}
	foreign := netlink.NewRule()
	foreign.Family = unix.AF_INET
	foreign.Priority = sharedNetworkRulePriority
	foreign.Table = sharedNetworkRoutingTableDefault + 1
	foreign.Mark = 0x1234
	foreign.MarkSet = true
	foreign.Mask = int(^uint32(0))
	if err := netlink.RuleAdd(foreign); err != nil {
		t.Fatalf("add foreign collision rule: %v", err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(foreign) })
	installed, err := installSharedNetworkPolicyRoute(sharedNetworkRoutingMarkDefault, sharedNetworkRoutingTableDefault, true, false)
	if err == nil {
		_ = installed.Close()
		t.Fatal("incompatible policy-rule collision was accepted")
	}
	exists, verifyErr := sharedNetworkPolicyRuleExists(*foreign)
	if verifyErr != nil || !exists {
		t.Fatalf("foreign collision rule was modified: exists=%v err=%v", exists, verifyErr)
	}
}

type discardInterfaceLogger struct{}

func (discardInterfaceLogger) Info(...any) {}
func (discardInterfaceLogger) Warn(...any) {}

type unexpectedDestinationError struct {
	destination netip.AddrPort
}

func listenTransparentTCP(network string, address string, transparent bool) (*net.TCPListener, error) {
	var listenConfig net.ListenConfig
	listenConfig.SetMultipathTCP(false)
	if transparent {
		listenConfig.Control = func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				controlErr = redir.TProxy(fd, network == "tcp6", false)
			}); err != nil {
				return err
			}
			return controlErr
		}
	}
	listener, err := listenConfig.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return listener.(*net.TCPListener), nil
}

func setTransparentSocket(t *testing.T, connection syscall.Conn, ipv6Socket bool, udp bool) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var controlErr error
	if err = raw.Control(func(fd uintptr) {
		controlErr = redir.TProxy(fd, ipv6Socket, udp)
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
}

func registerTestListenerSocket(t *testing.T, backend *ECommon.SharedNetworkBackend, key uint32, connection syscall.Conn) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var registerErr error
	if err = raw.Control(func(fd uintptr) {
		registerErr = backend.RegisterListenerSocket(key, int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if registerErr != nil {
		t.Fatalf("register listener socket %d: %v", key, registerErr)
	}
}

func writeTransparentUDPResponse(source netip.AddrPort, destination netip.AddrPort, payload []byte) error {
	network := "udp4"
	ipv6Socket := false
	if source.Addr().Is6() {
		network = "udp6"
		ipv6Socket = true
	}
	var listenConfig net.ListenConfig
	listenConfig.Control = func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			controlErr = redir.TProxy(fd, ipv6Socket, true)
		}); err != nil {
			return err
		}
		return controlErr
	}
	packetConnection, err := listenConfig.ListenPacket(context.Background(), network, source.String())
	if err != nil {
		return err
	}
	defer packetConnection.Close()
	_, err = packetConnection.(*net.UDPConn).WriteToUDPAddrPort(payload, destination)
	return err
}

func readNamespaceTCPStat(t *testing.T, namespace string, field string) int64 {
	t.Helper()
	output, err := exec.Command("ip", "netns", "exec", namespace, "cat", "/proc/net/snmp").Output()
	if err != nil {
		t.Fatalf("read namespace TCP stats: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for index := 0; index+1 < len(lines); index++ {
		header := strings.Fields(lines[index])
		values := strings.Fields(lines[index+1])
		if len(header) == 0 || header[0] != "Tcp:" || len(header) != len(values) {
			continue
		}
		for fieldIndex := 1; fieldIndex < len(header); fieldIndex++ {
			if header[fieldIndex] != field {
				continue
			}
			value, parseErr := strconv.ParseInt(values[fieldIndex], 10, 64)
			if parseErr != nil {
				t.Fatalf("parse TCP stat %s: %v", field, parseErr)
			}
			return value
		}
	}
	t.Fatalf("TCP stat %s not found", field)
	return 0
}

func (e *unexpectedDestinationError) Error() string {
	return "unexpected original destination: " + e.destination.String()
}
