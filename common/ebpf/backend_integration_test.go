//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const integrationTestEnv = "SING_BOX_EBPF_INTEGRATION"

func TestBackendProgramLoadIntegration(t *testing.T) {
	if os.Getenv(integrationTestEnv) != "1" {
		t.Skip("set " + integrationTestEnv + "=1 to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
	for _, hijackDNS := range []bool{true, false} {
		name := "off"
		if hijackDNS {
			name = "hijack"
		}
		t.Run(name, func(t *testing.T) {
			testBackendProgramLoad(t, hijackDNS)
		})
	}
	t.Run("shared-network-only", testBackendSharedNetworkOnly)
	t.Run("socket-assignment", testBackendSocketAssignment)
}

func testBackendSocketAssignment(t *testing.T) {
	parent, err := Prepare("", 65532, true, true,
		netip.MustParsePrefix("127.128.0.0/9"), netip.Prefix{},
		Policy{DisableLocalCapture: true, HijackDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	backend, err := PrepareSharedNetwork(parent, 65531, true, true,
		netip.MustParsePrefix("127.128.0.0/9"), netip.Prefix{},
		true, true, 0x53420001)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	var listenConfig net.ListenConfig
	listenConfig.SetMultipathTCP(false)
	tcpNetListener, err := listenConfig.Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener := tcpNetListener.(*net.TCPListener)
	defer tcpListener.Close()
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	for key, conn := range []syscall.Conn{tcpListener, udpListener} {
		raw, rawErr := conn.SyscallConn()
		if rawErr != nil {
			t.Fatal(rawErr)
		}
		var updateErr error
		if rawErr = raw.Control(func(fd uintptr) {
			updateErr = backend.RegisterListenerSocket(uint32(key), int(fd))
		}); rawErr != nil {
			t.Fatal(rawErr)
		}
		if updateErr != nil {
			var protocol, socketType int
			_ = raw.Control(func(fd uintptr) {
				protocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
				socketType, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
			})
			t.Fatalf("register listener key %d (protocol=%d type=%d): %v", key, protocol, socketType, updateErr)
		}
	}
	replacement, err := listenConfig.Listen(context.Background(), "tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	raw, err := replacement.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var replaceErr error
	if err = raw.Control(func(fd uintptr) {
		replaceErr = backend.RegisterListenerSocket(0, int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if replaceErr != nil {
		t.Fatalf("replace TCP listener: %v", replaceErr)
	}
}

func testBackendSharedNetworkOnly(t *testing.T) {
	backend, err := Prepare(
		os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		65532,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.Prefix{},
		Policy{DisableLocalCapture: true, HijackDNS: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close shared-network-only backend: %v", err)
		}
	})
	if programs := backend.AttachedPrograms(); len(programs) != 0 {
		t.Fatalf("shared-network-only backend built cgroup programs: %v", programs)
	}
	if backend.runtime.cgroup_fd >= 0 {
		t.Fatalf("shared-network-only backend opened cgroup fd: %d", backend.runtime.cgroup_fd)
	}
	if err = backend.Attach(); err != nil {
		t.Fatalf("shared-network-only attach must be a no-op: %v", err)
	}
	sharedBackend, err := PrepareSharedNetwork(
		backend,
		65531,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.Prefix{},
		true,
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sharedBackend.Close()
	if sharedBackend.IngressProgramFD() < 0 || sharedBackend.EgressProgramFD() < 0 {
		t.Fatal("shared-network-only backend did not load both TC programs")
	}
	stats, err := sharedBackend.RuntimeStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats != (SharedNetworkRuntimeStats{}) {
		t.Fatalf("new shared-network backend has non-zero stats: %+v", stats)
	}
}

func testBackendProgramLoad(t *testing.T, hijackDNS bool) {
	backend, err := Prepare(
		os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		65532,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		Policy{HijackDNS: hijackDNS},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})

	programs := backend.AttachedPrograms()
	if !containsProgram(programs, "sb_ebpf_rel (cgroup/sock_release)") {
		t.Fatalf("socket-release program was not built: %v", programs)
	}
	stats, err := backend.RuntimeStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats != (RuntimeStats{}) {
		t.Fatalf("new eBPF backend has non-zero runtime stats: %+v", stats)
	}

	sharedBackend, err := PrepareSharedNetwork(
		backend,
		65531,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		true,
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sharedBackend.Close(); err != nil {
			t.Errorf("close shared-network token backend: %v", err)
		}
	})
	if sharedBackend.IngressProgramFD() < 0 || sharedBackend.EgressProgramFD() < 0 {
		t.Fatal("shared-network token programs were not loaded")
	}
	if hasDNSHijack := sharedBackend.control.Flags&sharedNetworkFlagDNSHijack != 0; hasDNSHijack != hijackDNS {
		t.Fatalf("unexpected shared-network DNS hijack flag: %t", hasDNSHijack)
	}
	if err = sharedBackend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err = sharedBackend.Enable(); err != nil {
		t.Fatal(err)
	}
	if err = sharedBackend.Disable(); err != nil {
		t.Fatal(err)
	}
	if sharedBackend.control.Enabled != 0 {
		t.Fatalf("disable did not clear shared-network control: %+v", sharedBackend.control)
	}

	if os.Getenv("SING_BOX_EBPF_INTEGRATION_ATTACH") == "1" {
		if err = backend.Attach(); err != nil {
			t.Fatal(err)
		}
	}
}

func containsProgram(programs []string, expected string) bool {
	for _, program := range programs {
		if program == expected {
			return true
		}
	}
	return false
}
