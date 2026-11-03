//go:build linux

package group

import (
	"net"

	"golang.org/x/sys/unix"
)

// smartTCPRetransmitRatio reads TCP_INFO once, at connection close. It is
// intentionally not a polling loop: Smart receives a cheap loss signal without
// adding a syscall to every packet or goroutine to every connection.
func smartTCPRetransmitRatio(conn any) (float64, bool) {
	return smartTCPRetransmitRatioDepth(conn, 0)
}

func smartTCPRetransmitRatioDepth(conn any, depth int) (float64, bool) {
	if conn == nil || depth > 4 {
		return 0, false
	}
	var tcp *net.TCPConn
	switch value := conn.(type) {
	case *net.TCPConn:
		tcp = value
	case interface{ Upstream() any }:
		return smartTCPRetransmitRatioDepth(value.Upstream(), depth+1)
	case interface{ Unwrap() net.Conn }:
		return smartTCPRetransmitRatioDepth(value.Unwrap(), depth+1)
	default:
		return 0, false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var controlErr error
	if err = raw.Control(func(fd uintptr) {
		info, controlErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || controlErr != nil || info == nil {
		return 0, false
	}
	// Bytes_sent/Bytes_retrans are available on modern Linux. Fall back to
	// segment counters on older kernels where the byte counters remain zero.
	denominator := info.Bytes_sent
	numerator := info.Bytes_retrans
	if denominator == 0 {
		denominator = uint64(info.Segs_out)
		numerator = uint64(info.Total_retrans)
	}
	if denominator == 0 {
		return 0, false
	}
	ratio := float64(numerator) / float64(denominator)
	if ratio < 0 || ratio != ratio {
		return 0, false
	}
	if ratio > 1 {
		ratio = 1
	}
	return ratio, true
}
