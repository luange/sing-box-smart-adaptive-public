//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native -I${SRCDIR}/v3/kern
#include "singbox_ebpf.h"
#include <errno.h>

static int singbox_ebpf_xdp_probe_hardware(uint32_t ifindex, int *native_ok, int *skb_ok, int *saved_errno) {
	int result = sb_ebpf_xdp_probe_hardware(ifindex, native_ok, skb_ok);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	"net"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

// XDPModeSupport reports which XDP attach modes the kernel and driver of the
// named interface actually accept. The probe attaches a pass-everything
// program for microseconds and detaches it; no packets are redirected and no
// sing-box dataplane is installed. Use it to gate the experimental xdp
// options on hardware that may not support native XDP (drivers, virtual NICs).
func XDPModeSupport(interfaceName string) (nativeOK, skbOK bool, err error) {
	iface, ifaceErr := net.InterfaceByName(interfaceName)
	if ifaceErr != nil {
		return false, false, E.Cause(ifaceErr, "resolve interface")
	}
	var nativeInt, skbInt, savedErrno C.int
	result := C.singbox_ebpf_xdp_probe_hardware(C.uint32_t(iface.Index), &nativeInt, &skbInt, &savedErrno)
	if result != 0 {
		return false, false, E.Cause(syscall.Errno(savedErrno), "probe XDP support")
	}
	return nativeInt != 0, skbInt != 0, nil
}
