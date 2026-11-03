//go:build !cgo || !(with_ebpf && (linux || android))

package ebpf

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// XDPModeSupport is unavailable without cgo+Linux; callers must treat the
// error as "capability unknown" and keep the TC dataplane live.
func XDPModeSupport(string) (nativeOK, skbOK bool, err error) {
	return false, false, E.New("XDP probe requires with_ebpf, linux/android, and cgo")
}
