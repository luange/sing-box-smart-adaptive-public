//go:build !with_ebpf || (!linux && !android)

package ebpf

import (
	"github.com/sagernet/sing-box/adapter/outbound"
)

// RegisterOutbound is a no-op when eBPF is not in the build.
func RegisterOutbound(registry *outbound.Registry) {}
