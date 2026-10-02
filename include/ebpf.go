//go:build with_ebpf && (linux || android)

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/ebpf"
)

func registerEBPFInbound(registry *inbound.Registry) {
	ebpf.RegisterInbound(registry)
}

func registerEBPFOutbound(registry *outbound.Registry) {
	ebpf.RegisterOutbound(registry)
}
