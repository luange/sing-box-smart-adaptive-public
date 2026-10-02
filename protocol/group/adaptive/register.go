package adaptive

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func Register(registry *outbound.Registry) {
	outbound.Register[option.AdaptivePoolOutboundOptions](registry, C.TypeAdaptivePool, New)
}
