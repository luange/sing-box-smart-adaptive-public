package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*InboundInterfaceItem)(nil)

// InboundInterfaceItem matches the actual interface on which transparent
// traffic entered the process.  Unlike source_ip_cidr, this remains stable
// when a PBR gateway is selected without SNAT.
type InboundInterfaceItem struct {
	interfaces   []string
	interfaceMap map[string]bool
}

func NewInboundInterfaceItem(interfaces []string) *InboundInterfaceItem {
	item := &InboundInterfaceItem{
		interfaces:   interfaces,
		interfaceMap: make(map[string]bool, len(interfaces)),
	}
	for _, interfaceName := range interfaces {
		item.interfaceMap[interfaceName] = true
	}
	return item
}

func (r *InboundInterfaceItem) Match(metadata *adapter.InboundContext) bool {
	return r.interfaceMap[metadata.InboundInterface]
}

func (r *InboundInterfaceItem) String() string {
	if len(r.interfaces) == 1 {
		return F.ToString("inbound_interface=", r.interfaces[0])
	}
	return F.ToString("inbound_interface=[", strings.Join(r.interfaces, " "), "]")
}
