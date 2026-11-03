package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*InboundInterfaceItem)(nil)

// InboundInterfaceItem matches the PBR interface on which transparent traffic
// arrived. A shared transparent inbound can represent multiple such paths.
type InboundInterfaceItem struct {
	interfaces   []string
	interfaceMap map[string]bool
}

func NewInboundInterfaceItem(interfaces []string) *InboundInterfaceItem {
	item := &InboundInterfaceItem{
		interfaces:   append([]string(nil), interfaces...),
		interfaceMap: make(map[string]bool, len(interfaces)),
	}
	for _, name := range interfaces {
		item.interfaceMap[name] = true
	}
	return item
}

func (r *InboundInterfaceItem) Match(metadata *adapter.InboundContext) bool {
	return metadata != nil && r.interfaceMap[metadata.InboundInterface]
}

func (r *InboundInterfaceItem) String() string {
	if len(r.interfaces) == 1 {
		return F.ToString("inbound_interface=", r.interfaces[0])
	}
	return F.ToString("inbound_interface=[", strings.Join(r.interfaces, " "), "]")
}
