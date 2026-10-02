package rule

import (
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

var _ RuleItem = (*SourceMACAddressItem)(nil)

type SourceMACAddressItem struct {
	addresses  []string
	addressMap map[string]bool
	parsed     []net.HardwareAddr
}

func NewSourceMACAddressItem(addressList []string) *SourceMACAddressItem {
	rule := &SourceMACAddressItem{
		addresses:  addressList,
		addressMap: make(map[string]bool),
	}
	for _, address := range addressList {
		parsed, err := net.ParseMAC(address)
		if err == nil {
			rule.addressMap[parsed.String()] = true
			rule.parsed = append(rule.parsed, parsed)
		} else {
			rule.addressMap[address] = true
		}
	}
	return rule
}

// MACAddresses returns the successfully parsed hardware addresses for
// dataplane offload (v3 source-MAC policy). Unparseable entries are skipped.
func (r *SourceMACAddressItem) MACAddresses() []net.HardwareAddr {
	return r.parsed
}

func (r *SourceMACAddressItem) Match(metadata *adapter.InboundContext) bool {
	if metadata.SourceMACAddress == nil {
		return false
	}
	return r.addressMap[metadata.SourceMACAddress.String()]
}

func (r *SourceMACAddressItem) String() string {
	var description string
	if len(r.addresses) == 1 {
		description = "source_mac_address=" + r.addresses[0]
	} else {
		description = "source_mac_address=[" + strings.Join(r.addresses, " ") + "]"
	}
	return description
}
