package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestInboundInterfaceItem(t *testing.T) {
	item := NewInboundInterfaceItem([]string{"pa-jp", "pa-sg"})
	for _, test := range []struct {
		name          string
		interfaceName string
		matched       bool
	}{
		{name: "jp", interfaceName: "pa-jp", matched: true},
		{name: "sg", interfaceName: "pa-sg", matched: true},
		{name: "hk", interfaceName: "eth0", matched: false},
		{name: "missing", matched: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := adapter.InboundContext{InboundInterface: test.interfaceName}
			if matched := item.Match(&metadata); matched != test.matched {
				t.Fatalf("match=%v, want %v", matched, test.matched)
			}
		})
	}
	if got := item.MatchClass(); got != adapter.RouteMatchNetwork {
		t.Fatalf("match class=%v, want network", got)
	}
}
