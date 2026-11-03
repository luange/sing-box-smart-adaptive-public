package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestInboundInterfaceItem(t *testing.T) {
	item := NewInboundInterfaceItem([]string{"pa-us", "pa-hk"})
	if !item.Match(&adapter.InboundContext{InboundInterface: "pa-us"}) {
		t.Fatal("expected matching interface")
	}
	if item.Match(&adapter.InboundContext{InboundInterface: "pa-jp"}) || item.Match(nil) {
		t.Fatal("unexpected matching interface")
	}
}
