package transport

import (
	"testing"

	mDNS "github.com/miekg/dns"
)

func TestUDPTransportEDNSReadSizeIsBoundedAndMonotonic(t *testing.T) {
	transport := &UDPTransport{}
	transport.udpSize.Store(defaultUDPReadSize)
	transport.multiplexer = newQueryMultiplexer(queryMultiplexerOptions{})

	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	message.SetEdns0(65535, false)
	transport.updateUDPSize(message)
	if got := transport.udpSize.Load(); got != maxUDPReadSize {
		t.Fatalf("EDNS size was not clamped: got %d", got)
	}

	smaller := new(mDNS.Msg)
	smaller.SetQuestion("example.com.", mDNS.TypeA)
	smaller.SetEdns0(1232, false)
	transport.updateUDPSize(smaller)
	if got := transport.udpSize.Load(); got != maxUDPReadSize {
		t.Fatalf("EDNS update regressed read size: got %d", got)
	}
}
