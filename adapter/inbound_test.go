package adapter

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSResponseAddressesUnmapsHTTPSIPv4Hints(t *testing.T) {
	t.Parallel()

	ipv4Hint := net.ParseIP("1.1.1.1")
	require.NotNil(t, ipv4Hint)

	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response: true,
			Rcode:    dns.RcodeSuccess,
		},
		Answer: []dns.RR{
			&dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn("example.com"),
						Rrtype: dns.TypeHTTPS,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Priority: 1,
					Target:   ".",
					Value: []dns.SVCBKeyValue{
						&dns.SVCBIPv4Hint{Hint: []net.IP{ipv4Hint}},
					},
				},
			},
		},
	}

	addresses := DNSResponseAddresses(response)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, addresses)
	require.True(t, addresses[0].Is4())
}

func TestConnectionCloseReasonClassification(t *testing.T) {
	t.Parallel()

	if got := ClassifyDialError(context.DeadlineExceeded); got != CloseReasonDialTimeout {
		t.Fatalf("dial timeout reason = %q", got)
	}
	if got := ClassifyStreamError(io.EOF, true); got != CloseReasonClientEOF {
		t.Fatalf("client EOF reason = %q", got)
	}
	if got := ClassifyStreamError(io.EOF, false); got != CloseReasonRemoteEOF {
		t.Fatalf("remote EOF reason = %q", got)
	}

	var extended InboundContextExtended
	extended.SetCloseReason(CloseReasonClientEOF)
	extended.SetCloseReason(CloseReasonRemoteReset)
	extended.SetCloseReason(CloseReasonRemoteEOF)
	if got := extended.CloseReason(); got != CloseReasonRemoteReset {
		t.Fatalf("priority reason = %q", got)
	}
}
