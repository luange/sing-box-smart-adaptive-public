package adapter

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tlsspoof"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
)

type Inbound interface {
	Lifecycle
	Type() string
	Tag() string
}

type TCPInjectableInbound interface {
	Inbound
	ConnectionHandler
}

type UDPInjectableInbound interface {
	Inbound
	PacketConnectionHandler
}

type InboundRegistry interface {
	option.InboundOptionsRegistry
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, inboundType string, options any) (Inbound, error)
}

type InboundManager interface {
	Lifecycle
	Inbounds() []Inbound
	Get(tag string) (Inbound, bool)
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, inboundType string, options any) error
}

type InboundContext struct {
	Inbound          string
	InboundInterface string
	InboundType      string
	IPVersion        uint8
	Network          string
	Source           M.Socksaddr
	Destination      M.Socksaddr
	User             string
	Outbound         string

	// power report

	RouteRule     string
	RouteOutbound string

	// sniffer

	Protocol string
	// Application is an optional high-level application identity supplied by
	// an external classifier. It must not contain a transport protocol such as
	// TLS or QUIC; Smart validates it against the configured feature catalog.
	Application  string
	Domain       string
	SniffHost    string
	Client       string
	SniffContext any
	SnifferNames []string
	SniffError   error

	// cache

	// Deprecated: implement in rule action
	InboundDetour             string
	LastInbound               string
	OriginDestination         M.Socksaddr
	RouteOriginalDestination  M.Socksaddr
	UDPDisableDomainUnmapping bool
	UDPConnect                bool
	UDPTimeout                time.Duration
	TLSFragment               bool
	TLSFragmentFallbackDelay  time.Duration
	TLSRecordFragment         bool
	TLSSpoof                  string
	TLSSpoofMethod            tlsspoof.Method

	NetworkStrategy     *C.NetworkStrategy
	NetworkType         []C.InterfaceType
	FallbackNetworkType []C.InterfaceType
	FallbackDelay       time.Duration

	DestinationAddresses                []netip.Addr
	DNSResponse                         *dns.Msg
	NamedDNSResponses                   map[string]*dns.Msg
	DestinationAddressMatchFromResponse bool
	SourceGeoIPCode                     string
	GeoIPCode                           string
	ProcessInfo                         *ConnectionOwner
	SourceMACAddress                    net.HardwareAddr
	SourceHostname                      string
	QueryType                           uint16
	QueryClientSubnet                   netip.Prefix
	QueryDNSSEC                         bool
	FakeIP                              bool
	PreMatch                            bool
	// MatchInputs accumulates condition classes evaluated during routing.
	MatchInputs RouteMatchInputs
	// VerdictScope describes which dimensions influenced the winning route
	// verdict. eBPF destination-only promotion is permitted only for the
	// DestinationIP scope; zero remains fail-closed for legacy callers.
	VerdictScope RouteVerdictScope
	Extended     *InboundContextExtended

	// rule cache

	IPCIDRMatchSource bool
	IPCIDRAcceptEmpty bool

	SourceAddressMatch           bool
	SourcePortMatch              bool
	DestinationAddressMatch      bool
	DestinationPortMatch         bool
	DeferredIPCIDRMatchGroups    uint8
	IgnoreDestinationIPCIDRMatch bool
}

// InboundContextExtended holds optional chain diagnostics (loadbalance/smart).
type InboundContextExtended struct {
	RealOutboundChain []string
	closeReason       atomic.Pointer[closeReasonState]
}

func (c *InboundContext) InitExtended() {
	if c.Extended == nil {
		c.Extended = new(InboundContextExtended)
	}
}

func (c *InboundContext) AppendRealOutbound(tag string) {
	c.InitExtended()
	c.Extended.RealOutboundChain = append(c.Extended.RealOutboundChain, tag)
}

func (c *InboundContext) GetRealOutboundChain() []string {
	if c.Extended == nil {
		return nil
	}
	return c.Extended.RealOutboundChain
}

func (c *InboundContext) ResetRuleCache() {
	c.IPCIDRMatchSource = false
	c.IPCIDRAcceptEmpty = false
	// MatchInputs is scoped per rule evaluation; only the final matched rule's
	// classes must survive for eBPF verdict learn (not prior failed rules).
	c.MatchInputs = 0
	c.VerdictScope = RouteVerdictScopeUnknown
	c.ResetRuleMatchCache()
}

func (c *InboundContext) ResetRuleMatchCache() {
	c.SourceAddressMatch = false
	c.SourcePortMatch = false
	c.DestinationAddressMatch = false
	c.DestinationPortMatch = false
	c.DeferredIPCIDRMatchGroups = 0
}

func (c *InboundContext) DNSResponseAddressesForMatch() []netip.Addr {
	return DNSResponseAddresses(c.DNSResponse)
}

func DNSResponseAddresses(response *dns.Msg) []netip.Addr {
	if response == nil || response.Rcode != dns.RcodeSuccess {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawRecord := range response.Answer {
		switch record := rawRecord.(type) {
		case *dns.A:
			addr := M.AddrFromIP(record.A)
			if addr.IsValid() {
				addresses = append(addresses, addr)
			}
		case *dns.AAAA:
			addr := M.AddrFromIP(record.AAAA)
			if addr.IsValid() {
				addresses = append(addresses, addr)
			}
		case *dns.HTTPS:
			for _, value := range record.SVCB.Value {
				switch hint := value.(type) {
				case *dns.SVCBIPv4Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip).Unmap()
						if addr.IsValid() {
							addresses = append(addresses, addr)
						}
					}
				case *dns.SVCBIPv6Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip)
						if addr.IsValid() {
							addresses = append(addresses, addr)
						}
					}
				}
			}
		}
	}
	return addresses
}

type inboundContextKey struct{}

type dnsTransportTagKey struct{}

func ContextWithDNSTransportTag(ctx context.Context, transportTag string) context.Context {
	return context.WithValue(ctx, (*dnsTransportTagKey)(nil), transportTag)
}

func DNSTransportTagFromContext(ctx context.Context) (string, bool) {
	transportTag, loaded := ctx.Value((*dnsTransportTagKey)(nil)).(string)
	return transportTag, loaded
}

func WithContext(ctx context.Context, inboundContext *InboundContext) context.Context {
	return context.WithValue(ctx, (*inboundContextKey)(nil), inboundContext)
}

func ContextFrom(ctx context.Context) *InboundContext {
	metadata := ctx.Value((*inboundContextKey)(nil))
	if metadata == nil {
		return nil
	}
	return metadata.(*InboundContext)
}

func ExtendContext(ctx context.Context) (context.Context, *InboundContext) {
	var newMetadata InboundContext
	if metadata := ContextFrom(ctx); metadata != nil {
		newMetadata = *metadata
	}
	return WithContext(ctx, &newMetadata), &newMetadata
}

func OverrideContext(ctx context.Context) context.Context {
	if metadata := ContextFrom(ctx); metadata != nil {
		newMetadata := *metadata
		return WithContext(ctx, &newMetadata)
	}
	return ctx
}

// RouteMatchInputs is a bitset of rule condition classes evaluated for a flow.
type RouteMatchInputs uint32

// RouteVerdictScope is the semantic scope of a route decision. It prevents a
// verdict that depends on source, port, process, domain, or other metadata from
// being generalized into a global destination-IP kernel rule.
type RouteVerdictScope uint8

const (
	RouteVerdictScopeUnknown RouteVerdictScope = iota
	RouteVerdictScopeDestinationIP
)

type RouteVerdictScopeProvider interface {
	VerdictScope() RouteVerdictScope
}

// RouteMatchUnknown must be a real bit.  Zero means that no rule-input class
// was recorded (legacy callers); using zero for Unknown made OR accumulation a
// no-op and accidentally allowed unknown rules into the DIRECT offload path.
const RouteMatchUnknown RouteMatchInputs = 1 << 31

const (
	RouteMatchIP RouteMatchInputs = 1 << iota // ip_cidr / geoip / ip_is_private / ip_version
	RouteMatchPort
	RouteMatchNetwork
	RouteMatchDomain
	RouteMatchProcess
	RouteMatchUser
	RouteMatchSSID
	RouteMatchClashMode
	RouteMatchProtocol
	RouteMatchPackageName
	RouteMatchOther
)

// RouteMatchIPOnly is the whitelist for destination-level DIRECT learn.
const RouteMatchIPOnly = RouteMatchIP | RouteMatchPort | RouteMatchNetwork
