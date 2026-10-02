package adapter

import (
	"context"
	"net/netip"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
)

type DNSRouter interface {
	Lifecycle
	Exchange(ctx context.Context, message *dns.Msg, options DNSQueryOptions) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, message *dns.Msg, options DNSQueryOptions, callback func(response *dns.Msg, err error))
	Lookup(ctx context.Context, domain string, options DNSQueryOptions) ([]netip.Addr, error)
	ClearCache()
	LookupReverseMapping(ip netip.Addr) (string, bool)
	ResetNetwork()
}

type DNSClient interface {
	Start()
	Exchange(ctx context.Context, transport DNSTransport, message *dns.Msg, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, transport DNSTransport, message *dns.Msg, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool, callback func(response *dns.Msg, err error))
	Lookup(ctx context.Context, transport DNSTransport, domain string, options DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error)
	ClearCache()
}

type DNSQueryOptions struct {
	Transport              DNSTransport
	Strategy               C.DomainStrategy
	LookupStrategy         C.DomainStrategy
	DisableCache           bool
	DisableOptimisticCache bool
	RewriteTTL             *uint32
	Timeout                time.Duration
	ClientSubnet           netip.Prefix
	RemoveClientSubnet     bool
}

func DNSQueryOptionsFrom(ctx context.Context, options *option.DomainResolveOptions) (DNSQueryOptions, error) {
	if options == nil || options.Server == "" {
		return DNSQueryOptions{}, nil
	}
	transportManager := service.FromContext[DNSTransportManager](ctx)
	transport, loaded := transportManager.Transport(options.Server)
	if !loaded {
		return DNSQueryOptions{}, E.New("domain resolver not found: " + options.Server)
	}
	return DNSQueryOptions{
		Transport:              transport,
		Strategy:               C.DomainStrategy(options.Strategy),
		DisableCache:           options.DisableCache,
		DisableOptimisticCache: options.DisableOptimisticCache,
		RewriteTTL:             options.RewriteTTL,
		Timeout:                time.Duration(options.Timeout),
		ClientSubnet:           options.ClientSubnet.Build(netip.Prefix{}),
	}, nil
}

type RDRCStore interface {
	LoadRDRC(transportName string, qName string, qType uint16) (rejected bool)
	SaveRDRC(transportName string, qName string, qType uint16) error
	SaveRDRCAsync(transportName string, qName string, qType uint16, logger logger.Logger)
}

type DNSCacheStore interface {
	LoadDNSCache(transportName string, qName string, qType uint16) (rawMessage []byte, expireAt time.Time, loaded bool)
	SaveDNSCache(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time) error
	SaveDNSCacheAsync(transportName string, qName string, qType uint16, rawMessage []byte, expireAt time.Time, logger logger.Logger)
	ClearDNSCache() error
}

type DNSTransport interface {
	Lifecycle
	Type() string
	Tag() string
	Dependencies() []string
	// Reset closes the transport's existing connections so later requests use fresh connections.
	// Exchanges that are currently using those connections may fail.
	Reset()
	Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error)
	ExchangeAsync(ctx context.Context, message *dns.Msg, callback func(response *dns.Msg, err error))
}

type DNSTransportWithPreferredDomain interface {
	DNSTransport
	PreferredDomain(domain string) bool
}

type DNSTransportWithEnvironment interface {
	DNSTransport
	Environment() []string
}

type DNSTransportRegistry interface {
	option.DNSTransportOptionsRegistry
	CreateDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, transportType string, options any) (DNSTransport, error)
}

type DNSTransportManager interface {
	Lifecycle
	Transports() []DNSTransport
	Transport(tag string) (DNSTransport, bool)
	Default() DNSTransport
	FakeIP() FakeIPTransport
	Remove(tag string) error
	Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error
}

// DNSAnswerObserver is an optional service hook after a successful userspace DNS
// A/AAAA answer (e.g. eBPF weak dns_prefill → TC promote). Fail-open: never
// blocks the DNS path.
type DNSAnswerObserver interface {
	OnDNSAnswer(domain string, addresses []netip.Addr, fromFakeIP bool)
}

// DNSAnswerObserverHub fans out DNS answers to multiple observers (e.g. several eBPF inbounds).
// The DNS router still resolves a single adapter.DNSAnswerObserver from context — the hub.
type DNSAnswerObserverHub struct {
	access    sync.Mutex
	observers []DNSAnswerObserver
}

// NewDNSAnswerObserverHub returns an empty fan-out hub.
func NewDNSAnswerObserverHub() *DNSAnswerObserverHub {
	return &DNSAnswerObserverHub{}
}

// Add registers an observer. Duplicates are ignored.
func (h *DNSAnswerObserverHub) Add(observer DNSAnswerObserver) {
	if h == nil || observer == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for _, existing := range h.observers {
		if existing == observer {
			return
		}
	}
	h.observers = append(h.observers, observer)
}

// Remove unregisters an observer.
func (h *DNSAnswerObserverHub) Remove(observer DNSAnswerObserver) {
	if h == nil || observer == nil {
		return
	}
	h.access.Lock()
	defer h.access.Unlock()
	for i, existing := range h.observers {
		if existing == observer {
			h.observers = append(h.observers[:i], h.observers[i+1:]...)
			return
		}
	}
}

// OnDNSAnswer implements DNSAnswerObserver.
func (h *DNSAnswerObserverHub) OnDNSAnswer(domain string, addresses []netip.Addr, fromFakeIP bool) {
	if h == nil {
		return
	}
	h.access.Lock()
	snapshot := append([]DNSAnswerObserver(nil), h.observers...)
	h.access.Unlock()
	for _, observer := range snapshot {
		observer.OnDNSAnswer(domain, addresses, fromFakeIP)
	}
}
