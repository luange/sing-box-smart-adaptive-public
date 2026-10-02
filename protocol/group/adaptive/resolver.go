package adaptive

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group/trafficfamily"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type PolicyMode string

const (
	ModeStrictAffinity PolicyMode = "strict-affinity"
	ModeAdaptive       PolicyMode = "adaptive"
	ModeLatency        PolicyMode = "latency"
	ModeBulk           PolicyMode = "bulk"
	ModeManual         PolicyMode = "manual"
)

var observableHealthPaths = [...]string{
	"tcp/ipv4", "tcp/ipv6",
	"udp_dns/ipv4", "udp_dns/ipv6",
	"udp_data/ipv4", "udp_data/ipv6",
}

type ServiceContext struct {
	ID              string
	AffinityID      string
	Session         SessionKey
	Mode            PolicyMode
	Host            string
	Transport       string
	HealthTransport string
	// ExpectUDPResponse marks transactional UDP protocols (QUIC/DNS/STUN).
	// A flow that transmitted but received nothing before the client closed is
	// useful medium-confidence path evidence; one-way UDP must not be penalized.
	ExpectUDPResponse bool
}

type ServiceResolver struct {
	hasher      *IdentityHasher
	defaultMode PolicyMode
	access      sync.RWMutex
	overrides   map[string]ServiceOverride
	families    *trafficfamily.Resolver
}

type ServiceOverride struct {
	ServiceID string
	Mode      PolicyMode
	ExpiresAt time.Time
}

func NewServiceResolver(hasher *IdentityHasher, defaultMode PolicyMode) *ServiceResolver {
	if defaultMode == "" {
		defaultMode = ModeAdaptive
	}
	return &ServiceResolver{hasher: hasher, defaultMode: defaultMode, overrides: make(map[string]ServiceOverride), families: trafficfamily.NewResolver()}
}

func (r *ServiceResolver) Resolve(metadata *adapter.InboundContext, destination M.Socksaddr, transport string) ServiceContext {
	host := destinationHost(metadata, destination)
	now := time.Now()
	clientScope := "default"
	if metadata != nil {
		var processID uint32
		if metadata.ProcessInfo != nil {
			processID = metadata.ProcessInfo.ProcessID
		}
		clientScope = strings.Join([]string{
			metadata.Inbound,
			metadata.Source.Addr.String(),
			metadata.User,
			strconv.FormatUint(uint64(processID), 10),
		}, "\x00")
	}
	match := r.families.Resolve(host, clientScope, now)
	serviceID := match.ID
	mode := r.defaultMode
	if match.StrictAffinity {
		mode = ModeStrictAffinity
	}
	if override, loaded := r.override(serviceID, now); loaded {
		mode = override.Mode
	}
	return ServiceContext{
		ID:                serviceID,
		AffinityID:        serviceAffinityFamily(serviceID),
		Session:           r.hasher.Session(clientScope, serviceAffinityFamily(serviceID)),
		Mode:              mode,
		Host:              host,
		Transport:         transport,
		HealthTransport:   resolveHealthTransport(metadata, destination, transport),
		ExpectUDPResponse: expectsUDPResponse(metadata, destination, transport),
	}
}

func expectsUDPResponse(metadata *adapter.InboundContext, destination M.Socksaddr, transport string) bool {
	if transport != N.NetworkUDP {
		return false
	}
	if destination.Port == 53 || destination.Port == 443 || destination.Port == 3478 {
		return true
	}
	if metadata == nil {
		return false
	}
	switch strings.ToLower(metadata.Protocol) {
	case "dns", "quic", "stun":
		return true
	default:
		return false
	}
}

const (
	healthTransportTCP     = "tcp"
	healthTransportUDPDNS  = "udp_dns"
	healthTransportUDPData = "udp_data"
	healthFamilyAny        = "any"
	healthFamilyIPv4       = "ipv4"
	healthFamilyIPv6       = "ipv6"
)

func resolveHealthTransport(metadata *adapter.InboundContext, destination M.Socksaddr, transport string) string {
	class := transport
	if transport == "udp" {
		class = healthTransportUDPData
		if destination.Port == 53 || metadata != nil && strings.EqualFold(metadata.Protocol, "dns") {
			class = healthTransportUDPDNS
		}
	} else if transport == "tcp" {
		class = healthTransportTCP
	}
	address := destination.Addr
	if !address.IsValid() && metadata != nil {
		address = metadata.Destination.Addr
	}
	family := healthFamilyAny
	if address.IsValid() {
		if address.Is4() || address.Is4In6() {
			family = healthFamilyIPv4
		} else if address.Is6() {
			family = healthFamilyIPv6
		}
	} else if metadata != nil && len(metadata.DestinationAddresses) > 0 {
		resolvedFamily := ""
		for _, resolved := range metadata.DestinationAddresses {
			current := healthFamilyIPv6
			if resolved.Is4() || resolved.Is4In6() {
				current = healthFamilyIPv4
			}
			if resolvedFamily == "" {
				resolvedFamily = current
			} else if resolvedFamily != current {
				resolvedFamily = healthFamilyAny
				break
			}
		}
		if resolvedFamily != "" {
			family = resolvedFamily
		}
	}
	return class + "/" + family
}

func serviceHealthTransport(service ServiceContext) string {
	if service.HealthTransport != "" {
		return service.HealthTransport
	}
	return service.Transport
}

// refineHealthTransportFamily upgrades a collapsed */any (or bare class) path to
// a concrete family when the actual peer address family is known. Already-concrete
// paths are left unchanged. This is how dual-stack dials stop poisoning both
// families after only one address family was tried.
func refineHealthTransportFamily(path, family string) string {
	if path == "" || family == "" || family == healthFamilyAny {
		return path
	}
	if family != healthFamilyIPv4 && family != healthFamilyIPv6 {
		return path
	}
	class, currentFamily := splitHealthTransport(path)
	if class == "" {
		return path
	}
	if currentFamily != "" && currentFamily != healthFamilyAny {
		return path
	}
	return class + "/" + family
}

func splitHealthTransport(path string) (class, family string) {
	// N.NetworkTCP == "tcp", N.NetworkUDP == "udp"
	switch path {
	case N.NetworkTCP:
		return healthTransportTCP, ""
	case N.NetworkUDP:
		return healthTransportUDPData, ""
	case healthTransportUDPDNS, healthTransportUDPData:
		return path, ""
	}
	if i := strings.IndexByte(path, '/'); i > 0 {
		return path[:i], path[i+1:]
	}
	return path, ""
}

func familyFromNetAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		return familyFromIP(typed.IP)
	case *net.UDPAddr:
		return familyFromIP(typed.IP)
	case *net.IPAddr:
		return familyFromIP(typed.IP)
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		if ip := net.ParseIP(host); ip != nil {
			return familyFromIP(ip)
		}
	}
	return ""
}

func familyFromIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	// Proxy tunnel local addresses (10.x, 127.x, link-local) are not the dial
	// destination family. Using them pinned nearly every success to tcp/ipv4 and
	// left real destination ledgers unknown in production.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return ""
	}
	if ip.To4() != nil {
		return healthFamilyIPv4
	}
	return healthFamilyIPv6
}

func familyFromSocksaddr(destination M.Socksaddr) string {
	if !destination.IsValid() {
		return ""
	}
	addr := destination.Addr
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() || addr.Is4In6() {
		return healthFamilyIPv4
	}
	if addr.Is6() {
		return healthFamilyIPv6
	}
	return ""
}

// observedHealthTransport is the ledger key for a dial/business observation.
// Prefer destination IP (incl. FakeIP), then a *public* remote peer address.
// Never trust private/loopback RemoteAddr from proxy tunnels. Falls back to the
// service path (may remain */any) which still scores via aggregate ledgers.
func observedHealthTransport(service ServiceContext, destination M.Socksaddr, remote net.Addr) string {
	base := normalizeHealthTransportPath(serviceHealthTransport(service))
	if family := familyFromSocksaddr(destination); family != "" {
		return refineHealthTransportFamily(base, family)
	}
	if family := familyFromNetAddr(remote); family != "" {
		return refineHealthTransportFamily(base, family)
	}
	return base
}

// normalizeHealthTransportPath maps bare class names onto the qualified ledger
// vocabulary used by observation validation and dual-stack aggregates.
func normalizeHealthTransportPath(path string) string {
	if path == "" {
		return ""
	}
	// N.NetworkTCP == "tcp"; N.NetworkUDP == "udp"
	switch path {
	case N.NetworkTCP:
		return healthTransportTCP + "/" + healthFamilyAny
	case N.NetworkUDP:
		return healthTransportUDPData + "/" + healthFamilyAny
	case healthTransportUDPDNS:
		return healthTransportUDPDNS + "/" + healthFamilyAny
	case healthTransportUDPData:
		return healthTransportUDPData + "/" + healthFamilyAny
	default:
		return path
	}
}

// serviceAffinityFamily keys lease + sticky memory.
//
// Each identity-sensitive product keeps its own spine. The old shared
// "browser_identity" bag coupled ChatGPT/Claude/Gemini/accounts so one product
// breaker could bounce another product's egress — that was a real thrash path,
// not a useful cookie-world optimization.
func serviceAffinityFamily(serviceID string) string {
	if serviceID == "" {
		return "unknown"
	}
	return serviceID
}

func (r *ServiceResolver) SetOverride(serviceID string, mode PolicyMode, ttl time.Duration, now time.Time) error {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" || len(serviceID) > 128 || strings.ContainsAny(serviceID, "?\n\r") || ttl < time.Minute || ttl > 24*time.Hour {
		return errors.New("adaptive service override is invalid")
	}
	if mode != ModeStrictAffinity && mode != ModeAdaptive && mode != ModeLatency && mode != ModeBulk {
		return errors.New("adaptive service override mode is invalid")
	}
	r.access.Lock()
	for key, current := range r.overrides {
		if !current.ExpiresAt.After(now) {
			delete(r.overrides, key)
		}
	}
	if len(r.overrides) >= 1024 {
		r.access.Unlock()
		return errors.New("adaptive service override capacity reached")
	}
	r.overrides[serviceID] = ServiceOverride{ServiceID: serviceID, Mode: mode, ExpiresAt: now.Add(ttl)}
	r.access.Unlock()
	return nil
}

func (r *ServiceResolver) ClearOverride(serviceID string) bool {
	r.access.Lock()
	_, loaded := r.overrides[serviceID]
	delete(r.overrides, serviceID)
	r.access.Unlock()
	return loaded
}

func (r *ServiceResolver) Overrides(now time.Time) []ServiceOverride {
	r.access.RLock()
	result := make([]ServiceOverride, 0, len(r.overrides))
	for _, override := range r.overrides {
		if override.ExpiresAt.After(now) {
			result = append(result, override)
		}
	}
	r.access.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].ServiceID < result[j].ServiceID })
	return result
}

func (r *ServiceResolver) override(serviceID string, now time.Time) (ServiceOverride, bool) {
	r.access.RLock()
	override, loaded := r.overrides[serviceID]
	r.access.RUnlock()
	return override, loaded && override.ExpiresAt.After(now)
}

func destinationHost(metadata *adapter.InboundContext, destination M.Socksaddr) string {
	if metadata != nil {
		// A FakeIP reverse mapping represents the original requested domain and
		// remains authoritative over a CDN/challenge SNI. For native QUIC, the
		// sniffed SNI identifies the actual encrypted flow and wins over a stale
		// resolver-domain cache.
		if metadata.FakeIP && metadata.Domain != "" {
			return metadata.Domain
		}
		if strings.EqualFold(metadata.Protocol, "quic") && metadata.SniffHost != "" {
			return metadata.SniffHost
		}
		if metadata.Domain != "" {
			return metadata.Domain
		}
		if metadata.SniffHost != "" {
			return metadata.SniffHost
		}
		if metadata.Destination.IsFqdn() {
			return metadata.Destination.Fqdn
		}
	}
	if destination.IsFqdn() {
		return destination.Fqdn
	}
	if destination.Addr.IsValid() {
		return destination.Addr.String()
	}
	return ""
}
