package urltest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

// ProbeObservation describes the stage reached by a real URL test. It is
// advisory metadata: ordinary URLTest callers retain their delay/error API.
// A Smart caller can distinguish an upstream proxy rejection from an HTTP
// response sent by the probe site without parsing an error string.
type ProbeObservation struct {
	Stage      string
	HTTPStatus int
}

type probeObserverKey struct{}

func WithProbeObserver(ctx context.Context, observer func(ProbeObservation)) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, probeObserverKey{}, observer)
}

func probeFailureStage(err error, stage string) string {
	if err == nil {
		return stage
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "dns"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unexpected http response status") || strings.Contains(message, "authentication failed") {
		return "proxy_handshake"
	}
	if strings.Contains(message, "tls") || strings.Contains(message, "x509:") || strings.Contains(message, "certificate") {
		return "tls"
	}
	return stage
}

type HistoryStorage struct {
	access       sync.RWMutex
	keyedHistory map[HistoryKey]*adapter.URLTestHistory
	updateHooks  []*observable.Subscriber[struct{}]
	nextPrune    time.Time
	expired      uint64
	evicted      uint64
}

// HistoryStorageStatus exposes bounded URL-test retention for diagnostics.
// It contains no endpoint identity, credential, or probe URL.
type HistoryStorageStatus struct {
	Entries           int    `json:"entries"`
	MaxEntries        int    `json:"max_entries"`
	Retention         string `json:"retention"`
	ExpiredEntries    uint64 `json:"expired_entries"`
	CapacityEvictions uint64 `json:"capacity_evictions"`
}

// URL-test identity must survive an ordinary provider refresh, but it must not
// become a process-lifetime catalog of every endpoint and probe URL that has
// ever existed. Providers can rotate thousands of endpoints over time.
const (
	defaultHistoryRetention  = 24 * time.Hour
	defaultHistoryMaxEntries = 4096
	historyPruneInterval     = 5 * time.Minute
)

// HistoryKey identifies a URL-test observation without using a provider's
// display alias as the identity. PathIdentity is credential-free and stable
// across provider refreshes, while DialIdentity keeps full authenticated
// URLTest results separate when two credentials share one network path.
// ProbeTarget is a digest of the test URL so query strings or tokens are never
// retained in the in-memory key; Network keeps TCP4/TCP6 (and future families)
// from sharing measurements accidentally.
type HistoryKey struct {
	PathIdentity string
	DialIdentity string
	ProbeTarget  string
	Network      string
}

// KeyForOutbound creates an identity-aware history key. Ordinary static
// outbounds use their tag as a stable fallback; provider members expose the
// stronger OutboundWithEndpointIdentity contract.
func KeyForOutbound(outbound adapter.Outbound, link, network string) HistoryKey {
	pathIdentity := ""
	dialIdentity := ""
	if outbound != nil {
		if identified, ok := outbound.(adapter.OutboundWithEndpointIdentity); ok {
			pathIdentity = identified.EndpointIdentity()
		}
		if identified, ok := outbound.(adapter.OutboundWithDialIdentity); ok {
			dialIdentity = identified.DialIdentity()
		}
		if pathIdentity == "" {
			pathIdentity = outbound.Tag()
		}
	}
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	targetDigest := sha256.Sum256([]byte(link))
	if network == "" {
		network = N.NetworkTCP
	}
	return HistoryKey{
		PathIdentity: pathIdentity,
		DialIdentity: dialIdentity,
		ProbeTarget:  hex.EncodeToString(targetDigest[:]),
		Network:      network,
	}
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		keyedHistory: make(map[HistoryKey]*adapter.URLTestHistory),
	}
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.access.RLock()
	defer s.access.RUnlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) LoadURLTestHistoryKey(key HistoryKey) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if history := s.keyedHistory[key]; history != nil {
		return history
	}
	return nil
}

func (s *HistoryStorage) StoreURLTestHistoryKey(key HistoryKey, history *adapter.URLTestHistory) {
	if s == nil {
		return
	}
	s.access.Lock()
	if history == nil {
		delete(s.keyedHistory, key)
	} else {
		s.keyedHistory[key] = history
		s.pruneLocked(time.Now())
	}
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) pruneLocked(now time.Time) {
	if !now.Before(s.nextPrune) {
		for key, history := range s.keyedHistory {
			if history == nil || history.Time.IsZero() || now.Sub(history.Time) > defaultHistoryRetention {
				delete(s.keyedHistory, key)
				s.expired++
			}
		}
		s.nextPrune = now.Add(historyPruneInterval)
	}
	for len(s.keyedHistory) > defaultHistoryMaxEntries {
		var oldestKey HistoryKey
		var oldestTime time.Time
		for key, history := range s.keyedHistory {
			if oldestTime.IsZero() || history == nil || history.Time.Before(oldestTime) {
				oldestKey, oldestTime = key, time.Time{}
				if history != nil {
					oldestTime = history.Time
				}
			}
		}
		delete(s.keyedHistory, oldestKey)
		s.evicted++
	}
}

func (s *HistoryStorage) DeleteURLTestHistoryKey(key HistoryKey) {
	if s == nil {
		return
	}
	s.access.Lock()
	delete(s.keyedHistory, key)
	s.notifyUpdated()
	s.access.Unlock()
}

func (s *HistoryStorage) Status() HistoryStorageStatus {
	if s == nil {
		return HistoryStorageStatus{MaxEntries: defaultHistoryMaxEntries, Retention: defaultHistoryRetention.String()}
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return HistoryStorageStatus{
		Entries: len(s.keyedHistory), MaxEntries: defaultHistoryMaxEntries, Retention: defaultHistoryRetention.String(),
		ExpiredEntries: s.expired, CapacityEvictions: s.evicted,
	}
}

// LoadLatestURLTestHistoryForOutbound is used by dashboards and group status
// APIs that do not know which probe URL produced an observation. It only scans
// the matching path identity, dial identity, and network, so a duplicate
// provider alias or credential variant cannot leak another node's history into
// the display.
func (s *HistoryStorage) LoadLatestURLTestHistoryForOutbound(outbound adapter.Outbound, network string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	return s.LoadLatestURLTestHistoryKey(KeyForOutbound(outbound, "", network))
}

func (s *HistoryStorage) LoadLatestURLTestHistoryKey(key HistoryKey) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	var latest *adapter.URLTestHistory
	for candidateKey, history := range s.keyedHistory {
		if candidateKey.PathIdentity != key.PathIdentity || candidateKey.DialIdentity != key.DialIdentity || candidateKey.Network != key.Network {
			continue
		}
		if latest == nil || history.Time.After(latest.Time) {
			latest = history
		}
	}
	if latest != nil {
		return latest
	}
	return nil
}

func (s *HistoryStorage) notifyUpdated() {
	for _, updateHook := range s.updateHooks {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (uint16, error) {
	return URLTestWithNetwork(ctx, link, detour, N.NetworkTCP)
}

// URLTestWithNetwork keeps the upstream multiplex warm-up contract while
// measuring the requested TCP address family for Smart health evidence.
func URLTestWithNetwork(ctx context.Context, link string, detour N.Dialer, network string) (uint16, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		network = N.NetworkTCP
	}
	multiplexOutbound, isMultiplexOutbound := common.Cast[adapter.OutboundWithMultiplex](detour)
	if isMultiplexOutbound && multiplexOutbound.MultiplexEnabled() {
		warmContext := adapter.ContextWithKeepSession(ctx)
		warmContext = mux.ContextWithKeepSession(warmContext)
		warmContext = anytls.ContextWithKeepSession(warmContext)
		warmContext = contextWithQUICKeepSession(warmContext)
		warmContext = snell.ContextWithKeepSession(warmContext)
		if _, err := urlTest(warmContext, link, detour, network); err != nil {
			return 0, err
		}
	}
	return urlTest(ctx, link, detour, network)
}

func urlTest(ctx context.Context, link string, detour N.Dialer, network string) (t uint16, err error) {
	stage := "request"
	responseStatus := 0
	defer func() {
		if observer, ok := ctx.Value(probeObserverKey{}).(func(ProbeObservation)); ok {
			observer(ProbeObservation{Stage: probeFailureStage(err, stage), HTTPStatus: responseStatus})
		}
	}()
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	stage = "proxy_dial"
	start := time.Now()
	instance, err := detour.DialContext(ctx, network, M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
		stage = "proxy_handshake"
	} else {
		stage = "target_request"
	}
	stage = "request"
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	if N.NeedHandshakeForWrite(instance) {
		stage = "proxy_handshake_or_target"
	} else {
		stage = "target_request"
	}
	// Prefer the caller's deadline (smart probe is typically 5s). Falling back
	// to TCPTimeout (15s) made serial smart-group Close exceed FatalStopTimeout.
	clientTimeout := C.TCPTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < clientTimeout {
			clientTimeout = remaining
		}
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return instance, nil
			},
			TLSClientConfig: &tls.Config{
				Time:       ntp.TimeFuncFromContext(ctx),
				RootCAs:    adapter.RootPoolFromContext(ctx),
				ServerName: probeTLSServerName(hostname),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: clientTimeout,
	}
	defer client.CloseIdleConnections()
	newRequest := func() *http.Request {
		request := req.WithContext(ctx)
		if serverName := probeTLSServerName(hostname); serverName != hostname {
			// Keep the probe endpoint literal so bootstrap never performs a DNS
			// lookup through the Smart group, while still routing Cloudflare's
			// virtual host to a valid certificate and response handler.
			request.Host = serverName
		}
		return request
	}
	resp, err := client.Do(newRequest())
	if err != nil {
		return
	}
	stage = "target_response"
	responseStatus = resp.StatusCode
	resp.Body.Close()
	firstDelay := uint16(time.Since(start) / time.Millisecond)
	if resp.Close {
		// The endpoint explicitly disabled keep-alive, so the first request is
		// the only meaningful measurement (the same fallback used by Surge).
		t = firstDelay
		return
	}

	// A second request on the same HTTP connection removes most handshake
	// cost from the score and makes URLTest compare the path rather than the
	// proxy's cold-start behavior.  If a peer closes the connection between
	// requests, retain the successful first result instead of turning a
	// keep-alive quirk into a false outage.
	secondStart := time.Now()
	secondResp, secondErr := client.Do(newRequest())
	if secondErr != nil {
		t = firstDelay
		return
	}
	responseStatus = secondResp.StatusCode
	secondResp.Body.Close()
	t = uint16(time.Since(secondStart) / time.Millisecond)
	return
}

func probeTLSServerName(hostname string) string {
	if ip := net.ParseIP(hostname); ip != nil {
		switch ip.String() {
		case "1.1.1.1", "1.0.0.1":
			return "cloudflare-dns.com"
		}
	}
	return hostname
}

// Legacy tag helpers keep testing URLTest groups source-compatible. Smart uses keyed APIs.
func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	return s.LoadURLTestHistoryKey(HistoryKey{PathIdentity: tag})
}
func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	s.StoreURLTestHistoryKey(HistoryKey{PathIdentity: tag}, history)
}
func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.DeleteURLTestHistoryKey(HistoryKey{PathIdentity: tag})
}
