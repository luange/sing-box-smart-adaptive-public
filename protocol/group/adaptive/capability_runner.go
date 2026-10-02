package adaptive

import (
	"context"
	"crypto/sha256"
	stdTLS "crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var errProbeRedirectPolicy = errors.New("adaptive probe redirect rejected")

const (
	defaultProbeBodyLimit = int64(64 * 1024)
	probePayloadPrefix    = 64
	maxProbeRedirects     = 3
)

type probeHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	CloseIdleConnections()
}

type CapabilityProbeRunner struct {
	clock              Clock
	bodyLimit          int64
	httpClientFactory  func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error)
	http3ClientFactory func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error)
	tlsProbe           func(context.Context, N.Dialer, ProbeTarget) ProbeRawResult
}

func NewCapabilityProbeRunner(clock Clock) *CapabilityProbeRunner {
	if clock == nil {
		clock = realClock{}
	}
	runner := &CapabilityProbeRunner{clock: clock, bodyLimit: defaultProbeBodyLimit}
	runner.httpClientFactory = runner.newHTTPClient
	runner.http3ClientFactory = newHTTP3ProbeClient
	runner.tlsProbe = runner.runTLS
	return runner
}

func (r *CapabilityProbeRunner) Run(ctx context.Context, dialer N.Dialer, target ProbeTarget) (result ProbeRawResult) {
	startedAt := r.clock.Now()
	defer func() {
		result.Delay = r.clock.Now().Sub(startedAt)
		if recovered := recover(); recovered != nil {
			result = ProbeRawResult{ProtocolFailed: true, Delay: result.Delay}
		}
	}()
	if dialer == nil || target.executionURL() == "" || r.clock.Now().Before(target.IssuedAt) || !r.clock.Now().Before(target.ExpiresAt) {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	if target.Capability == ProbeCapabilityEndpoint {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	if target.Capability == ProbeCapabilityTLS {
		return r.tlsProbe(ctx, dialer, target)
	}
	clientFactory := r.httpClientFactory
	if target.Capability == ProbeCapabilityHTTP3 {
		clientFactory = r.http3ClientFactory
	}
	client, err := clientFactory(ctx, dialer, target)
	if err != nil {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.executionURL(), nil)
	if err != nil {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "sing-box-adaptive-probe/1")
	if target.Capability == ProbeCapabilityRange && target.Range != nil {
		request.Header.Set("Range", "bytes="+strconv.FormatInt(target.Range.Start, 10)+"-"+strconv.FormatInt(target.Range.End, 10))
	}
	var tlsStarted, tlsFailed, gotConnection bool
	trace := &httptrace.ClientTrace{
		GotConn:           func(httptrace.GotConnInfo) { gotConnection = true },
		TLSHandshakeStart: func() { tlsStarted = true },
		TLSHandshakeDone: func(_ stdTLS.ConnectionState, handshakeErr error) {
			tlsFailed = handshakeErr != nil
		},
	}
	response, err := client.Do(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	if err != nil {
		return classifyProbeExecutionError(ctx, err, tlsStarted, tlsFailed, gotConnection)
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	result.WAFChallenge = strings.EqualFold(strings.TrimSpace(response.Header.Get("cf-mitigated")), "challenge")
	if target.Capability == ProbeCapabilityHTTP3 && response.ProtoMajor != 3 {
		result.ProtocolFailed = true
		return result
	}
	result.ContentRange = response.Header.Get("Content-Range")
	result.ContentType = response.Header.Get("Content-Type")
	result.TLSHandshakeOK = !target.RequireTLS || target.Capability == ProbeCapabilityHTTP3 || response.TLS != nil || tlsStarted && !tlsFailed
	limit := r.bodyLimit
	if limit <= 0 {
		limit = defaultProbeBodyLimit
	}
	if target.Capability == ProbeCapabilityRange && target.Range != nil {
		limit = target.Range.Len() + 1
	} else if target.Capability == ProbeCapabilityExitIdentity {
		limit = 65
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, limit))
	result.BytesRead = int64(len(payload))
	if target.Capability == ProbeCapabilityExitIdentity {
		if result.StatusCode == http.StatusOK && len(payload) <= 64 {
			result.identityToken, result.hasIdentityToken = tokenizeExitIdentity(payload)
		}
	} else if len(payload) > 0 {
		prefixLength := min(len(payload), probePayloadPrefix)
		result.PayloadPrefix = append([]byte(nil), payload[:prefixLength]...)
		result.Digest = sha256.Sum256(payload)
		result.HasDigest = true
	}
	if readErr != nil {
		if errors.Is(readErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			result.Canceled = true
		} else if isTimeoutError(readErr) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
		} else {
			result.ProtocolFailed = true
		}
	}
	return result
}

func (r *CapabilityProbeRunner) newHTTPClient(ctx context.Context, dialer N.Dialer, target ProbeTarget) (probeHTTPClient, error) {
	redirectHosts := target.executionRedirectHosts()
	allowedHosts := make(map[string]struct{}, len(redirectHosts)+1)
	allowedHosts[strings.ToLower(target.executionHost())] = struct{}{}
	for _, host := range redirectHosts {
		allowedHosts[strings.ToLower(host)] = struct{}{}
	}
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: C.TCPTimeout,
		TLSClientConfig: &stdTLS.Config{
			MinVersion: stdTLS.VersionTLS12,
			Time:       ntp.TimeFuncFromContext(ctx),
			RootCAs:    adapter.RootPoolFromContext(ctx),
		},
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(dialContext, network, M.ParseSocksaddr(address))
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxProbeRedirects || !probeRedirectAllowed(request.URL, allowedHosts) {
				return errProbeRedirectPolicy
			}
			return nil
		},
	}
	return client, nil
}

func (r *CapabilityProbeRunner) runTLS(ctx context.Context, dialer N.Dialer, target ProbeTarget) ProbeRawResult {
	parsed, err := url.Parse(target.executionURL())
	if err != nil || parsed.Hostname() == "" {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	connection, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(parsed.Hostname(), port))
	if err != nil {
		return classifyProbeExecutionError(ctx, err, false, false, false)
	}
	defer connection.Close()
	tlsConnection := stdTLS.Client(connection, &stdTLS.Config{
		ServerName: parsed.Hostname(), MinVersion: stdTLS.VersionTLS12,
		Time: ntp.TimeFuncFromContext(ctx), RootCAs: adapter.RootPoolFromContext(ctx),
	})
	if err = tlsConnection.HandshakeContext(ctx); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return ProbeRawResult{Canceled: true}
		}
		if isTimeoutError(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ProbeRawResult{TimedOut: true}
		}
		return ProbeRawResult{}
	}
	return ProbeRawResult{TLSHandshakeOK: true}
}

func classifyProbeExecutionError(ctx context.Context, err error, tlsStarted, tlsFailed, gotConnection bool) ProbeRawResult {
	if errors.Is(err, errProbeRedirectPolicy) {
		return ProbeRawResult{TargetPolicyErr: true}
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return ProbeRawResult{Canceled: true}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || isTimeoutError(err) {
		return ProbeRawResult{TimedOut: true}
	}
	if tlsStarted && tlsFailed {
		return ProbeRawResult{}
	}
	if gotConnection {
		return ProbeRawResult{TLSHandshakeOK: tlsStarted && !tlsFailed, ProtocolFailed: true}
	}
	return ProbeRawResult{ConnectFailed: true}
}

func isTimeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func probeRedirectAllowed(location *url.URL, allowedHosts map[string]struct{}) bool {
	if location == nil || location.Scheme != "http" && location.Scheme != "https" {
		return false
	}
	_, allowed := allowedHosts[strings.ToLower(strings.TrimSuffix(location.Hostname(), "."))]
	return allowed
}
