package adaptive

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
)

type probeHTTPClientFunc struct {
	do     func(*http.Request) (*http.Response, error)
	closed bool
}

func (c *probeHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return c.do(request)
}

func (c *probeHTTPClientFunc) CloseIdleConnections() { c.closed = true }

func TestCapabilityProbeRunnerRangeRequestAndStructuredResult(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &fakeClock{now: now}
	target := testProbeTarget(t, "runner-range", 9, ProbeCapabilityRange, now)
	client := &probeHTTPClientFunc{do: func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != target.executionURL() {
			t.Fatalf("runner changed execution URL")
		}
		if got := request.Header.Get("Range"); got != "bytes=0-15" {
			t.Fatalf("unexpected range header: %q", got)
		}
		if got := request.Header.Get("Accept-Encoding"); got != "identity" {
			t.Fatalf("compression was not disabled: %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			TLS:        &tls.ConnectionState{},
			Header: http.Header{
				"Content-Range": []string{"bytes 0-15/100"},
				"Content-Type":  []string{"video/mp4"},
			},
			Body: io.NopCloser(bytes.NewReader([]byte("0123456789abcdef"))),
		}, nil
	}}
	runner := NewCapabilityProbeRunner(clock)
	runner.httpClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		return client, nil
	}

	result := runner.Run(context.Background(), newTestOutbound("runner"), target)
	if !client.closed {
		t.Fatal("HTTP idle connections were not closed")
	}
	if result.StatusCode != http.StatusPartialContent || result.ContentRange != "bytes 0-15/100" || result.ContentType != "video/mp4" || result.BytesRead != 16 || !result.HasDigest {
		t.Fatalf("unexpected structured result: %+v", result)
	}
	if classification := ClassifyProbeResult(target, result, now); classification.Class != ProbeSampleSuccess {
		t.Fatalf("valid range response was not successful: %+v", classification)
	}
	formatted := fmt.Sprintf("%+v", result)
	if strings.Contains(formatted, "runner-range.example.test") || strings.Contains(formatted, "secret-runner-range") {
		t.Fatalf("structured result leaked target credentials: %s", formatted)
	}
}

func TestCapabilityProbeRunnerTLSAndErrorBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	runner := NewCapabilityProbeRunner(&fakeClock{now: now})
	target := testProbeTarget(t, "runner-tls", 1, ProbeCapabilityTLS, now)
	dialer := newTestOutbound("runner")

	called := 0
	runner.tlsProbe = func(context.Context, N.Dialer, ProbeTarget) ProbeRawResult {
		called++
		return ProbeRawResult{TLSHandshakeOK: true}
	}
	if result := runner.Run(context.Background(), dialer, target); !result.TLSHandshakeOK || called != 1 {
		t.Fatalf("TLS runner did not use the TLS execution path: %+v calls=%d", result, called)
	}

	runner.tlsProbe = func(context.Context, N.Dialer, ProbeTarget) ProbeRawResult { panic("private target must not escape") }
	if result := runner.Run(context.Background(), dialer, target); !result.ProtocolFailed {
		t.Fatalf("TLS panic was not contained: %+v", result)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := classifyProbeExecutionError(canceled, context.Canceled, false, false, false); !result.Canceled {
		t.Fatalf("cancellation was misclassified: %+v", result)
	}
	if result := classifyProbeExecutionError(context.Background(), timeoutProbeError{}, false, false, false); !result.TimedOut {
		t.Fatalf("timeout was misclassified: %+v", result)
	}
	if result := classifyProbeExecutionError(context.Background(), errors.New("dial failed"), false, false, false); !result.ConnectFailed {
		t.Fatalf("connect error was misclassified: %+v", result)
	}
	if result := classifyProbeExecutionError(context.Background(), errors.New("tls failed"), true, true, true); result.ConnectFailed || result.ProtocolFailed || result.TLSHandshakeOK {
		t.Fatalf("TLS handshake failure escaped its classification boundary: %+v", result)
	}
}

func TestCapabilityProbeRunnerDetectsWAFChallengeWithoutPersistingHeaders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	runner := NewCapabilityProbeRunner(&fakeClock{now: now})
	// web_waf is sealed at construct; HTTP runner still detects challenge markers.
	target := testProbeTarget(t, "runner-http-waf", 1, ProbeCapabilityHTTP, now)
	var userAgent string
	runner.httpClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(request *http.Request) (*http.Response, error) {
			userAgent = request.Header.Get("User-Agent")
			return &http.Response{
				StatusCode: http.StatusForbidden, TLS: &tls.ConnectionState{},
				Header: http.Header{"Cf-Mitigated": []string{"challenge"}, "Set-Cookie": []string{"secret=must-not-escape"}},
				Body:   io.NopCloser(strings.NewReader("challenge body")),
			}, nil
		}}, nil
	}
	result := runner.Run(context.Background(), newTestOutbound("runner-http-waf"), target)
	// web_waf sealed → HTTP probe UA; challenge marker detection is what matters.
	if !result.WAFChallenge || result.StatusCode != http.StatusForbidden || userAgent == "" {
		t.Fatalf("WAF challenge was not detected: result=%+v ua=%q", result, userAgent)
	}
	formatted := fmt.Sprintf("%+v %#v", result, result)
	if strings.Contains(formatted, "Set-Cookie") || strings.Contains(formatted, "must-not-escape") {
		t.Fatalf("WAF response headers escaped structured result: %s", formatted)
	}
}

func TestCapabilityProbeRunnerRequiresRealHTTP3(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target, err := NewProbeTarget("https://h3.example.test/object?token=secret", 1, ProbeCapabilityHTTP3, now.Add(-time.Minute), now.Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewCapabilityProbeRunner(&fakeClock{now: now})
	runner.http3ClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, ProtoMajor: 3, ProtoMinor: 0, TLS: &tls.ConnectionState{}, Header: http.Header{"Content-Type": []string{"video/mp4"}}, Body: io.NopCloser(strings.NewReader("payload"))}, nil
		}}, nil
	}
	result := runner.Run(context.Background(), newTestOutbound("runner"), target)
	if result.ProtocolFailed || !result.TLSHandshakeOK || result.BytesRead == 0 {
		t.Fatalf("valid HTTP/3 response failed: %+v", result)
	}
	runner.http3ClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, ProtoMajor: 2, TLS: &tls.ConnectionState{}, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("payload"))}, nil
		}}, nil
	}
	if result = runner.Run(context.Background(), newTestOutbound("runner"), target); !result.ProtocolFailed {
		t.Fatalf("HTTP/2 fallback was accepted as HTTP/3: %+v", result)
	}
}

func TestCapabilityProbeRunnerExitIdentityKeepsAddressOutOfResult(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target, err := NewProbeTarget("https://api.ipify.org/", 1, ProbeCapabilityExitIdentity, now.Add(-time.Minute), now.Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewExitIdentityStore("runner-exit-identity"); err != nil {
		t.Fatal(err)
	}
	runner := NewCapabilityProbeRunner(&fakeClock{now: now})
	runner.httpClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		return &probeHTTPClientFunc{do: func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("203.0.113.25\n"))}, nil
		}}, nil
	}
	result := runner.Run(context.Background(), newTestOutbound("runner-exit-identity"), target)
	if !result.hasIdentityToken || result.HasDigest || len(result.PayloadPrefix) != 0 || result.BytesRead == 0 {
		t.Fatalf("unexpected exit identity result shape: %+v", result)
	}
	if formatted := fmt.Sprintf("%+v", result); strings.Contains(formatted, "203.0.113.25") {
		t.Fatalf("raw exit identity leaked through result formatting: %s", formatted)
	}
	if classification := ClassifyProbeResult(target, result, now); classification.Class != ProbeSampleSuccess {
		t.Fatalf("valid exit identity was rejected: %+v", classification)
	}
	result.identityChanged = true
	if classification := ClassifyProbeResult(target, result, now); classification.Class != ProbeSampleNodeFailure || classification.Failure != FailureIdentity {
		t.Fatalf("exit identity change was not classified: %+v", classification)
	}
}

func TestCapabilityProbeRunnerRedirectPolicyAndInvalidTargets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	target := testProbeTarget(t, "runner-http", 1, ProbeCapabilityHTTP, now)
	target, _ = target.WithRedirectHosts("allowed-cdn.example.test")
	runner := NewCapabilityProbeRunner(&fakeClock{now: now})
	client, err := runner.newHTTPClient(context.Background(), newTestOutbound("runner"), target)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := client.(*http.Client)
	allowed, _ := url.Parse("https://allowed-cdn.example.test/object")
	blocked, _ := url.Parse("https://untrusted.example.test/object?token=secret")
	if err = httpClient.CheckRedirect(&http.Request{URL: allowed}, []*http.Request{{}}); err != nil {
		t.Fatalf("allowlisted redirect rejected: %v", err)
	}
	if err = httpClient.CheckRedirect(&http.Request{URL: blocked}, []*http.Request{{}}); !errors.Is(err, errProbeRedirectPolicy) {
		t.Fatalf("untrusted redirect accepted: %v", err)
	}
	via := make([]*http.Request, maxProbeRedirects)
	if err = httpClient.CheckRedirect(&http.Request{URL: allowed}, via); !errors.Is(err, errProbeRedirectPolicy) {
		t.Fatalf("redirect limit was not enforced: %v", err)
	}

	invocations := 0
	runner.httpClientFactory = func(context.Context, N.Dialer, ProbeTarget) (probeHTTPClient, error) {
		invocations++
		return nil, errors.New("must not execute")
	}
	expired := target
	expired.ExpiresAt = now
	if result := runner.Run(context.Background(), newTestOutbound("runner"), expired); !result.TargetPolicyErr || invocations != 0 {
		t.Fatalf("expired target reached execution: %+v invocations=%d", result, invocations)
	}
	endpoint := testProbeTarget(t, "runner-endpoint", 1, ProbeCapabilityEndpoint, now)
	if result := runner.Run(context.Background(), newTestOutbound("runner"), endpoint); !result.TargetPolicyErr || invocations != 0 {
		t.Fatalf("endpoint target entered service runner: %+v invocations=%d", result, invocations)
	}
}

type timeoutProbeError struct{}

func (timeoutProbeError) Error() string   { return "timeout" }
func (timeoutProbeError) Timeout() bool   { return true }
func (timeoutProbeError) Temporary() bool { return true }
