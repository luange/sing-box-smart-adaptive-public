package adaptive

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type probeManifestHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// HTTPSignedProbeTargetFetcher fetches an opaque signed payload from one fixed
// control-plane endpoint. It never parses targets or publishes state.
type HTTPSignedProbeTargetFetcher struct {
	endpoint *url.URL
	doer     probeManifestHTTPDoer
}

func NewHTTPSignedProbeTargetFetcher(rawEndpoint string, doer probeManifestHTTPDoer) (*HTTPSignedProbeTargetFetcher, error) {
	endpoint, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return nil, ErrProbeTargetFetch
	}
	if doer == nil {
		doer = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect disabled") }}
	}
	return &HTTPSignedProbeTargetFetcher{endpoint: cloneManifestEndpoint(endpoint), doer: doer}, nil
}

func (*HTTPSignedProbeTargetFetcher) String() string   { return "<adaptive-probe-manifest-fetcher>" }
func (*HTTPSignedProbeTargetFetcher) GoString() string { return "<adaptive-probe-manifest-fetcher>" }
func (*HTTPSignedProbeTargetFetcher) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<adaptive-probe-manifest-fetcher>")
}

func (f *HTTPSignedProbeTargetFetcher) FetchSignedProbeTargets(ctx context.Context) (*SignedProbeTargetManifest, error) {
	if f == nil || f.endpoint == nil || f.doer == nil {
		return nil, ErrProbeTargetFetch
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.endpoint.String(), nil)
	if err != nil {
		return nil, ErrProbeTargetFetch
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := f.doer.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrProbeTargetFetch
	}
	if response == nil {
		return nil, ErrProbeTargetFetch
	}
	if response.Body == nil {
		return nil, ErrProbeTargetFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || response.Request == nil || !sameManifestEndpoint(response.Request.URL, f.endpoint) {
		return nil, ErrProbeTargetFetch
	}
	keyID := response.Header.Get(ProbeManifestKeyIDHeader)
	signature, err := base64.RawURLEncoding.DecodeString(response.Header.Get(ProbeManifestSignatureHeader))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrProbeTargetFetch
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxSignedProbeManifestBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxSignedProbeManifestBytes {
		return nil, ErrProbeTargetFetch
	}
	manifest, err := NewSignedProbeTargetManifest(keyID, payload, signature)
	if err != nil {
		return nil, ErrProbeTargetFetch
	}
	return manifest, nil
}

func sameManifestEndpoint(actual, expected *url.URL) bool {
	return actual != nil && expected != nil && actual.Scheme == expected.Scheme && actual.Host == expected.Host && actual.EscapedPath() == expected.EscapedPath() && actual.RawQuery == expected.RawQuery
}

func cloneManifestEndpoint(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}
