package adaptive

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type probeManifestHTTPDoerFunc func(*http.Request) (*http.Response, error)

func (f probeManifestHTTPDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

type trackedProbeBody struct {
	reader io.Reader
	closed bool
}

func (b *trackedProbeBody) Read(content []byte) (int, error) { return b.reader.Read(content) }
func (b *trackedProbeBody) Close() error {
	b.closed = true
	return nil
}

type failingProbeReader struct{}

func (failingProbeReader) Read([]byte) (int, error) {
	return 0, errors.New("https://secret.invalid/?token=leak")
}

func TestHTTPSignedProbeTargetFetcherFeedsAuthenticatedProvider(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := signedYouTubeManifest(t, youtubeTargetSnapshot(t, now, 1), "fetch-key", privateKey, youtubeTargetSourceID)
	body := &trackedProbeBody{reader: strings.NewReader(signed.payload.value)}
	fetcher, err := NewHTTPSignedProbeTargetFetcher("https://control.example.test/adaptive/v1/targets", probeManifestHTTPDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://control.example.test/adaptive/v1/targets" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("unexpected manifest request: %+v", request)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			TLS:        &tls.ConnectionState{},
			Request:    request,
			Header: http.Header{
				probeManifestKeyIDHeader:     []string{"fetch-key"},
				probeManifestSignatureHeader: []string{base64.RawURLEncoding.EncodeToString(signed.signature)},
			},
			Body: body,
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewTrustedYouTubeTargetProvider(&fakeClock{now: now}, fetcher, map[string]ed25519.PublicKey{"fetch-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err = provider.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.Snapshot(context.Background(), youtubeProbeServiceID)
	if err != nil || snapshot.Generation != 1 {
		t.Fatalf("fetched authenticated manifest was not published: generation=%d err=%v", snapshot.Generation, err)
	}
	if !body.closed {
		t.Fatal("successful manifest response body was not closed")
	}
	formatted := fmt.Sprintf("%+v %#v", fetcher, fetcher)
	if strings.Contains(formatted, "control.example") || strings.Contains(formatted, "adaptive/v1") {
		t.Fatalf("fetcher formatter exposed its control endpoint: %s", formatted)
	}
}

func TestHTTPSignedProbeTargetFetcherRejectsTransportFailuresAndClosesBodies(t *testing.T) {
	validSignature := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tests := []struct {
		name          string
		response      func(*trackedProbeBody) *http.Response
		doErr         error
		finalEndpoint string
	}{
		{name: "redirect", response: func(body *trackedProbeBody) *http.Response {
			return &http.Response{StatusCode: http.StatusFound, TLS: &tls.ConnectionState{}, Header: make(http.Header), Body: body}
		}},
		{name: "no tls", response: func(body *trackedProbeBody) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}
		}},
		{name: "invalid signature", response: func(body *trackedProbeBody) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: http.Header{probeManifestKeyIDHeader: []string{"key"}, probeManifestSignatureHeader: []string{"not-base64"}}, Body: body}
		}},
		{name: "oversize", response: func(body *trackedProbeBody) *http.Response {
			body.reader = bytes.NewReader(make([]byte, maxSignedProbeManifestBytes+1))
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: http.Header{probeManifestKeyIDHeader: []string{"key"}, probeManifestSignatureHeader: []string{validSignature}}, Body: body}
		}},
		{name: "read error", response: func(body *trackedProbeBody) *http.Response {
			body.reader = failingProbeReader{}
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: http.Header{probeManifestKeyIDHeader: []string{"key"}, probeManifestSignatureHeader: []string{validSignature}}, Body: body}
		}},
		{name: "do error with response", response: func(body *trackedProbeBody) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: make(http.Header), Body: body}
		}, doErr: errors.New("https://secret.invalid/?token=leak")},
		{name: "followed redirect", response: func(body *trackedProbeBody) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, TLS: &tls.ConnectionState{}, Header: http.Header{probeManifestKeyIDHeader: []string{"key"}, probeManifestSignatureHeader: []string{validSignature}}, Body: body}
		}, finalEndpoint: "https://other.example.test/manifest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedProbeBody{reader: strings.NewReader("private payload")}
			fetcher, err := NewHTTPSignedProbeTargetFetcher("https://control.example.test/manifest", probeManifestHTTPDoerFunc(func(request *http.Request) (*http.Response, error) {
				response := test.response(body)
				response.Request = request
				if test.finalEndpoint != "" {
					response.Request, _ = http.NewRequest(http.MethodGet, test.finalEndpoint, nil)
				}
				return response, test.doErr
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = fetcher.FetchSignedProbeTargets(context.Background())
			if !errors.Is(err, ErrProbeTargetFetch) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), "payload") {
				t.Fatalf("transport failure was not sanitized: %v", err)
			}
			if !body.closed {
				t.Fatal("failed manifest response body was not closed")
			}
		})
	}
}

func TestHTTPSignedProbeTargetFetcherRejectsUnsafeEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://control.example.test/manifest",
		"https://user:password@control.example.test/manifest",
		"https://control.example.test/manifest?token=secret",
		"https://control.example.test/manifest#fragment",
	} {
		if _, err := NewHTTPSignedProbeTargetFetcher(endpoint, probeManifestHTTPDoerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })); !errors.Is(err, ErrProbeTargetFetch) {
			t.Fatalf("unsafe control endpoint was accepted: %s", endpoint)
		}
	}
}
