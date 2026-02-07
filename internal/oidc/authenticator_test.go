package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeStringSlice(t *testing.T) {
	cases := []struct {
		name  string
		input any
		want  []string
	}{
		{name: "string", input: "  group ", want: []string{"group"}},
		{name: "string-empty", input: "   ", want: nil},
		{name: "slice", input: []string{"", " a ", "b"}, want: []string{"a", "b"}},
		{name: "any-slice", input: []any{" a ", 123, "b", ""}, want: []string{"a", "b"}},
		{name: "unsupported", input: 42, want: nil},
	}

	for _, tc := range cases {
		got := normalizeStringSlice(tc.input)
		if !stringSlicesEqual(got, tc.want) {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, got)
		}
	}
}

func TestExtractGroups(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"a", " ", "b"},
	}

	groups := extractGroups(claims, "groups")
	if !stringSlicesEqual(groups, []string{"a", "b"}) {
		t.Fatalf("unexpected groups %v", groups)
	}

	if got := extractGroups(claims, "missing"); got != nil {
		t.Fatalf("expected nil for missing claim, got %v", got)
	}

	if got := extractGroups(nil, "groups"); got != nil {
		t.Fatalf("expected nil for nil claims, got %v", got)
	}
}

func TestNormalizeConfigDefaultsAndTrim(t *testing.T) {
	cfg := Config{
		IssuerURL:    " https://issuer ",
		ClientID:     " client ",
		ClientSecret: " secret ",
	}

	normalized := normalizeConfig(cfg)
	if normalized.IssuerURL != "https://issuer" {
		t.Fatalf("expected issuer url to be trimmed")
	}
	if normalized.ClientID != "client" {
		t.Fatalf("expected client id to be trimmed")
	}
	if normalized.ClientSecret != "secret" {
		t.Fatalf("expected client secret to be trimmed")
	}
	if len(normalized.Scopes) == 0 {
		t.Fatalf("expected default scopes")
	}
	if normalized.GroupClaim == "" {
		t.Fatalf("expected default group claim")
	}
	if normalized.DeviceTimeout == 0 || normalized.HTTPTimeout == 0 {
		t.Fatalf("expected default timeouts")
	}
}

func TestWaitIntervalHonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	if err := waitInterval(ctx, 0); err == nil {
		t.Fatalf("expected context error")
	}
}

func TestRequestTokenUsesBasicAuth(t *testing.T) {
	var gotAuth string
	var gotBody url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		data, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		gotBody, _ = url.ParseQuery(string(data))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(
			[]byte(`{"access_token":"at","id_token":"it","token_type":"Bearer","expires_in":3600}`),
		)
	}))
	defer srv.Close()

	a := &Authenticator{
		clientID:      "client",
		clientSecret:  "secret",
		httpClient:    srv.Client(),
		tokenEndpoint: srv.URL,
	}

	resp, errResp, err := a.requestToken(context.Background(), "device")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errResp != nil {
		t.Fatalf("unexpected error response: %v", errResp)
	}
	if resp.IDToken != "it" {
		t.Fatalf("expected id token")
	}
	if gotAuth == "" || !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("expected basic auth header")
	}
	if gotBody.Get("client_id") != "client" {
		t.Fatalf("expected client_id in body")
	}
	if gotBody.Get("client_secret") != "" {
		t.Fatalf("did not expect client_secret in body")
	}
}

func TestRequestTokenFallbackToBody(t *testing.T) {
	var calls int32
	errCh := make(chan error, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		data, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		values, _ := url.ParseQuery(string(data))

		if call == 1 {
			if r.Header.Get("Authorization") == "" {
				select {
				case errCh <- errAssertion("expected basic auth on first request"):
				default:
				}
			}
			if values.Get("client_secret") != "" {
				select {
				case errCh <- errAssertion("did not expect client_secret in body on first request"):
				default:
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}

		if values.Get("client_secret") != "secret" {
			select {
			case errCh <- errAssertion("expected client_secret in fallback body"):
			default:
			}
		}
		if r.Header.Get("Authorization") != "" {
			select {
			case errCh <- errAssertion("did not expect basic auth on fallback request"):
			default:
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(
			[]byte(`{"access_token":"at","id_token":"it","token_type":"Bearer","expires_in":3600}`),
		)
	}))
	defer srv.Close()

	a := &Authenticator{
		clientID:      "client",
		clientSecret:  "secret",
		httpClient:    srv.Client(),
		tokenEndpoint: srv.URL,
	}

	resp, errResp, err := a.requestToken(context.Background(), "device")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errResp != nil {
		t.Fatalf("unexpected error response: %v", errResp)
	}
	if resp.IDToken != "it" {
		t.Fatalf("expected id token")
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	select {
	case err := <-errCh:
		t.Fatalf("%v", err)
	default:
	}
}

func TestPollTokenAuthorizationPending(t *testing.T) {
	origWait := waitIntervalFn
	waitIntervalFn = func(ctx context.Context, interval time.Duration) error {
		return nil
	}
	t.Cleanup(func() {
		waitIntervalFn = origWait
	})

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		_, _ = w.Write(
			[]byte(`{"access_token":"at","id_token":"it","token_type":"Bearer","expires_in":3600}`),
		)
	}))
	defer srv.Close()

	a := &Authenticator{
		clientID:      "client",
		clientSecret:  "secret",
		httpClient:    srv.Client(),
		tokenEndpoint: srv.URL,
	}

	resp, err := a.pollToken(
		context.Background(),
		deviceAuthResponse{DeviceCode: "device", Interval: 1},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IDToken != "it" {
		t.Fatalf("expected id token")
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type errAssertion string

func (e errAssertion) Error() string {
	return string(e)
}
