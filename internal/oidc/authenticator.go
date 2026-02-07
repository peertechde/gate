package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

const maxOIDCResponseBytes = 1 << 20

type clientAuthMethod int

const (
	clientAuthBasic clientAuthMethod = iota
	clientAuthBody
)

// waitIntervalFn allows tests to stub out sleep behavior during polling.
var waitIntervalFn = waitInterval

// Config configures OIDC device-flow authentication.
type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	Scopes        []string
	GroupClaim    string
	DeviceTimeout time.Duration
	HTTPTimeout   time.Duration
}

// Prompt describes the device login prompt shown to users.
type Prompt struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	ExpiresIn               time.Duration
}

// PromptFunc is called with the device login prompt.
type PromptFunc func(Prompt) error

// Identity captures the verified OIDC identity.
type Identity struct {
	Issuer  string
	Subject string
	Groups  []string
}

// Authenticator performs OIDC device-flow authentication.
type Authenticator struct {
	issuerURL      string
	clientID       string
	clientSecret   string
	scopes         []string
	groupClaim     string
	deviceTimeout  time.Duration
	httpClient     *http.Client
	provider       *coreoidc.Provider
	verifier       *coreoidc.IDTokenVerifier
	deviceEndpoint string
	tokenEndpoint  string
}

// NewAuthenticator initializes an OIDC authenticator using discovery.
func NewAuthenticator(ctx context.Context, cfg Config) (*Authenticator, error) {
	cfg = normalizeConfig(cfg)
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, errors.New("oidc issuer url and client id are required")
	}
	if cfg.GroupClaim == "" {
		return nil, errors.New("oidc group claim must not be empty")
	}
	if cfg.DeviceTimeout <= 0 {
		return nil, errors.New("oidc device timeout must be positive")
	}
	if cfg.HTTPTimeout <= 0 {
		return nil, errors.New("oidc http timeout must be positive")
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	providerCtx := coreoidc.ClientContext(ctx, httpClient)
	provider, err := coreoidc.NewProvider(providerCtx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider discovery: %w", err)
	}

	var discovery struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("oidc discovery claims: %w", err)
	}
	if discovery.DeviceAuthorizationEndpoint == "" {
		return nil, errors.New("oidc device authorization endpoint missing")
	}
	if discovery.TokenEndpoint == "" {
		return nil, errors.New("oidc token endpoint missing")
	}

	verifier := provider.Verifier(&coreoidc.Config{ClientID: cfg.ClientID})

	return &Authenticator{
		issuerURL:      cfg.IssuerURL,
		clientID:       cfg.ClientID,
		clientSecret:   cfg.ClientSecret,
		scopes:         cfg.Scopes,
		groupClaim:     cfg.GroupClaim,
		deviceTimeout:  cfg.DeviceTimeout,
		httpClient:     httpClient,
		provider:       provider,
		verifier:       verifier,
		deviceEndpoint: discovery.DeviceAuthorizationEndpoint,
		tokenEndpoint:  discovery.TokenEndpoint,
	}, nil
}

// Authenticate performs the device flow and returns a verified identity.
func (a *Authenticator) Authenticate(ctx context.Context, prompt PromptFunc) (Identity, error) {
	baseDeadline := time.Now().Add(a.deviceTimeout)
	ctx, cancel := context.WithDeadline(ctx, baseDeadline)
	defer cancel()

	deviceResp, err := a.startDeviceFlow(ctx)
	if err != nil {
		return Identity{}, err
	}

	promptInfo := Prompt{
		VerificationURI:         deviceResp.VerificationURI,
		VerificationURIComplete: deviceResp.VerificationURIComplete,
		UserCode:                deviceResp.UserCode,
		ExpiresIn:               time.Duration(deviceResp.ExpiresIn) * time.Second,
	}
	if prompt != nil {
		if err := prompt(promptInfo); err != nil {
			return Identity{}, err
		}
	}

	if deviceResp.ExpiresIn > 0 {
		expiryDeadline := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
		if expiryDeadline.Before(baseDeadline) {
			expiryCtx, expiryCancel := context.WithDeadline(ctx, expiryDeadline)
			defer expiryCancel()
			ctx = expiryCtx
		}
	}

	tokenResp, err := a.pollToken(ctx, deviceResp)
	if err != nil {
		return Identity{}, err
	}

	if tokenResp.IDToken == "" {
		return Identity{}, errors.New("oidc id_token missing in token response")
	}

	verifyCtx := coreoidc.ClientContext(ctx, a.httpClient)
	idToken, err := a.verifier.Verify(verifyCtx, tokenResp.IDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc token verification failed: %w", err)
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc token claims: %w", err)
	}
	groups := extractGroups(claims, a.groupClaim)

	return Identity{
		Issuer:  idToken.Issuer,
		Subject: idToken.Subject,
		Groups:  groups,
	}, nil
}

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type tokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *tokenError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (a *Authenticator) startDeviceFlow(ctx context.Context) (deviceAuthResponse, error) {
	resp, errResp, status, err := a.startDeviceFlowWithAuth(ctx, clientAuthBasic)
	if err == nil && errResp == nil {
		return a.validateDeviceFlowResponse(resp)
	}

	if a.clientSecret != "" && shouldRetryClientAuth(status, errResp) {
		resp, errResp, status, err = a.startDeviceFlowWithAuth(ctx, clientAuthBody)
		if err == nil && errResp == nil {
			return a.validateDeviceFlowResponse(resp)
		}
	}
	if err != nil {
		return deviceAuthResponse{}, err
	}
	if errResp != nil {
		return deviceAuthResponse{}, errResp
	}

	return deviceAuthResponse{}, fmt.Errorf("oidc endpoint http %d", status)
}

func (a *Authenticator) validateDeviceFlowResponse(
	resp deviceAuthResponse,
) (deviceAuthResponse, error) {
	if resp.DeviceCode == "" || resp.VerificationURI == "" {
		return deviceAuthResponse{}, errors.New("oidc device authorization response incomplete")
	}
	if resp.Interval <= 0 {
		resp.Interval = 5
	}

	return resp, nil
}

func (a *Authenticator) startDeviceFlowWithAuth(
	ctx context.Context,
	auth clientAuthMethod,
) (deviceAuthResponse, *tokenError, int, error) {
	payload := url.Values{}
	payload.Set("client_id", a.clientID)

	if len(a.scopes) > 0 {
		payload.Set("scope", strings.Join(a.scopes, " "))
	}

	var resp deviceAuthResponse
	status, errResp, err := a.postForm(ctx, a.deviceEndpoint, payload, &resp, "oidc endpoint", auth)
	if err != nil {
		return deviceAuthResponse{}, nil, status, err
	}

	return resp, errResp, status, nil
}

func (a *Authenticator) pollToken(
	ctx context.Context,
	device deviceAuthResponse,
) (tokenResponse, error) {
	interval := time.Duration(device.Interval) * time.Second
	for {
		if err := waitIntervalFn(ctx, interval); err != nil {
			return tokenResponse{}, err
		}

		resp, errResp, err := a.requestToken(ctx, device.DeviceCode)
		if err != nil {
			return tokenResponse{}, err
		}
		if errResp == nil {
			return resp, nil
		}

		switch errResp.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token", "invalid_grant", "invalid_client":
			return tokenResponse{}, errResp
		default:
			return tokenResponse{}, errResp
		}
	}
}

func (a *Authenticator) requestToken(
	ctx context.Context,
	deviceCode string,
) (tokenResponse, *tokenError, error) {
	resp, errResp, status, err := a.requestTokenWithAuth(ctx, deviceCode, clientAuthBasic)
	if err == nil && errResp == nil {
		return resp, nil, nil
	}
	if a.clientSecret != "" && shouldRetryClientAuth(status, errResp) {
		resp, errResp, status, err = a.requestTokenWithAuth(ctx, deviceCode, clientAuthBody)
		if err == nil && errResp == nil {
			return resp, nil, nil
		}
	}
	if err != nil {
		return tokenResponse{}, nil, err
	}
	if errResp != nil {
		return tokenResponse{}, errResp, nil
	}

	return tokenResponse{}, nil, fmt.Errorf("oidc token endpoint http %d", status)
}

func (a *Authenticator) requestTokenWithAuth(
	ctx context.Context,
	deviceCode string,
	auth clientAuthMethod,
) (tokenResponse, *tokenError, int, error) {
	payload := url.Values{}
	payload.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	payload.Set("device_code", deviceCode)
	payload.Set("client_id", a.clientID)

	var token tokenResponse
	status, errResp, err := a.postForm(
		ctx,
		a.tokenEndpoint,
		payload,
		&token,
		"oidc token endpoint",
		auth,
	)
	if err != nil {
		return tokenResponse{}, nil, status, err
	}

	return token, errResp, status, nil
}

func (a *Authenticator) postForm(
	ctx context.Context,
	endpoint string,
	payload url.Values,
	out any,
	errorLabel string,
	auth clientAuthMethod,
) (int, *tokenError, error) {
	if auth == clientAuthBody && a.clientSecret != "" {
		payload.Set("client_secret", a.clientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(payload.Encode()),
	)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if auth == clientAuthBasic && a.clientSecret != "" {
		req.SetBasicAuth(a.clientID, a.clientSecret)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var errResp tokenError
		if err := decodeJSONLimited(resp.Body, &errResp); err != nil {
			return resp.StatusCode, nil, fmt.Errorf("%s http %d", errorLabel, resp.StatusCode)
		}
		if errResp.Code == "" {
			return resp.StatusCode, nil, fmt.Errorf("%s http %d", errorLabel, resp.StatusCode)
		}
		return resp.StatusCode, &errResp, nil
	}
	if out == nil {
		return resp.StatusCode, nil, nil
	}

	if err := decodeJSONLimited(resp.Body, out); err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, nil, nil
}

func waitInterval(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func decodeJSONLimited(r io.Reader, out any) error {
	if out == nil {
		return nil
	}

	limited := &io.LimitedReader{R: r, N: maxOIDCResponseBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if limited.N <= 0 {
		return fmt.Errorf("oidc response exceeds %d bytes", maxOIDCResponseBytes)
	}

	return json.Unmarshal(data, out)
}

func shouldRetryClientAuth(status int, errResp *tokenError) bool {
	if status == http.StatusUnauthorized {
		return true
	}
	if errResp != nil && errResp.Code == "invalid_client" {
		return true
	}

	return false
}

func extractGroups(claims map[string]any, claimName string) []string {
	if claimName == "" || claims == nil {
		return nil
	}

	raw, ok := claims[claimName]
	if !ok || raw == nil {
		return nil
	}

	return normalizeStringSlice(raw)
}

func normalizeStringSlice(value any) []string {
	switch v := value.(type) {
	case string:
		item := strings.TrimSpace(v)
		if item == "" {
			return nil
		}
		return []string{item}
	case []string:
		return filterStrings(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			value, ok := item.(string)
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			out = append(out, value)
		}
		return out
	default:
		return nil
	}
}

func filterStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}

	return out
}

func normalizeConfig(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.GroupClaim == "" {
		cfg.GroupClaim = "groups"
	}
	if cfg.DeviceTimeout == 0 {
		cfg.DeviceTimeout = 2 * time.Minute
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}

	cfg.IssuerURL = strings.TrimSpace(cfg.IssuerURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)

	return cfg
}
