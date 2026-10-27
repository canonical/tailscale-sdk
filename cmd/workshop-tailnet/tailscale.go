package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// createOAuthAppRequest is the JSON payload for app registration.
type createOAuthAppRequest struct {
	AllowedNodeAttributes []string `json:"allowedNodeAttributes"`
	Name                  string   `json:"name"`
	RedirectURIs          []string `json:"redirectUris"`
	Scopes                []string `json:"scopes"`
}

type listOAuthAppsResponse struct {
	OAuthApps []oauthApp `json:"oauthApps"`
}

type oauthApp struct {
	AllowedNodeAttributes []string `json:"allowedNodeAttributes,omitempty"`
	ClientSecret          string   `json:"clientSecret,omitempty"`
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	RedirectURIs          []string `json:"redirectURIs"`
	Scopes                []string `json:"scopes"`
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type tailscaleClient struct {
	baseURL    string
	httpClient *http.Client
}

const (
	defaultNodeAttribute = "workshop"
	nodeAttributePrefix  = "custom:"
	provisioningScope    = "auth_keys:create:once"
	tailscaleAPIURL      = "https://api.tailscale.com"
)

// prefixedNodeAttributes adds the node-attribute prefix required by the
// Tailscale API to each attribute.
func prefixedNodeAttributes(attributes []string) []string {
	prefixed := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		prefixed = append(prefixed, nodeAttributePrefix+attribute)
	}
	return prefixed
}

// unprefixedNodeAttributes removes the node-attribute prefix from each
// attribute so callers see the plain names.
func unprefixedNodeAttributes(attributes []string) []string {
	plain := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		plain = append(plain, strings.TrimPrefix(attribute, nodeAttributePrefix))
	}
	return plain
}

// CreateOAuthApp registers an app with the supplied configuration.
func (c tailscaleClient) CreateOAuthApp(
	ctx context.Context,
	token string,
	args CreateOAuthAppArgs,
) (OAuthApp, error) {
	request := createOAuthAppRequest{
		AllowedNodeAttributes: prefixedNodeAttributes(
			args.AllowedNodeAttributes,
		),
		Name:         args.Name,
		RedirectURIs: args.RedirectURIs,
		Scopes:       args.Scopes,
	}
	var app oauthApp
	err := c.doJSON(
		ctx,
		http.MethodPost,
		"/api/v2/tailnet/-/oauth-apps",
		token,
		request,
		&app,
	)
	if err != nil {
		return OAuthApp{}, fmt.Errorf("creating OAuth app: %w", err)
	}
	if app.ID == "" || app.ClientSecret == "" {
		return OAuthApp{}, fmt.Errorf(
			"creating OAuth app: response did not include both a client " +
				"ID and client secret",
		)
	}
	return app.toOAuthApp(), nil
}

// DeleteOAuthApp removes an OAuth app. An app that is already absent is
// treated as removed.
func (c tailscaleClient) DeleteOAuthApp(
	ctx context.Context,
	token string,
	id string,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		c.baseURL+"/api/v2/tailnet/-/oauth-apps/"+url.PathEscape(id),
		nil,
	)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(token, "")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIResponse(resp, &struct{}{})
	}
	return nil
}

func decodeAPIResponse(resp *http.Response, output any) error {
	defer resp.Body.Close()
	limitedBody := io.LimitReader(resp.Body, 1<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiError struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(limitedBody).Decode(&apiError)
		if apiError.Message != "" {
			return fmt.Errorf(
				"Tailscale API returned %s: %s",
				resp.Status,
				apiError.Message,
			)
		}
		return fmt.Errorf("Tailscale API returned %s", resp.Status)
	}
	err := json.NewDecoder(limitedBody).Decode(output)
	if err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c tailscaleClient) doJSON(
	ctx context.Context,
	method string,
	path string,
	token string,
	input any,
	output any,
) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		method,
		c.baseURL+path,
		body,
	)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.SetBasicAuth(token, "")
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	return decodeAPIResponse(resp, output)
}

// ExchangeAuthCode exchanges an authorisation code for an auth key.
func (c tailscaleClient) ExchangeAuthCode(
	ctx context.Context,
	args ExchangeAuthCodeArgs,
) (string, error) {
	form := url.Values{}
	form.Set("client_id", args.ClientID)
	form.Set("client_secret", args.ClientSecret)
	form.Set("code", args.Code)
	form.Set("grant_type", "authorization_code")
	if len(args.NodeAttributes) > 0 {
		attributes := make(map[string]bool, len(args.NodeAttributes))
		for _, attribute := range prefixedNodeAttributes(args.NodeAttributes) {
			attributes[attribute] = true
		}
		encoded, err := json.Marshal(attributes)
		if err != nil {
			return "", fmt.Errorf("encoding node attributes: %w", err)
		}
		form.Set("node_attributes", string(encoded))
	}
	form.Set("redirect_uri", args.RedirectURI)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/api/v2/oauth/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending token request: %w", err)
	}
	var tokenResponse oauthTokenResponse
	err = decodeAPIResponse(resp, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("exchanging authorisation code: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("token response did not include an access token")
	}
	return tokenResponse.AccessToken, nil
}

// GetOAuthApp retrieves an app so its configuration can be verified.
func (c tailscaleClient) GetOAuthApp(
	ctx context.Context,
	token string,
	id string,
) (OAuthApp, error) {
	var app oauthApp
	path := "/api/v2/tailnet/-/oauth-apps/" + url.PathEscape(id)
	err := c.doJSON(ctx, http.MethodGet, path, token, nil, &app)
	if err != nil {
		return OAuthApp{}, fmt.Errorf("verifying OAuth app: %w", err)
	}
	return app.toOAuthApp(), nil
}

func isLoopbackHostname(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// ListOAuthApps lists every OAuth app in the tailnet.
func (c tailscaleClient) ListOAuthApps(
	ctx context.Context,
	token string,
) ([]OAuthApp, error) {
	var response listOAuthAppsResponse
	err := c.doJSON(
		ctx,
		http.MethodGet,
		"/api/v2/tailnet/-/oauth-apps",
		token,
		nil,
		&response,
	)
	if err != nil {
		return nil, fmt.Errorf("listing OAuth apps: %w", err)
	}
	if response.OAuthApps == nil {
		return nil, nil
	}
	apps := make([]OAuthApp, 0, len(response.OAuthApps))
	for _, app := range response.OAuthApps {
		apps = append(apps, app.toOAuthApp())
	}
	return apps, nil
}

// newTailscaleClient constructs a client for the Tailscale API.
func newTailscaleClient(httpClient *http.Client) tailscaleClient {
	return tailscaleClient{
		baseURL:    tailscaleAPIURL,
		httpClient: httpClient,
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// toOAuthApp maps the wire response to the interface result.
func (app oauthApp) toOAuthApp() OAuthApp {
	return OAuthApp{
		AllowedNodeAttributes: unprefixedNodeAttributes(
			app.AllowedNodeAttributes,
		),
		ClientSecret: app.ClientSecret,
		ID:           app.ID,
		Name:         app.Name,
		RedirectURIs: app.RedirectURIs,
		Scopes:       app.Scopes,
	}
}

func validateRedirectURI(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("must be an absolute HTTP or HTTPS URI")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("scheme must be HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf(
			"must not contain user information, a query, or a fragment",
		)
	}
	if parsed.Scheme == "http" && !isLoopbackHostname(parsed.Hostname()) {
		return fmt.Errorf("HTTP is only allowed for loopback addresses; use HTTPS")
	}
	return nil
}
