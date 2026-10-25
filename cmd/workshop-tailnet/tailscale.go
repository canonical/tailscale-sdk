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

type createOAuthAppRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`
}

type oauthApp struct {
	ClientSecret string   `json:"clientSecret,omitempty"`
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirectURIs"`
	Scopes       []string `json:"scopes"`
}

type tailscaleClient struct {
	baseURL    string
	httpClient *http.Client
}

const provisioningScope = "auth_keys:create:once"

// CreateOAuthApp registers an app with the one-time provisioning scope.
func (c tailscaleClient) CreateOAuthApp(
	ctx context.Context,
	token string,
	name string,
	redirectURI string,
) (oauthApp, error) {
	requestBody := createOAuthAppRequest{
		Name:         name,
		RedirectURIs: []string{redirectURI},
		Scopes:       []string{provisioningScope},
	}
	var app oauthApp
	err := c.doJSON(
		ctx,
		http.MethodPost,
		"/api/v2/tailnet/-/oauth-apps",
		token,
		requestBody,
		&app,
	)
	if err != nil {
		return oauthApp{}, fmt.Errorf("create OAuth app: %w", err)
	}
	if app.ID == "" || app.ClientSecret == "" {
		return oauthApp{}, fmt.Errorf(
			"create OAuth app: response did not include both a client " +
				"ID and client secret",
		)
	}
	return app, nil
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
			return fmt.Errorf("encode request: %w", err)
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
		return fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(token, "")
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
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
	err = json.NewDecoder(limitedBody).Decode(output)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// GetOAuthApp retrieves an app so its configuration can be verified.
func (c tailscaleClient) GetOAuthApp(
	ctx context.Context,
	token string,
	id string,
) (oauthApp, error) {
	var app oauthApp
	path := "/api/v2/tailnet/-/oauth-apps/" + url.PathEscape(id)
	err := c.doJSON(ctx, http.MethodGet, path, token, nil, &app)
	if err != nil {
		return oauthApp{}, fmt.Errorf("verify OAuth app: %w", err)
	}
	return app, nil
}

func isLoopbackHostname(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func newTailscaleClient(
	baseURL string,
	httpClient *http.Client,
) tailscaleClient {
	return tailscaleClient{
		baseURL:    baseURL,
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
