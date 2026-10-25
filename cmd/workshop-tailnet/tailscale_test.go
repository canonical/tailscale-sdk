package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juju/tc"
)

// tailscaleSuite tests the Tailscale OAuth app HTTP API client.
type tailscaleSuite struct{}

// TestTailscaleSuite registers the Tailscale HTTP client tests.
func TestTailscaleSuite(t *testing.T) {
	tc.Run(t, &tailscaleSuite{})
}

// TestCreateOAuthApp checks the create request and decoded response.
func (tailscaleSuite) TestCreateOAuthApp(c *tc.C) {
	const token = "test-admin-token"
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Check(r.Method, tc.Equals, http.MethodPost)
			c.Check(r.URL.Path, tc.Equals, oauthAppsPath)
			username, password, ok := r.BasicAuth()
			c.Check(ok, tc.IsTrue)
			c.Check(username, tc.Equals, token)
			c.Check(password, tc.Equals, "")
			c.Check(r.Header.Get("Accept"), tc.Equals, "application/json")
			contentType := r.Header.Get("Content-Type")
			c.Check(contentType, tc.Equals, "application/json")

			var request createOAuthAppRequest
			err := json.NewDecoder(r.Body).Decode(&request)
			c.Check(err, tc.IsNil)
			c.Check(request.Name, tc.Equals, defaultAppName)
			c.Check(
				request.RedirectURIs,
				tc.DeepEquals,
				[]string{defaultRedirectURI},
			)
			c.Check(
				request.Scopes,
				tc.DeepEquals,
				[]string{provisioningScope},
			)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(createdApp("test-secret"))
		}),
	)
	defer server.Close()
	client := newTailscaleClient(server.URL, server.Client())

	app, err := client.CreateOAuthApp(
		c.Context(),
		token,
		defaultAppName,
		defaultRedirectURI,
	)
	c.Assert(err, tc.IsNil)
	c.Check(app, tc.DeepEquals, createdApp("test-secret"))
}

// TestDeleteOAuthApp checks deletion requests and absent-app handling.
func (tailscaleSuite) TestDeleteOAuthApp(c *tc.C) {
	const token = "test-admin-token"
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "removed", status: http.StatusOK},
		{name: "already absent", status: http.StatusNotFound},
		{
			name:    "unauthorised",
			status:  http.StatusUnauthorized,
			wantErr: "invalid test token",
		},
	}
	for _, test := range tests {
		c.Run(test.name, func(c *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					tc.Check(c, r.Method, tc.Equals, http.MethodDelete)
					tc.Check(
						c,
						r.URL.Path,
						tc.Equals,
						oauthAppsPath+"/app-test",
					)
					username, password, ok := r.BasicAuth()
					tc.Check(c, ok, tc.IsTrue)
					tc.Check(c, username, tc.Equals, token)
					tc.Check(c, password, tc.Equals, "")
					tc.Check(
						c,
						r.Header.Get("Accept"),
						tc.Equals,
						"application/json",
					)
					w.WriteHeader(test.status)
					if test.status == http.StatusUnauthorized {
						response := map[string]string{
							"message": "invalid test token",
						}
						_ = json.NewEncoder(w).Encode(response)
					}
				}),
			)
			defer server.Close()
			client := newTailscaleClient(server.URL, server.Client())

			err := client.DeleteOAuthApp(c.Context(), token, "app-test")
			if test.wantErr != "" {
				tc.Assert(c, err, tc.NotNil)
				tc.Check(c, err.Error(), tc.Contains, test.wantErr)
				return
			}
			tc.Check(c, err, tc.IsNil)
		})
	}
}

// TestExchangeAuthCode checks the authorisation-code token exchange.
func (tailscaleSuite) TestExchangeAuthCode(c *tc.C) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Check(r.Method, tc.Equals, http.MethodPost)
			c.Check(r.URL.Path, tc.Equals, "/api/v2/oauth/token")
			_, _, ok := r.BasicAuth()
			c.Check(ok, tc.IsFalse)
			contentType := r.Header.Get("Content-Type")
			c.Check(contentType, tc.Equals, "application/x-www-form-urlencoded")
			err := r.ParseForm()
			c.Check(err, tc.IsNil)
			c.Check(r.Form.Get("grant_type"), tc.Equals, "authorization_code")
			c.Check(r.Form.Get("client_id"), tc.Equals, "app-test")
			c.Check(r.Form.Get("client_secret"), tc.Equals, "test-secret")
			c.Check(r.Form.Get("code"), tc.Equals, "test-code")
			c.Check(r.Form.Get("redirect_uri"), tc.Equals, defaultRedirectURI)
			_ = json.NewEncoder(w).Encode(oauthTokenResponse{
				AccessToken: "test-one-time-token",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			})
		}),
	)
	defer server.Close()
	client := newTailscaleClient(server.URL, server.Client())

	token, err := client.ExchangeAuthCode(
		c.Context(),
		"app-test",
		"test-secret",
		"test-code",
		defaultRedirectURI,
	)
	c.Assert(err, tc.IsNil)
	c.Check(token, tc.Equals, "test-one-time-token")
}

// TestGetOAuthApp checks app verification using the admin credential.
func (tailscaleSuite) TestGetOAuthApp(c *tc.C) {
	const token = "test-admin-token"
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Check(r.Method, tc.Equals, http.MethodGet)
			c.Check(r.URL.Path, tc.Equals, oauthAppsPath+"/app-test")
			username, password, ok := r.BasicAuth()
			c.Check(ok, tc.IsTrue)
			c.Check(username, tc.Equals, token)
			c.Check(password, tc.Equals, "")
			_ = json.NewEncoder(w).Encode(verifiedApp())
		}),
	)
	defer server.Close()
	client := newTailscaleClient(server.URL, server.Client())

	app, err := client.GetOAuthApp(c.Context(), token, "app-test")
	c.Assert(err, tc.IsNil)
	c.Check(app, tc.DeepEquals, verifiedApp())
}

// TestListOAuthApps checks the list request and decoded response.
func (tailscaleSuite) TestListOAuthApps(c *tc.C) {
	const token = "test-admin-token"
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Check(r.Method, tc.Equals, http.MethodGet)
			c.Check(r.URL.Path, tc.Equals, oauthAppsPath)
			username, password, ok := r.BasicAuth()
			c.Check(ok, tc.IsTrue)
			c.Check(username, tc.Equals, token)
			c.Check(password, tc.Equals, "")
			c.Check(r.Header.Get("Accept"), tc.Equals, "application/json")
			response := listOAuthAppsResponse{
				OAuthApps: []oauthApp{verifiedApp()},
			}
			_ = json.NewEncoder(w).Encode(response)
		}),
	)
	defer server.Close()
	client := newTailscaleClient(server.URL, server.Client())

	apps, err := client.ListOAuthApps(c.Context(), token)
	c.Assert(err, tc.IsNil)
	c.Check(apps, tc.DeepEquals, []oauthApp{verifiedApp()})
}

// TestTailscaleAPIError checks that API diagnostics reach the caller.
func (tailscaleSuite) TestTailscaleAPIError(c *tc.C) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			response := map[string]string{"message": "invalid test token"}
			_ = json.NewEncoder(w).Encode(response)
		}),
	)
	defer server.Close()
	client := newTailscaleClient(server.URL, server.Client())

	app, err := client.CreateOAuthApp(
		c.Context(),
		"test-token",
		defaultAppName,
		defaultRedirectURI,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "invalid test token")
	c.Check(app, tc.DeepEquals, oauthApp{})
}
