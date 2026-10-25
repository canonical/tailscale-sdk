package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juju/tc"
)

// authSuite tests OAuth callback handling and one-time token storage.
type authSuite struct{}

func testOAuthApp(redirectURI string) storedOAuthApp {
	return storedOAuthApp{
		ClientID:     "app-test",
		ClientSecret: "test-client-secret",
		Name:         defaultAppName,
		RedirectURIs: []string{redirectURI},
		Scopes:       []string{provisioningScope},
	}
}

func unusedLoopbackAddress(c *tc.C) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, tc.IsNil)
	address := listener.Addr().String()
	err = listener.Close()
	c.Assert(err, tc.IsNil)
	return address
}

// TestAuthSuite registers the OAuth authentication tests.
func TestAuthSuite(t *testing.T) {
	tc.Run(t, &authSuite{})
}

// TestAuthenticateRejectsEmptyCredential checks fail-closed credential loading.
func (authSuite) TestAuthenticateRejectsEmptyCredential(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := os.WriteFile(configPath, nil, 0o600)
	c.Assert(err, tc.IsNil)
	var output strings.Builder

	err = authenticate(
		c.Context(),
		nil,
		configPath,
		filepath.Join(c.MkDir(), "auth-key"),
		&output,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "credential is empty")
}

// TestAuthenticateRejectsInvalidState checks OAuth CSRF protection.
func (authSuite) TestAuthenticateRejectsInvalidState(c *tc.C) {
	address := unusedLoopbackAddress(c)
	app := testOAuthApp("http://" + address + "/callback")
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, app)
	c.Assert(err, tc.IsNil)
	authKeyPath := filepath.Join(c.MkDir(), "auth-key")
	provisioner := &fakeDeviceProvisioner{token: "test-one-time-token"}
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- authenticate(
			ctx,
			provisioner,
			configPath,
			authKeyPath,
			writer,
		)
		_ = writer.Close()
	}()

	lines := bufio.NewReader(reader)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	callbackURL := "http://" + address + "/callback?code=test-code&state=wrong"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(callbackURL)
	c.Assert(err, tc.IsNil)
	_, err = io.Copy(io.Discard, resp.Body)
	c.Assert(err, tc.IsNil)
	err = resp.Body.Close()
	c.Assert(err, tc.IsNil)
	c.Check(resp.StatusCode, tc.Equals, http.StatusBadRequest)

	err = <-result
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "state did not match")
	c.Check(provisioner.code, tc.Equals, "")
	_, statErr := os.Stat(authKeyPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
}

// TestAuthenticateSavesOneTimeToken checks the complete OAuth callback flow.
func (authSuite) TestAuthenticateSavesOneTimeToken(c *tc.C) {
	address := unusedLoopbackAddress(c)
	app := testOAuthApp("http://" + address + "/callback")
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, app)
	c.Assert(err, tc.IsNil)
	authKeyPath := filepath.Join(c.MkDir(), "auth-key")
	provisioner := &fakeDeviceProvisioner{token: "test-one-time-token"}
	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- authenticate(
			ctx,
			provisioner,
			configPath,
			authKeyPath,
			writer,
		)
		_ = writer.Close()
	}()

	lines := bufio.NewReader(reader)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	authorisationLine, err := lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	authorisationURL, err := url.Parse(strings.TrimSpace(authorisationLine))
	c.Assert(err, tc.IsNil)
	state := authorisationURL.Query().Get("state")
	c.Assert(state, tc.Not(tc.Equals), "")
	c.Check(authorisationURL.Query().Get("client_id"), tc.Equals, "app-test")
	callbackURL := fmt.Sprintf(
		"http://%s/callback?code=test-code&state=%s",
		address,
		url.QueryEscape(state),
	)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(callbackURL)
	c.Assert(err, tc.IsNil)
	_, err = io.Copy(io.Discard, resp.Body)
	c.Assert(err, tc.IsNil)
	err = resp.Body.Close()
	c.Assert(err, tc.IsNil)
	c.Check(resp.StatusCode, tc.Equals, http.StatusOK)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)

	err = <-result
	c.Assert(err, tc.IsNil)
	c.Check(provisioner.clientID, tc.Equals, "app-test")
	c.Check(provisioner.clientSecret, tc.Equals, "test-client-secret")
	c.Check(provisioner.code, tc.Equals, "test-code")
	c.Check(provisioner.redirectURI, tc.Equals, app.RedirectURIs[0])
	encoded, err := os.ReadFile(authKeyPath)
	c.Assert(err, tc.IsNil)
	c.Check(string(encoded), tc.Equals, "test-one-time-token\n")
	info, err := os.Stat(authKeyPath)
	c.Assert(err, tc.IsNil)
	c.Check(info.Mode().Perm(), tc.Equals, os.FileMode(0o600))
}
