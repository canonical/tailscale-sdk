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
		AllowedNodeAttributes: provisioningNodeAttributeNames,
		ClientID:              "app-test",
		ClientSecret:          "test-client-secret",
		Name:                  defaultAppName,
		RedirectURIs:          []string{redirectURI},
		Scopes:                []string{provisioningScope},
	}
}

// testNodeAttributes provides deterministic node attribute values for
// authentication tests.
func testNodeAttributes() map[string]any {
	return map[string]any{
		nodeAttributeIs:        true,
		nodeAttributeName:      "test-workshop",
		nodeAttributeProjectId: "test-project",
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
		testNodeAttributes(),
		&output,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "credential is empty")
}

// TestAuthenticateRejectsLegacyCredential checks that a credential saved
// before node attributes were allowlisted fails with re-setup guidance.
func (authSuite) TestAuthenticateRejectsLegacyCredential(c *tc.C) {
	legacy := `{
  "client_id": "app-test",
  "client_secret": "test-client-secret",
  "name": "Canonical-Workshop",
  "redirect_uris": ["http://127.0.0.1:8765/callback"],
  "scopes": ["auth_keys:create:once"]
}`
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := os.WriteFile(configPath, []byte(legacy), 0o600)
	c.Assert(err, tc.IsNil)
	var output strings.Builder

	err = authenticate(
		c.Context(),
		nil,
		configPath,
		filepath.Join(c.MkDir(), "auth-key"),
		testNodeAttributes(),
		&output,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, nodeAttributeIs)
	c.Check(err.Error(), tc.Contains, "re-run workshop-tailnet setup")
}

// TestAuthenticateRejectsInvalidState checks OAuth CSRF protection.
func (authSuite) TestAuthenticateRejectsInvalidState(c *tc.C) {
	address := unusedLoopbackAddress(c)
	app := testOAuthApp("http://" + address + "/callback")
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, app)
	c.Assert(err, tc.IsNil)
	authKeyPath := filepath.Join(c.MkDir(), "auth-key")
	authURLPath := filepath.Join(filepath.Dir(authKeyPath), authURLFilename)
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
			testNodeAttributes(),
			writer,
		)
		_ = writer.Close()
	}()

	lines := bufio.NewReader(reader)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	_, err = lines.ReadString('\n')
	c.Assert(err, tc.IsNil)
	_, err = os.Stat(authURLPath)
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
	c.Check(provisioner.args, tc.DeepEquals, ExchangeAuthCodeArgs{})
	_, statErr := os.Stat(authKeyPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	_, statErr = os.Stat(authURLPath)
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
	authURLPath := filepath.Join(filepath.Dir(authKeyPath), authURLFilename)
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
			testNodeAttributes(),
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
	notice, err := os.ReadFile(authURLPath)
	c.Assert(err, tc.IsNil)
	c.Check(string(notice), tc.Equals, authorisationLine)
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
	c.Check(provisioner.args, tc.DeepEquals, ExchangeAuthCodeArgs{
		ClientID:       "app-test",
		ClientSecret:   "test-client-secret",
		Code:           "test-code",
		NodeAttributes: testNodeAttributes(),
		RedirectURI:    app.RedirectURIs[0],
	})
	encoded, err := os.ReadFile(authKeyPath)
	c.Assert(err, tc.IsNil)
	c.Check(string(encoded), tc.Equals, "test-one-time-token\n")
	info, err := os.Stat(authKeyPath)
	c.Assert(err, tc.IsNil)
	c.Check(info.Mode().Perm(), tc.Equals, os.FileMode(0o600))
	_, statErr := os.Stat(authURLPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
}

// TestWorkshopNodeAttributes checks attribute collection from the
// workshop name and the project lock file.
func (authSuite) TestWorkshopNodeAttributes(c *tc.C) {
	lockPath := filepath.Join(c.MkDir(), ".workshop.lock")
	err := os.WriteFile(lockPath, []byte("12345\n"), 0o600)
	c.Assert(err, tc.IsNil)

	attributes, err := workshopNodeAttributes(lockPath)
	c.Assert(err, tc.IsNil)
	hostname, err := os.Hostname()
	c.Assert(err, tc.IsNil)
	c.Check(attributes[nodeAttributeIs], tc.Equals, true)
	c.Check(
		attributes[nodeAttributeName],
		tc.Equals,
		strings.ReplaceAll(hostname, "-", "_"),
	)
	c.Check(attributes[nodeAttributeProjectId], tc.Equals, "12345")

	attributes, err = workshopNodeAttributes(
		filepath.Join(c.MkDir(), "absent.lock"),
	)
	c.Assert(err, tc.IsNil)
	_, ok := attributes[nodeAttributeProjectId]
	c.Check(ok, tc.IsFalse)

	err = os.WriteFile(lockPath, nil, 0o600)
	c.Assert(err, tc.IsNil)
	_, err = workshopNodeAttributes(lockPath)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "is empty")
}
