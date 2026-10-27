package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juju/tc"
)

// removeSuite tests the interactive OAuth app removal command.
type removeSuite struct{}

// TestRemoveSuite registers the OAuth app removal behaviour tests.
func TestRemoveSuite(t *testing.T) {
	tc.Run(t, &removeSuite{})
}

func storedOAuthAppForID(id string) storedOAuthApp {
	return storedOAuthApp{
		AllowedNodeAttributes: []string{defaultNodeAttribute},
		ClientID:              id,
		ClientSecret:          "test-client-secret",
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	}
}

// TestRemoveCommandRequiresClientID checks argument validation.
func (removeSuite) TestRemoveCommandRequiresClientID(c *tc.C) {
	var stdout bytes.Buffer
	err := run(
		c.Context(),
		[]string{"remove-oauth-app"},
		nil,
		nil,
		nil,
		nil,
		&stdout,
	)
	c.Check(err, tc.ErrorIs, errUsage)
}

// TestRemoveCommandDispatchesByID checks command dispatch and config lookup.
func (removeSuite) TestRemoveCommandDispatchesByID(c *tc.C) {
	c.Run("dispatch", func(c *testing.T) {
		configRoot := c.TempDir()
		c.Setenv("XDG_CONFIG_HOME", configRoot)
		configPath := filepath.Join(
			configRoot,
			"workshop-tailnet",
			"oauth-app.json",
		)
		err := saveOAuthApp(configPath, storedOAuthAppForID("app-test"))
		tc.Assert(c, err, tc.IsNil)

		var stdout bytes.Buffer
		prompt := &fakePrompter{
			confirmation: true,
			secretValue:  "test-admin-token",
		}
		client := &fakeOAuthAppClient{}

		err = run(
			c.Context(),
			[]string{"remove-oauth-app", "app-test"},
			prompt,
			client,
			nil,
			nil,
			&stdout,
		)
		tc.Assert(c, err, tc.IsNil)
		tc.Check(c, client.deleteCalls, tc.Equals, 1)
		tc.Check(c, client.deleteID, tc.Equals, "app-test")
		_, statErr := os.Stat(configPath)
		tc.Check(c, os.IsNotExist(statErr), tc.IsTrue)
	})
}

// TestRemoveDeletesAppAndLocalCredentials checks the complete removal flow.
func (removeSuite) TestRemoveDeletesAppAndLocalCredentials(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, storedOAuthAppForID("app-test"))
	c.Assert(err, tc.IsNil)
	var stdout bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		secretValue:  "test-admin-token",
	}
	client := &fakeOAuthAppClient{}

	err = removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		configPath,
		&stdout,
	)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", stdout.String()))
	c.Assert(client.deleteCalls, tc.Equals, 1)
	c.Check(client.deleteID, tc.Equals, "app-test")
	c.Check(client.token, tc.Equals, "test-admin-token")
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	c.Check(stdout.String(), tc.Contains, "OAuth app app-test removed")
	c.Check(stdout.String(), tc.Contains, "Local credentials")
	c.Check(strings.Contains(stdout.String(), "test-admin-token"), tc.IsFalse)
}

// TestRemoveDeletesLegacyLocalCredentials checks that local cleanup still
// matches credentials saved before node attributes were allowlisted.
func (removeSuite) TestRemoveDeletesLegacyLocalCredentials(c *tc.C) {
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
	var stdout bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		secretValue:  "test-admin-token",
	}
	client := &fakeOAuthAppClient{}

	err = removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		configPath,
		&stdout,
	)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", stdout.String()))
	c.Check(client.deleteCalls, tc.Equals, 1)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	c.Check(stdout.String(), tc.Contains, "Local credentials")
}

// TestRemoveLeavesUnrelatedLocalCredentials checks ID matching.
func (removeSuite) TestRemoveLeavesUnrelatedLocalCredentials(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, storedOAuthAppForID("app-other"))
	c.Assert(err, tc.IsNil)
	var stdout bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		secretValue:  "test-admin-token",
	}
	client := &fakeOAuthAppClient{}

	err = removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		configPath,
		&stdout,
	)
	c.Assert(err, tc.IsNil)
	c.Assert(client.deleteCalls, tc.Equals, 1)
	_, statErr := os.Stat(configPath)
	c.Check(statErr, tc.IsNil)
	c.Check(stdout.String(), tc.Not(tc.Contains), "Local credentials")
}

// TestRemoveWithoutLocalCredentials checks removal without a saved app.
func (removeSuite) TestRemoveWithoutLocalCredentials(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var stdout bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		secretValue:  "test-admin-token",
	}
	client := &fakeOAuthAppClient{}

	err := removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		configPath,
		&stdout,
	)
	c.Assert(err, tc.IsNil)
	c.Assert(client.deleteCalls, tc.Equals, 1)
	c.Check(stdout.String(), tc.Not(tc.Contains), "Local credentials")
}

// TestRemovePropagatesAPIError checks that deletion failures surface.
func (removeSuite) TestRemovePropagatesAPIError(c *tc.C) {
	var stdout bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		secretValue:  "test-admin-token",
	}
	deleteErr := errors.New("test removal failure")
	client := &fakeOAuthAppClient{deleteErr: deleteErr}

	err := removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		filepath.Join(c.MkDir(), "oauth-app.json"),
		&stdout,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err, tc.ErrorIs, deleteErr)
}

// TestRemoveCanBeCancelled checks that declining confirmation changes nothing.
func (removeSuite) TestRemoveCanBeCancelled(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := saveOAuthApp(configPath, storedOAuthAppForID("app-test"))
	c.Assert(err, tc.IsNil)
	var stdout bytes.Buffer
	prompt := &fakePrompter{confirmation: false}
	client := &fakeOAuthAppClient{}

	err = removeOAuthApp(
		c.Context(),
		prompt,
		client,
		"app-test",
		configPath,
		&stdout,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "cancelled")
	c.Check(client.deleteCalls, tc.Equals, 0)
	_, statErr := os.Stat(configPath)
	c.Check(statErr, tc.IsNil)
}
