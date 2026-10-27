package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juju/tc"
)

// setupSuite tests the interactive OAuth app registration workflow.
type setupSuite struct{}

const oauthAppsPath = "/api/v2/tailnet/-/oauth-apps"

func createdApp(secret string) OAuthApp {
	return OAuthApp{
		AllowedNodeAttributes: []string{defaultNodeAttribute},
		ClientSecret:          secret,
		ID:                    "app-test",
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	}
}

func verifiedApp() OAuthApp {
	return OAuthApp{
		AllowedNodeAttributes: []string{defaultNodeAttribute},
		ClientSecret:          "",
		ID:                    "app-test",
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	}
}

// TestSetupSuite registers the interactive setup behaviour tests.
func TestSetupSuite(t *testing.T) {
	tc.Run(t, &setupSuite{})
}

// TestParseNodeAttributes checks splitting, trimming, automatic prefix
// removal, and empty-value handling for attribute input.
func (setupSuite) TestParseNodeAttributes(c *tc.C) {
	c.Check(
		parseNodeAttributes("ci, staging"),
		tc.DeepEquals,
		[]string{"ci", "staging"},
	)
	c.Check(
		parseNodeAttributes(" custom:ci ,, x "),
		tc.DeepEquals,
		[]string{"ci", "x"},
	)
	c.Check(parseNodeAttributes(""), tc.DeepEquals, []string(nil))
	c.Check(parseNodeAttributes(" , ,"), tc.DeepEquals, []string(nil))
}

// TestPrompterSecretErrorIncludesLabel checks contextual secret read errors.
func (setupSuite) TestPrompterSecretErrorIncludesLabel(c *tc.C) {
	cause := errors.New("test read failure")
	readSecret := func() (string, error) {
		return "", fmt.Errorf("reading secret: %w", cause)
	}
	var output bytes.Buffer
	prompt := newInteractivePrompter(nil, &output, readSecret)

	value, err := prompt.Secret("Tailscale admin API token")
	c.Assert(err, tc.NotNil)
	c.Check(value, tc.Equals, "")
	c.Check(err, tc.ErrorIs, cause)
	c.Check(err.Error(), tc.Contains, "Tailscale admin API token")
	c.Check(err.Error(), tc.Contains, "reading secret")
}

// TestRunHelpAndUnknownCommand checks command dispatch and returned errors.
func (setupSuite) TestRunHelpAndUnknownCommand(c *tc.C) {
	var stdout bytes.Buffer
	err := run(c.Context(), []string{"--help"}, nil, nil, nil, nil, &stdout)
	c.Assert(err, tc.IsNil)
	c.Check(stdout.String(), tc.Contains, "setup")

	stdout.Reset()
	err = run(c.Context(), []string{"unknown"}, nil, nil, nil, nil, &stdout)
	c.Check(err, tc.ErrorIs, errUsage)
}

// TestRunRejectsInvalidArguments checks command argument counts.
func (setupSuite) TestRunRejectsInvalidArguments(c *tc.C) {
	tests := []struct {
		args []string
		name string
	}{
		{name: "no command"},
		{
			args: []string{"setup", "extra"},
			name: "setup extra argument",
		},
		{
			args: []string{"authenticate", "extra"},
			name: "authenticate extra argument",
		},
		{
			args: []string{"list-oauth-apps", "extra"},
			name: "list extra argument",
		},
		{
			args: []string{"remove-oauth-app"},
			name: "remove missing ID",
		},
		{
			args: []string{"remove-oauth-app", "app-test", "extra"},
			name: "remove extra argument",
		},
	}
	for _, test := range tests {
		c.Run(test.name, func(c *testing.T) {
			var stdout bytes.Buffer
			err := run(
				c.Context(),
				test.args,
				nil,
				nil,
				nil,
				nil,
				&stdout,
			)
			tc.Check(c, err, tc.ErrorIs, errUsage)
			tc.Check(c, stdout.String(), tc.Equals, "")
		})
	}
}

// TestSetupCanBeCancelled checks that declining confirmation changes nothing.
func (setupSuite) TestSetupCanBeCancelled(c *tc.C) {
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: false,
		inputs:       []string{defaultAppName, defaultRedirectURI, ""},
		secretValue:  "test-token",
	}
	client := &fakeOAuthAppClient{}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "cancelled")
	c.Check(client.createCalls, tc.Equals, 0)
	c.Check(client.getCalls, tc.Equals, 0)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
}

// TestSetupCreatesVerifiesAndStoresOAuthApp checks the complete setup flow.
func (setupSuite) TestSetupCreatesVerifiesAndStoresOAuthApp(c *tc.C) {
	const (
		token  = "test-admin-token"
		secret = "test-client-secret"
	)
	configPath := filepath.Join(c.MkDir(), "config", "oauth-app.json")
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs:       []string{defaultAppName, defaultRedirectURI, ""},
		secretValue:  token,
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getApp:    verifiedApp(),
	}

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", output.String()))
	c.Assert(client.createCalls, tc.Equals, 1)
	c.Assert(client.getCalls, tc.Equals, 1)
	c.Check(client.token, tc.Equals, token)
	c.Check(client.createArgs, tc.DeepEquals, CreateOAuthAppArgs{
		AllowedNodeAttributes: []string{defaultNodeAttribute},
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	})

	encoded, err := os.ReadFile(configPath)
	c.Assert(err, tc.IsNil)
	var stored storedOAuthApp
	err = json.Unmarshal(encoded, &stored)
	c.Assert(err, tc.IsNil)
	expected := storedOAuthApp{
		AllowedNodeAttributes: []string{defaultNodeAttribute},
		ClientID:              "app-test",
		ClientSecret:          secret,
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	}
	c.Check(stored, tc.DeepEquals, expected)
	c.Check(bytes.Contains(encoded, []byte(token)), tc.IsFalse)
	info, err := os.Stat(configPath)
	c.Assert(err, tc.IsNil)
	c.Check(info.Mode().Perm(), tc.Equals, os.FileMode(0o600))
	directoryInfo, err := os.Stat(filepath.Dir(configPath))
	c.Assert(err, tc.IsNil)
	c.Check(directoryInfo.Mode().Perm(), tc.Equals, os.FileMode(0o700))
	c.Check(strings.Contains(output.String(), token), tc.IsFalse)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(output.String(), tc.Contains, "is ready for Workshop")
}

// TestSetupDetectsVerificationMismatch checks that setup rejects drift.
func (setupSuite) TestSetupDetectsVerificationMismatch(c *tc.C) {
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs:       []string{defaultAppName, defaultRedirectURI, ""},
		secretValue:  "token",
	}
	verified := verifiedApp()
	verified.RedirectURIs = []string{"https://example.com/callback"}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getApp:    verified,
	}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "did not match")
	_, statErr := os.Stat(configPath)
	c.Check(statErr, tc.IsNil)
}

// TestSetupPromptsForNodeAttributes checks that setup offers a
// comma-separated node attribute list with the workshop attribute as the
// default.
func (setupSuite) TestSetupPromptsForNodeAttributes(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs: []string{
			defaultAppName,
			defaultRedirectURI,
			" workshop, custom:ci , staging, ",
		},
		secretValue: "test-admin-token",
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getApp:    verifiedApp(),
	}

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", output.String()))
	c.Check(
		client.createArgs.AllowedNodeAttributes,
		tc.DeepEquals,
		[]string{defaultNodeAttribute, "ci", "staging"},
	)
	c.Check(output.String(), tc.Contains, "workshop, ci, staging")
}

// TestSetupDefaultsNodeAttributes checks that accepting the prompt default
// allowlists only the workshop attribute.
func (setupSuite) TestSetupDefaultsNodeAttributes(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs: []string{
			defaultAppName,
			defaultRedirectURI,
			defaultNodeAttribute,
		},
		secretValue: "test-admin-token",
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getApp:    verifiedApp(),
	}

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", output.String()))
	c.Check(
		client.createArgs.AllowedNodeAttributes,
		tc.DeepEquals,
		[]string{defaultNodeAttribute},
	)
}

// TestSetupOverridesDefaultNodeAttribute checks that setup accepts an
// attribute list without the workshop attribute.
func (setupSuite) TestSetupOverridesDefaultNodeAttribute(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs: []string{
			defaultAppName,
			defaultRedirectURI,
			"ci, staging",
		},
		secretValue: "test-admin-token",
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getApp:    verifiedApp(),
	}

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.IsNil, tc.Commentf("output:\n%s", output.String()))
	c.Check(
		client.createArgs.AllowedNodeAttributes,
		tc.DeepEquals,
		[]string{"ci", "staging"},
	)
}

// TestSetupRejectsExistingCredentials checks that setup cannot overwrite them.
func (setupSuite) TestSetupRejectsExistingCredentials(c *tc.C) {
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := os.WriteFile(configPath, []byte("existing"), 0o600)
	c.Assert(err, tc.IsNil)
	var output bytes.Buffer
	prompt := &fakePrompter{}

	err = setup(c.Context(), prompt, nil, nil, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "already exists")
	contents, err := os.ReadFile(configPath)
	c.Assert(err, tc.IsNil)
	c.Check(string(contents), tc.Equals, "existing")
}

// TestSetupRetriesInvalidRedirectURI checks validation before any API call.
func (setupSuite) TestSetupRetriesInvalidRedirectURI(c *tc.C) {
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs: []string{
			defaultAppName,
			"http://example.com/callback",
			defaultRedirectURI,
			"",
		},
		secretValue: "test-token",
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getApp:    verifiedApp(),
	}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.IsNil)
	c.Check(output.String(), tc.Contains, "only allowed for loopback")
}

// TestSetupVerificationFailurePreservesCredentials checks secret recovery.
func (setupSuite) TestSetupVerificationFailurePreservesCredentials(c *tc.C) {
	var output bytes.Buffer
	prompt := &fakePrompter{
		confirmation: true,
		inputs:       []string{defaultAppName, defaultRedirectURI, ""},
		secretValue:  "token",
	}
	client := &fakeOAuthAppClient{
		createApp: createdApp("test-secret"),
		getErr:    errors.New("test verification failure"),
	}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")

	err := setup(c.Context(), prompt, client, nil, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "credentials were saved")
	_, statErr := os.Stat(configPath)
	c.Check(statErr, tc.IsNil)
}

// TestValidateRedirectURI checks accepted callbacks and malformed URIs.
func (setupSuite) TestValidateRedirectURI(c *tc.C) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "loopback HTTP", value: "http://127.0.0.1:8765/callback"},
		{name: "localhost HTTP", value: "http://localhost/callback"},
		{name: "IPv6 loopback", value: "http://[::1]:8765/callback"},
		{name: "hosted HTTPS", value: "https://workshop.example.com/cb"},
		{name: "relative", value: "/callback", wantErr: true},
		{name: "external HTTP", value: "http://example.com/cb", wantErr: true},
		{name: "other scheme", value: "ftp://example.com/cb", wantErr: true},
		{name: "query", value: "https://example.com/cb?q=v", wantErr: true},
		{name: "fragment", value: "https://example.com/cb#f", wantErr: true},
		{name: "user info", value: "https://user@example.com/cb", wantErr: true},
	}
	for _, test := range tests {
		c.Run(test.name, func(c *testing.T) {
			err := validateRedirectURI(test.value)
			if test.wantErr {
				tc.Check(c, err, tc.NotNil)
				return
			}
			tc.Check(c, err, tc.IsNil)
		})
	}
}
