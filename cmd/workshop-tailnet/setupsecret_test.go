package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juju/tc"
	"gopkg.in/yaml.v2"
)

// setupSecretSuite tests keyring storage and private-file fallback.
type setupSecretSuite struct{}

// checkSetupSecret checks that saved JSON contains the complete OAuth app.
func checkSetupSecret(c *tc.C, encoded []byte, name, secret string) {
	var stored storedOAuthApp
	err := json.Unmarshal(encoded, &stored)
	c.Assert(err, tc.IsNil)
	c.Check(stored, tc.DeepEquals, storedOAuthApp{
		AllowedNodeAttributes: provisioningNodeAttributeNames,
		ClientID:              "app-test",
		ClientSecret:          secret,
		Name:                  name,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	})
}

// checkSetupSecretYAML checks the slot YAML and explicit connection command.
func checkSetupSecretYAML(c *tc.C, output, name string) {
	start := strings.Index(output, "sdks:\n")
	c.Assert(start >= 0, tc.IsTrue)
	fragment, _, found := strings.Cut(
		output[start:],
		"\nConnect the secret explicitly",
	)
	c.Assert(found, tc.IsTrue)
	var document struct {
		SDKs []struct {
			Name  string `yaml:"name"`
			Slots map[string]struct {
				Attributes map[string]string `yaml:"attributes"`
				Collection string            `yaml:"collection"`
				Interface  string            `yaml:"interface"`
			} `yaml:"slots"`
		} `yaml:"sdks"`
	}
	err := yaml.UnmarshalStrict([]byte(fragment), &document)
	c.Assert(err, tc.IsNil)
	c.Assert(document.SDKs, tc.HasLen, 1)
	c.Check(document.SDKs[0].Name, tc.Equals, "system")
	c.Assert(document.SDKs[0].Slots, tc.HasLen, 1)
	slot, found := document.SDKs[0].Slots["tailscale-oauth-app"]
	c.Assert(found, tc.IsTrue)
	c.Check(slot.Interface, tc.Equals, "secret")
	c.Check(slot.Collection, tc.Equals, "default")
	c.Check(slot.Attributes, tc.DeepEquals, map[string]string{
		"app":     name,
		"service": "tailscale.com/workshop/oauth-app",
	})
	c.Check(
		output,
		tc.Contains,
		"workshop connect WORKSHOP/tailscale:tailscale-oauth-app",
	)
}

// setupSecretPrompt supplies consistent app configuration and confirmation.
func setupSecretPrompt(name string) *fakePrompter {
	return &fakePrompter{
		confirmation: true,
		inputs:       []string{name, defaultRedirectURI},
		secretValue:  "test-admin-token",
	}
}

// TestSetupSecretSuite registers keyring setup and fallback behaviour tests.
func TestSetupSecretSuite(t *testing.T) {
	tc.Run(t, &setupSecretSuite{})
}

// TestBothStoresFail checks one-time recovery and preserves an existing file.
func (setupSecretSuite) TestBothStoresFail(c *tc.C) {
	const secret = "one-time-client-secret"
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	err := os.WriteFile(configPath, []byte("existing credentials"), 0o600)
	c.Assert(err, tc.IsNil)
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getApp:    verifiedApp(),
	}
	store := &fakeSecretStore{storeErr: errors.New("keyring locked")}
	var output bytes.Buffer

	err = setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(store.lookupCalls, tc.Equals, 1)
	c.Check(client.createCalls, tc.Equals, 1)
	c.Check(store.storeCalls, tc.Equals, 1)
	contents, readErr := os.ReadFile(configPath)
	c.Assert(readErr, tc.IsNil)
	c.Check(string(contents), tc.Equals, "existing credentials")
	c.Check(output.String(), tc.Contains, "only once")
	c.Check(output.String(), tc.Contains, "Store it securely now")
	c.Check(output.String(), tc.Contains, "Client ID: app-test")
	c.Check(output.String(), tc.Contains, "Client secret: "+secret)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
	c.Check(strings.Contains(output.String(), "sdks:\n"), tc.IsFalse)
}

// TestCancellation checks that declining creation leaves both stores untouched.
func (setupSecretSuite) TestCancellation(c *tc.C) {
	prompt := setupSecretPrompt(defaultAppName)
	prompt.confirmation = false
	client := &fakeOAuthAppClient{}
	store := &fakeSecretStore{}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "cancelled")
	c.Check(client.createCalls, tc.Equals, 0)
	c.Check(client.getCalls, tc.Equals, 0)
	c.Check(store.storeCalls, tc.Equals, 0)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
}

// TestCommandUsesSecretStore checks setup dispatch with an injected keyring.
func (setupSecretSuite) TestCommandUsesSecretStore(c *tc.C) {
	c.Run("setup", func(c *testing.T) {
		configRoot := c.TempDir()
		c.Setenv("XDG_CONFIG_HOME", configRoot)
		prompt := setupSecretPrompt(defaultAppName)
		client := &fakeOAuthAppClient{
			createApp: createdApp("command-client-secret"),
			getApp:    verifiedApp(),
		}
		store := &fakeSecretStore{}
		var output bytes.Buffer

		err := run(
			c.Context(),
			[]string{"setup"},
			prompt,
			client,
			nil,
			store,
			&output,
		)
		tc.Assert(c, err, tc.IsNil)
		tc.Check(c, store.lookupCalls, tc.Equals, 1)
		tc.Check(c, store.storeCalls, tc.Equals, 1)
		tc.Check(c, output.String(), tc.Contains, "sdks:\n")
	})
}

// TestCreationMetadata checks that unchecked response names cannot redirect
// storage and that omitted metadata does not produce incomplete credentials.
func (setupSecretSuite) TestCreationMetadata(c *tc.C) {
	for _, name := range []string{"", "another-existing-app"} {
		c.Run("returned name "+name, func(c *testing.T) {
			const secret = "creation-response-secret"
			prompt := setupSecretPrompt(defaultAppName)
			created := createdApp(secret)
			created.Name = name
			created.RedirectURIs = nil
			created.Scopes = nil
			client := &fakeOAuthAppClient{
				createApp: created,
				getApp:    verifiedApp(),
			}
			store := &fakeSecretStore{}
			configPath := filepath.Join(c.TempDir(), "oauth-app.json")
			var output bytes.Buffer

			err := setup(
				c.Context(),
				prompt,
				client,
				store,
				configPath,
				&output,
			)
			tc.Assert(c, err, tc.IsNil)
			tc.Check(
				c,
				store.storeArgs.Attributes,
				tc.DeepEquals,
				store.attributes,
			)
			tc.Check(c, store.attributes["app"], tc.Equals, defaultAppName)
			var stored storedOAuthApp
			err = json.Unmarshal(store.storeArgs.Secret, &stored)
			tc.Assert(c, err, tc.IsNil)
			tc.Check(c, stored, tc.DeepEquals, storedOAuthApp{
				AllowedNodeAttributes: provisioningNodeAttributeNames,
				ClientID:              "app-test",
				ClientSecret:          secret,
				Name:                  defaultAppName,
				RedirectURIs:          []string{defaultRedirectURI},
				Scopes:                []string{provisioningScope},
			})
		})
	}
}

// TestExistingSecret checks that matching credentials prevent remote creation.
func (setupSecretSuite) TestExistingSecret(c *tc.C) {
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{}
	store := &fakeSecretStore{exists: true}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err.Error(), tc.Contains, "already exists")
	c.Check(store.lookupCalls, tc.Equals, 1)
	c.Check(store.attributes, tc.DeepEquals, map[string]string{
		"app":     defaultAppName,
		"service": "tailscale.com/workshop/oauth-app",
	})
	c.Check(client.createCalls, tc.Equals, 0)
	c.Check(client.getCalls, tc.Equals, 0)
	c.Check(store.storeCalls, tc.Equals, 0)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
}

// TestLookupFailure checks private-file fallback without a keyring store call.
func (setupSecretSuite) TestLookupFailure(c *tc.C) {
	const secret = "lookup-fallback-secret"
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getApp:    verifiedApp(),
	}
	store := &fakeSecretStore{lookupErr: errors.New("keyring unavailable")}
	configPath := filepath.Join(c.MkDir(), "config", "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.IsNil)
	c.Check(store.lookupCalls, tc.Equals, 1)
	c.Check(store.storeCalls, tc.Equals, 0)
	c.Check(client.createCalls, tc.Equals, 1)
	c.Check(client.getCalls, tc.Equals, 1)
	encoded, err := os.ReadFile(configPath)
	c.Assert(err, tc.IsNil)
	checkSetupSecret(c, encoded, defaultAppName, secret)
	c.Check(bytes.Contains(encoded, []byte(prompt.secretValue)), tc.IsFalse)
	info, err := os.Stat(configPath)
	c.Assert(err, tc.IsNil)
	c.Check(info.Mode().Perm(), tc.Equals, os.FileMode(0o600))
	directory, err := os.Stat(filepath.Dir(configPath))
	c.Assert(err, tc.IsNil)
	c.Check(directory.Mode().Perm(), tc.Equals, os.FileMode(0o700))
	c.Check(output.String(), tc.Contains, "falling back")
	c.Check(strings.Contains(output.String(), "sdks:\n"), tc.IsFalse)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
}

// TestStoreFailure checks that a failed keyring save retains private JSON.
func (setupSecretSuite) TestStoreFailure(c *tc.C) {
	const secret = "store-fallback-secret"
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getApp:    verifiedApp(),
	}
	store := &fakeSecretStore{storeErr: errors.New("keyring locked")}
	configPath := filepath.Join(c.MkDir(), "config", "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.IsNil)
	c.Check(store.lookupCalls, tc.Equals, 1)
	c.Check(store.storeCalls, tc.Equals, 1)
	c.Check(client.createCalls, tc.Equals, 1)
	c.Check(client.getCalls, tc.Equals, 1)
	encoded, err := os.ReadFile(configPath)
	c.Assert(err, tc.IsNil)
	checkSetupSecret(c, encoded, defaultAppName, secret)
	info, err := os.Stat(configPath)
	c.Assert(err, tc.IsNil)
	c.Check(info.Mode().Perm(), tc.Equals, os.FileMode(0o600))
	directory, err := os.Stat(filepath.Dir(configPath))
	c.Assert(err, tc.IsNil)
	c.Check(directory.Mode().Perm(), tc.Equals, os.FileMode(0o700))
	c.Check(strings.Contains(output.String(), "sdks:\n"), tc.IsFalse)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
}

// TestSuccess checks keyring metadata, complete JSON and safe setup guidance.
func (setupSecretSuite) TestSuccess(c *tc.C) {
	const secret = "keyring-client-secret"
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getApp:    verifiedApp(),
	}
	store := &fakeSecretStore{}
	configPath := filepath.Join(c.MkDir(), "config", "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.IsNil)
	c.Check(client.createCalls, tc.Equals, 1)
	c.Check(client.getCalls, tc.Equals, 1)
	c.Check(client.token, tc.Equals, prompt.secretValue)
	c.Check(client.createArgs, tc.DeepEquals, CreateOAuthAppArgs{
		AllowedNodeAttributes: provisioningNodeAttributeNames,
		Name:                  defaultAppName,
		RedirectURIs:          []string{defaultRedirectURI},
		Scopes:                []string{provisioningScope},
	})
	c.Check(store.lookupCalls, tc.Equals, 1)
	c.Check(store.storeCalls, tc.Equals, 1)
	expectedAttributes := map[string]string{
		"app":     defaultAppName,
		"service": "tailscale.com/workshop/oauth-app",
	}
	c.Check(store.attributes, tc.DeepEquals, expectedAttributes)
	c.Check(store.storeArgs.Attributes, tc.DeepEquals, expectedAttributes)
	c.Check(
		store.storeArgs.Label,
		tc.Equals,
		"Workshop Tailscale OAuth app: "+defaultAppName,
	)
	checkSetupSecret(c, store.storeArgs.Secret, defaultAppName, secret)
	c.Check(
		bytes.Contains(store.storeArgs.Secret, []byte(prompt.secretValue)),
		tc.IsFalse,
	)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
	checkSetupSecretYAML(c, output.String(), defaultAppName)
}

// TestVerificationFailure checks that saved keyring credentials remain usable.
func (setupSecretSuite) TestVerificationFailure(c *tc.C) {
	const secret = "saved-before-verification-secret"
	cause := errors.New("verification unavailable")
	prompt := setupSecretPrompt(defaultAppName)
	client := &fakeOAuthAppClient{
		createApp: createdApp(secret),
		getErr:    cause,
	}
	store := &fakeSecretStore{}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.NotNil)
	c.Check(err, tc.ErrorIs, cause)
	c.Check(err.Error(), tc.Contains, "credentials were saved")
	c.Check(client.createCalls, tc.Equals, 1)
	c.Check(client.getCalls, tc.Equals, 1)
	c.Check(client.deleteCalls, tc.Equals, 0)
	c.Check(store.storeCalls, tc.Equals, 1)
	checkSetupSecret(c, store.storeArgs.Secret, defaultAppName, secret)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
}

// TestYAMLEscaping checks that special app names survive YAML round-tripping.
func (setupSecretSuite) TestYAMLEscaping(c *tc.C) {
	const (
		name   = "Workshop \"quoted\": app\nsecond line"
		secret = "special-name-client-secret"
	)
	prompt := setupSecretPrompt(name)
	created := createdApp(secret)
	created.Name = name
	verified := verifiedApp()
	verified.Name = name
	client := &fakeOAuthAppClient{createApp: created, getApp: verified}
	store := &fakeSecretStore{}
	configPath := filepath.Join(c.MkDir(), "oauth-app.json")
	var output bytes.Buffer

	err := setup(c.Context(), prompt, client, store, configPath, &output)
	c.Assert(err, tc.IsNil)
	c.Check(client.createArgs.Name, tc.Equals, name)
	c.Check(store.attributes["app"], tc.Equals, name)
	c.Check(store.storeArgs.Attributes["app"], tc.Equals, name)
	c.Check(
		store.storeArgs.Label,
		tc.Equals,
		"Workshop Tailscale OAuth app: "+name,
	)
	checkSetupSecret(c, store.storeArgs.Secret, name, secret)
	_, statErr := os.Stat(configPath)
	c.Check(os.IsNotExist(statErr), tc.IsTrue)
	c.Check(strings.Contains(output.String(), secret), tc.IsFalse)
	c.Check(strings.Contains(output.String(), prompt.secretValue), tc.IsFalse)
	checkSetupSecretYAML(c, output.String(), name)
}
