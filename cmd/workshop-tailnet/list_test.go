package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/juju/tc"
)

// listSuite tests the interactive OAuth app listing command.
type listSuite struct{}

// TestListSuite registers the OAuth app listing tests.
func TestListSuite(t *testing.T) {
	tc.Run(t, &listSuite{})
}

// TestListCommandWritesApps checks command dispatch, prompts, and output.
func (listSuite) TestListCommandWritesApps(c *tc.C) {
	var stdout bytes.Buffer
	prompt := &fakePrompter{secretValue: "test-admin-token"}
	client := &fakeOAuthAppClient{
		listApps: []oauthApp{
			{
				ID:           "app-test",
				Name:         defaultAppName,
				RedirectURIs: []string{defaultRedirectURI},
				Scopes:       []string{provisioningScope},
			},
		},
	}

	err := run(
		c.Context(),
		[]string{"list-oauth-apps"},
		prompt,
		client,
		nil,
		&stdout,
	)
	c.Assert(err, tc.IsNil)
	c.Assert(client.listCalls, tc.Equals, 1)
	c.Check(client.token, tc.Equals, "test-admin-token")
	output := stdout.String()
	c.Check(output, tc.Contains, "Client ID: app-test")
	c.Check(output, tc.Contains, defaultAppName)
	c.Check(output, tc.Contains, defaultRedirectURI)
	c.Check(output, tc.Contains, provisioningScope)
	c.Check(strings.Contains(output, "test-admin-token"), tc.IsFalse)
}

// TestListCommandWritesNoApps checks the empty tailnet output.
func (listSuite) TestListCommandWritesNoApps(c *tc.C) {
	var stdout bytes.Buffer
	prompt := &fakePrompter{secretValue: "test-admin-token"}
	client := &fakeOAuthAppClient{}

	err := run(
		c.Context(),
		[]string{"list-oauth-apps"},
		prompt,
		client,
		nil,
		&stdout,
	)
	c.Assert(err, tc.IsNil)
	c.Assert(client.listCalls, tc.Equals, 1)
	c.Check(stdout.String(), tc.Contains, "No OAuth apps found.")
}

// TestListCommandPropagatesAPIError checks that listing failures surface.
func (listSuite) TestListCommandPropagatesAPIError(c *tc.C) {
	var stdout bytes.Buffer
	prompt := &fakePrompter{secretValue: "test-admin-token"}
	client := &fakeOAuthAppClient{
		listErr: errUsage,
	}

	err := run(
		c.Context(),
		[]string{"list-oauth-apps"},
		prompt,
		client,
		nil,
		&stdout,
	)
	c.Assert(err, tc.NotNil)
	c.Check(err, tc.ErrorIs, errUsage)
}
