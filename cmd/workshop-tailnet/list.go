package main

import (
	"context"
	"fmt"
	"io"
)

func listOAuthApps(
	ctx context.Context,
	prompt Prompter,
	client OAuthAppClient,
	out io.Writer,
) error {
	fmt.Fprint(
		out,
		`List the OAuth apps in your tailnet.
You need a Tailscale Owner or Admin API access token.
The token is used for this listing only and is not saved.

`,
	)

	token, err := prompt.Secret("Tailscale admin API token")
	if err != nil {
		return err
	}
	apps, err := client.ListOAuthApps(ctx, token)
	if err != nil {
		return err
	}
	if len(apps) == 0 {
		fmt.Fprintln(out, "No OAuth apps found.")
		return nil
	}

	for _, app := range apps {
		fmt.Fprintf(
			out,
			`
Client ID: %s
  Name:         %s
`,
			app.ID,
			app.Name,
		)
		for _, redirectURI := range app.RedirectURIs {
			fmt.Fprintf(out, "  Redirect URI: %s\n", redirectURI)
		}
		for _, scope := range app.Scopes {
			fmt.Fprintf(out, "  Scope:        %s\n", scope)
		}
	}
	return nil
}
