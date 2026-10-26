package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// CreateOAuthAppArgs describes the OAuth app to register.
type CreateOAuthAppArgs struct {
	// Name is the app's display name.
	Name string

	// RedirectURIs lists the permitted OAuth callback URIs.
	RedirectURIs []string

	// Scopes lists the permissions requested by the app.
	Scopes []string
}

// OAuthApp describes a registered OAuth app.
type OAuthApp struct {
	// ClientSecret is returned when the app is created and omitted later.
	ClientSecret string

	// ID identifies the app.
	ID string

	// Name is the app's display name.
	Name string

	// RedirectURIs lists the permitted OAuth callback URIs.
	RedirectURIs []string

	// Scopes lists the permissions granted to the app.
	Scopes []string
}

// OAuthAppClient manages Tailscale OAuth apps for device provisioning.
type OAuthAppClient interface {
	// CreateOAuthApp registers an app with the supplied configuration.
	CreateOAuthApp(
		ctx context.Context,
		token string,
		args CreateOAuthAppArgs,
	) (OAuthApp, error)

	// DeleteOAuthApp removes an OAuth app from the tailnet. An app that is
	// already absent is treated as removed.
	DeleteOAuthApp(ctx context.Context, token string, id string) error

	// GetOAuthApp retrieves an app so its configuration can be verified.
	GetOAuthApp(
		ctx context.Context,
		token string,
		id string,
	) (OAuthApp, error)

	// ListOAuthApps lists every OAuth app in the tailnet.
	ListOAuthApps(ctx context.Context, token string) ([]OAuthApp, error)
}

type storedOAuthApp struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

const (
	defaultAppName     = "Canonical-Workshop"
	defaultRedirectURI = "http://127.0.0.1:8765/callback"
)

func promptRedirectURI(prompt Prompter, out io.Writer) (string, error) {
	for {
		value, err := prompt.Input(
			"OAuth redirect URI",
			defaultRedirectURI,
		)
		if err != nil {
			return "", err
		}
		err = validateRedirectURI(value)
		if err == nil {
			return value, nil
		}
		fmt.Fprintf(out, "Invalid redirect URI: %v\n", err)
	}
}

func saveOAuthApp(path string, app storedOAuthApp) error {
	encoded, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding credentials: %w", err)
	}
	encoded = append(encoded, '\n')
	return writePrivateFile(path, encoded)
}

func setup(
	ctx context.Context,
	prompt Prompter,
	client OAuthAppClient,
	configPath string,
	out io.Writer,
) error {
	fmt.Fprint(
		out,
		`Configure a tailnet for Workshop device provisioning.
You need a Tailscale Owner or Admin API access token.
The token is used for this setup only and is not saved.

`,
	)

	_, err := os.Stat(configPath)
	if err == nil {
		return fmt.Errorf(
			"credentials file %s already exists; move it away before "+
				"registering another app",
			configPath,
		)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking credentials file: %w", err)
	}

	token, err := prompt.Secret("Tailscale admin API token")
	if err != nil {
		return err
	}
	name, err := prompt.Input("OAuth app name", defaultAppName)
	if err != nil {
		return err
	}
	redirectURI, err := promptRedirectURI(prompt, out)
	if err != nil {
		return err
	}

	fmt.Fprintf(
		out,
		`
Tailscale will create an OAuth app with:
  Name:         %s
  Redirect URI: %s
  Scope:        %s
`,
		name,
		redirectURI,
		provisioningScope,
	)

	confirmed, err := prompt.Confirm("Create this OAuth app?", true)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("setup cancelled")
	}

	args := CreateOAuthAppArgs{
		Name:         name,
		RedirectURIs: []string{redirectURI},
		Scopes:       []string{provisioningScope},
	}
	app, err := client.CreateOAuthApp(ctx, token, args)
	if err != nil {
		return err
	}

	stored := storedOAuthApp{
		ClientID:     app.ID,
		ClientSecret: app.ClientSecret,
		Name:         app.Name,
		RedirectURIs: app.RedirectURIs,
		Scopes:       app.Scopes,
	}
	err = saveOAuthApp(configPath, stored)
	if err != nil {
		fmt.Fprintf(
			out,
			`
The OAuth app was created, but its credentials could not be saved: %v
Tailscale shows this client secret only once. Store it securely now:
Client ID: %s
Client secret: %s
`,
			err,
			app.ID,
			app.ClientSecret,
		)
		return fmt.Errorf("saving OAuth app credentials: %w", err)
	}

	verified, err := client.GetOAuthApp(ctx, token, app.ID)
	if err != nil {
		return fmt.Errorf(
			"verifying OAuth app (credentials were saved to %s): %w",
			configPath,
			err,
		)
	}
	matches := verified.ID == app.ID &&
		verified.Name == name &&
		sameStrings(verified.RedirectURIs, []string{redirectURI}) &&
		sameStrings(verified.Scopes, []string{provisioningScope})
	if !matches {
		return fmt.Errorf(
			"credentials were saved to %s, but the verified OAuth app "+
				"configuration did not match the requested configuration",
			configPath,
		)
	}

	fmt.Fprintf(
		out,
		`
OAuth app %q is ready for Workshop device provisioning.
Client ID: %s
Credentials saved to %s (mode 0600).
`,
		app.Name,
		app.ID,
		configPath,
	)
	return nil
}

func writePrivateFile(path string, contents []byte) (returnErr error) {
	directory := filepath.Dir(path)
	err := os.MkdirAll(directory, 0o700)
	if err != nil {
		return fmt.Errorf("creating configuration directory: %w", err)
	}
	err = os.Chmod(directory, 0o700)
	if err != nil {
		return fmt.Errorf("securing configuration directory: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".workshop-tailnet-*")
	if err != nil {
		return fmt.Errorf(
			"creating temporary credentials file: %w",
			err,
		)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	err = temporary.Chmod(0o600)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf(
			"securing temporary credentials file: %w",
			err,
		)
	}
	_, err = temporary.Write(contents)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("writing credentials: %w", err)
	}
	err = temporary.Sync()
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("syncing credentials: %w", err)
	}
	err = temporary.Close()
	if err != nil {
		return fmt.Errorf("closing credentials: %w", err)
	}
	err = os.Rename(temporaryPath, path)
	if err != nil {
		return fmt.Errorf("installing credentials file: %w", err)
	}
	return nil
}
