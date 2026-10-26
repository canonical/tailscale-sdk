package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
)

type credentialLocation struct {
	description   string
	secretService bool
}

const oauthAppSecretService = "tailscale.com/workshop/oauth-app"

func checkOAuthAppFile(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf(
			"credentials file %s already exists; move it away before "+
				"registering another app",
			path,
		)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking credentials file: %w", err)
	}
	return nil
}

func encodeOAuthApp(app storedOAuthApp) ([]byte, error) {
	encoded, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding credentials: %w", err)
	}
	return append(encoded, '\n'), nil
}

func oauthAppSecretAttributes(name string) map[string]string {
	return map[string]string{
		"app":     name,
		"service": oauthAppSecretService,
	}
}

func prepareOAuthAppStore(
	ctx context.Context,
	store SecretStore,
	name string,
	configPath string,
	out io.Writer,
) (SecretStore, error) {
	if store == nil {
		return nil, nil
	}
	exists, err := store.Lookup(ctx, oauthAppSecretAttributes(name))
	if err != nil {
		fmt.Fprint(
			out,
			`Secret Service lookup failed; falling back to a private file.
No existing keyring item will be changed.

`,
		)
		err = checkOAuthAppFile(configPath)
		if err != nil {
			return nil, err
		}
		return nil, nil
	} else if exists {
		return nil, fmt.Errorf(
			"OAuth app secret for %q already exists; use another app "+
				"name or remove the existing secret first",
			name,
		)
	}
	return store, nil
}

func printOAuthAppSecretSlot(out io.Writer, name string) {
	fmt.Fprintf(
		out,
		`
Merge this slot into the system SDK entry in your workshop definition:

sdks:
  - name: system
    slots:
      tailscale-oauth-app:
        interface: secret
        collection: default
        attributes:
          service: %s
          app: %s

Connect the secret explicitly (replace WORKSHOP with your workshop name):
  workshop connect WORKSHOP/tailscale:tailscale-oauth-app \
    WORKSHOP/system:tailscale-oauth-app
`,
		strconv.Quote(oauthAppSecretService),
		strconv.Quote(name),
	)
}

func storeOAuthApp(
	ctx context.Context,
	store SecretStore,
	configPath string,
	app storedOAuthApp,
	out io.Writer,
) (credentialLocation, error) {
	encoded, err := encodeOAuthApp(app)
	if err != nil {
		return credentialLocation{}, err
	}
	if store != nil {
		err = store.Store(ctx, StoreSecretArgs{
			Attributes: oauthAppSecretAttributes(app.Name),
			Label:      "Workshop Tailscale OAuth app: " + app.Name,
			Secret:     encoded,
		})
		if err == nil {
			return credentialLocation{
				description:   "desktop Secret Service",
				secretService: true,
			}, nil
		}
		fmt.Fprint(
			out,
			`Secret Service storage failed; falling back to a private file.
Check your keyring before retrying setup.

`,
		)
	}

	// A keyring failure must not overwrite credentials from an earlier setup.
	err = checkOAuthAppFile(configPath)
	if err != nil {
		return credentialLocation{}, err
	}
	err = writePrivateFile(configPath, encoded)
	if err != nil {
		return credentialLocation{}, err
	}
	return credentialLocation{
		description: fmt.Sprintf("%s (mode 0600)", configPath),
	}, nil
}
