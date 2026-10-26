package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

func removeOAuthApp(
	ctx context.Context,
	prompt Prompter,
	client OAuthAppClient,
	id string,
	configPath string,
	out io.Writer,
) error {
	fmt.Fprintf(out, "Remove OAuth app %s from your tailnet.\n", id)
	confirmed, err := prompt.Confirm("Remove this OAuth app?", false)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("removal cancelled")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "You need a Tailscale Owner or Admin API access token.")
	fmt.Fprintln(out, "The token is used for this removal only and is not saved.")
	fmt.Fprintln(out)
	token, err := prompt.Secret("Tailscale admin API token")
	if err != nil {
		return err
	}

	err = client.DeleteOAuthApp(ctx, token, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nOAuth app %s removed.\n", id)

	removed, err := removeStoredOAuthApp(configPath, id)
	if err != nil {
		return err
	}
	if removed {
		fmt.Fprintf(
			out,
			"Local credentials for this app were removed from %s.\n",
			configPath,
		)
	}
	return nil
}

func removeStoredOAuthApp(path string, id string) (bool, error) {
	app, err := loadOAuthApp(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("read local OAuth app credentials: %w", err)
	}
	if app.ClientID != id {
		return false, nil
	}
	err = os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("remove local OAuth app credentials: %w", err)
	}
	return true, nil
}

// runRemoveOAuthApp validates arguments and runs the removal command.
func runRemoveOAuthApp(
	ctx context.Context,
	args []string,
	prompt Prompter,
	client OAuthAppClient,
	out io.Writer,
) error {
	if len(args) != 1 {
		return errUsage
	}
	configPath, err := defaultConfigPath()
	if err != nil {
		return err
	}
	return removeOAuthApp(ctx, prompt, client, args[0], configPath, out)
}
