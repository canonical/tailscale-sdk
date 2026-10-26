package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"

	"time"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	usage              = `Usage: workshop-tailnet <command> [args]

Commands:
  setup                         Register a Tailscale OAuth app
  authenticate                  Authorise a workshop and save a one-time key
  list-oauth-apps               List the OAuth apps in your tailnet
  remove-oauth-app <client-id>  Remove an OAuth app by client ID
`
)

var errUsage = errors.New("invalid command")

func isHelp(argument string) bool {
	switch argument {
	case "help", "--help", "-h":
		return true
	default:
		return false
	}
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
	)
	defer stop()

	prompter := newInteractivePrompter(
		bufio.NewReader(os.Stdin),
		os.Stdout,
		readSecret,
	)

	httpClient := &http.Client{Timeout: defaultHTTPTimeout}
	tailscaleClient := newTailscaleClient(httpClient)

	err := run(
		ctx, os.Args[1:], prompter, tailscaleClient, tailscaleClient, os.Stdout,
	)

	if errors.Is(err, errUsage) {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	prompt Prompter,
	client OAuthAppClient,
	provisioner DeviceProvisioner,
	stdout io.Writer,
) error {
	if len(args) == 0 {
		return errUsage
	}

	if len(args) == 1 && isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return nil
	}

	switch args[0] {
	case "setup":
		if len(args) != 1 {
			return errUsage
		}
		configPath, err := defaultConfigPath()
		if err != nil {
			return err
		}
		return setup(ctx, prompt, client, configPath, stdout)
	case "authenticate":
		if len(args) != 1 {
			return errUsage
		}
		configPath, err := defaultOAuthAppCredentialPath()
		if err != nil {
			return err
		}
		return authenticate(
			ctx,
			provisioner,
			configPath,
			defaultAuthKeyPath,
			stdout,
		)
	case "list-oauth-apps":
		if len(args) != 1 {
			return errUsage
		}
		return listOAuthApps(ctx, prompt, client, stdout)
	case "remove-oauth-app":
		return runRemoveOAuthApp(ctx, args[1:], prompt, client, stdout)
	default:
		return errUsage
	}
}
