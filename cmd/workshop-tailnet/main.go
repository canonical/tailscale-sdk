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
	"path/filepath"
	"time"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	usage              = `Usage: workshop-tailnet <command>

Commands:
  setup    Register a Tailscale OAuth app for Workshop device provisioning
`
)

var errUsage = errors.New("invalid command")

func defaultConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user configuration directory: %w", err)
	}
	path := filepath.Join(
		configDir,
		"workshop-tailnet",
		"oauth-app.json",
	)
	return path, nil
}

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
	prompt := newInteractivePrompter(
		bufio.NewReader(os.Stdin),
		os.Stdout,
		readSecret,
	)
	httpClient := &http.Client{Timeout: defaultHTTPTimeout}
	client := newTailscaleClient(
		"https://api.tailscale.com",
		httpClient,
	)
	err := run(ctx, os.Args[1:], prompt, client, os.Stdout)
	if errors.Is(err, errUsage) {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	prompt Prompter,
	client OAuthAppClient,
	stdout io.Writer,
) error {
	if len(args) == 1 && isHelp(args[0]) {
		fmt.Fprint(stdout, usage)
		return nil
	}
	if len(args) != 1 || args[0] != "setup" {
		return errUsage
	}

	configPath, err := defaultConfigPath()
	if err != nil {
		return err
	}

	return setup(ctx, prompt, client, configPath, stdout)
}
