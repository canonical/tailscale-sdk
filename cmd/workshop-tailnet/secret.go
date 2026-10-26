package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"time"
)

// SecretStore checks for and stores raw secrets in the desktop Secret Service.
// Lookup searches by attributes, which should uniquely identify Workshop items.
type SecretStore interface {
	// Lookup reports whether a matching secret exists without returning it.
	Lookup(ctx context.Context, attributes map[string]string) (bool, error)

	// Store saves raw secret bytes without applying domain-specific encoding.
	Store(ctx context.Context, args StoreSecretArgs) error
}

// StoreSecretArgs describes a secret and its desktop keyring metadata.
type StoreSecretArgs struct {
	// Attributes identifies the secret for subsequent lookups.
	Attributes map[string]string

	// Label is the human-readable name shown by the desktop keyring.
	Label string

	// Secret contains the raw bytes sent to secret-tool's standard input.
	Secret []byte
}

type secretToolRunner func(context.Context, []byte, ...string) error

type secretToolStore struct {
	run secretToolRunner
}

var errSecretNotFound = errors.New("secret not found")

func appendSecretAttributes(
	args []string,
	attributes map[string]string,
) []string {
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, key, attributes[key])
	}
	return args
}

// Lookup reports whether a matching secret exists, discarding its contents.
// secret-tool cannot restrict lookup to the default collection; attributes
// must distinguish Workshop secrets from items in other collections.
func (s secretToolStore) Lookup(
	ctx context.Context,
	attributes map[string]string,
) (bool, error) {
	args := appendSecretAttributes([]string{"lookup", "--"}, attributes)
	err := s.run(ctx, nil, args...)
	if errors.Is(err, errSecretNotFound) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("looking up secret: %w", err)
	}
	return true, nil
}

func newSecretToolStore() secretToolStore {
	return secretToolStore{run: runSecretTool}
}

// runSecretTool bounds the client process without stopping the desktop service.
// It returns errSecretNotFound only for lookup exit status 1 with empty stderr.
//
// The following errors may be expected:
//   - *exec.Error when secret-tool is unavailable.
//   - *exec.ExitError when secret-tool exits unsuccessfully.
func runSecretTool(
	ctx context.Context,
	input []byte,
	args ...string,
) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "secret-tool", args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("running secret-tool: %w", ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 &&
		stderr.Len() == 0 && len(args) > 0 && args[0] == "lookup" {
		return errSecretNotFound
	} else if err != nil {
		// ExitError does not contain stderr when Cmd.Stderr is set.
		return fmt.Errorf("running secret-tool: %w", err)
	} else if stderr.Len() != 0 {
		return errors.New("running secret-tool: stderr output suppressed")
	}
	return nil
}

// Store saves raw secret bytes in the default desktop collection.
func (s secretToolStore) Store(
	ctx context.Context,
	args StoreSecretArgs,
) error {
	commandArgs := appendSecretAttributes([]string{
		"store",
		"--label=" + args.Label,
		"--collection=default",
		"--",
	}, args.Attributes)
	err := s.run(ctx, args.Secret, commandArgs...)
	if err != nil {
		return fmt.Errorf("storing secret: %w", err)
	}
	return nil
}
