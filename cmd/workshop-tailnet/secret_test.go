package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juju/tc"
)

// secretToolSuite tests the secret adapter using fake runners and tools.
type secretToolSuite struct{}

// TestSecretToolSuite registers the desktop secret adapter tests.
func TestSecretToolSuite(t *testing.T) {
	tc.Run(t, &secretToolSuite{})
}

// TestLookupArguments checks sorted attributes, context and empty stdin.
func (secretToolSuite) TestLookupArguments(c *tc.C) {
	ctx := c.Context()
	calls := 0
	store := secretToolStore{
		run: func(
			gotCtx context.Context,
			input []byte,
			args ...string,
		) error {
			calls++
			c.Check(gotCtx, tc.Equals, ctx)
			c.Check(input, tc.IsNil)
			c.Check(args, tc.DeepEquals, []string{
				"lookup",
				"--",
				"account", "workshop user",
				"service", "workshop-tailnet",
			})
			return nil
		},
	}

	found, err := store.Lookup(ctx, map[string]string{
		"service": "workshop-tailnet",
		"account": "workshop user",
	})
	c.Check(err, tc.IsNil)
	c.Check(found, tc.IsTrue)
	c.Check(calls, tc.Equals, 1)
}

// TestLookupResults checks absence, success and wrapped operational failures.
func (secretToolSuite) TestLookupResults(c *tc.C) {
	unlockErr := errors.New("unlocking failed")
	tests := []struct {
		found   bool
		name    string
		runErr  error
		wantErr error
	}{
		{
			found: true,
			name:  "success",
		},
		{
			name:   "missing",
			runErr: errSecretNotFound,
		},
		{
			name: "wrapped missing",
			runErr: fmt.Errorf(
				"running lookup: %w",
				errSecretNotFound,
			),
		},
		{
			name:    "failed unlock",
			runErr:  unlockErr,
			wantErr: unlockErr,
		},
		{
			name:    "cancelled",
			runErr:  context.Canceled,
			wantErr: context.Canceled,
		},
		{
			name:    "deadline exceeded",
			runErr:  context.DeadlineExceeded,
			wantErr: context.DeadlineExceeded,
		},
	}
	for _, test := range tests {
		c.Run(test.name, func(c *testing.T) {
			store := secretToolStore{
				run: func(
					context.Context,
					[]byte,
					...string,
				) error {
					return test.runErr
				},
			}

			found, err := store.Lookup(c.Context(), map[string]string{
				"service": "workshop-tailnet",
			})
			tc.Check(c, found, tc.Equals, test.found)
			if test.wantErr != nil {
				tc.Assert(c, err, tc.ErrorIs, test.wantErr)
				tc.Check(c, err.Error(), tc.Contains, "looking up secret: ")
				return
			}
			tc.Check(c, err, tc.IsNil)
		})
	}
}

// TestNewSecretToolStore checks production wiring without invoking a keyring.
func (secretToolSuite) TestNewSecretToolStore(c *tc.C) {
	store := newSecretToolStore()
	c.Check(store.run, tc.NotNil)
}

// TestOptionLikeNames checks that app names cannot become command options.
func (secretToolSuite) TestOptionLikeNames(c *tc.C) {
	for _, name := range []string{"--help", "--", "--collection=other"} {
		c.Run(name, func(c *testing.T) {
			attributes := map[string]string{"app": name}
			store := secretToolStore{}
			store.run = func(
				ctx context.Context,
				input []byte,
				args ...string,
			) error {
				tc.Check(c, args, tc.DeepEquals, []string{
					"lookup", "--", "app", name,
				})
				return nil
			}
			found, err := store.Lookup(c.Context(), attributes)
			tc.Check(c, err, tc.IsNil)
			tc.Check(c, found, tc.IsTrue)

			store.run = func(
				ctx context.Context,
				input []byte,
				args ...string,
			) error {
				tc.Check(c, args, tc.DeepEquals, []string{
					"store", "--label=app", "--collection=default",
					"--", "app", name,
				})
				return nil
			}
			err = store.Store(c.Context(), StoreSecretArgs{
				Attributes: attributes,
				Label:      "app",
				Secret:     []byte("secret"),
			})
			tc.Check(c, err, tc.IsNil)
		})
	}
}

// TestRunSecretTool checks subprocess results and secret output suppression.
// Temporary scripts cover lookup, store, missing tools and cancellation.
func (secretToolSuite) TestRunSecretTool(c *tc.C) {
	const sensitive = "sensitive-test-secret"
	tests := []struct {
		args        []string
		cancelled   bool
		missing     bool
		name        string
		script      string
		wantErr     error
		wantFailure bool
	}{
		{
			args:   []string{"lookup", "service", "workshop-tailnet"},
			name:   "lookup success suppresses stdout",
			script: "#!/bin/sh\nprintf '" + sensitive + "\\n'\n",
		},
		{
			args:        []string{"lookup", "service", "workshop-tailnet"},
			name:        "lookup missing with empty stderr",
			script:      "#!/bin/sh\nexit 1\n",
			wantErr:     errSecretNotFound,
			wantFailure: true,
		},
		{
			args: []string{"lookup", "service", "workshop-tailnet"},
			name: "lookup failure suppresses sensitive stderr",
			script: "#!/bin/sh\nprintf '" + sensitive +
				"\\n' >&2\nexit 1\n",
			wantFailure: true,
		},
		{
			args: []string{
				"store", "--label=Workshop", "--collection=default",
				"service", "workshop-tailnet",
			},
			name:        "store exit one is not absence",
			script:      "#!/bin/sh\nexit 1\n",
			wantFailure: true,
		},
		{
			args:        []string{"lookup", "service", "workshop-tailnet"},
			missing:     true,
			name:        "executable missing",
			wantErr:     exec.ErrNotFound,
			wantFailure: true,
		},
		{
			args:        []string{"lookup", "service", "workshop-tailnet"},
			cancelled:   true,
			name:        "pre-cancelled context",
			script:      "#!/bin/sh\nexit 0\n",
			wantErr:     context.Canceled,
			wantFailure: true,
		},
	}
	for _, test := range tests {
		c.Run(test.name, func(c *testing.T) {
			dir := c.TempDir()
			c.Setenv("PATH", dir)
			if !test.missing {
				err := os.WriteFile(
					filepath.Join(dir, "secret-tool"),
					[]byte(test.script),
					0o700,
				)
				tc.Assert(c, err, tc.IsNil)
			}
			ctx, cancel := context.WithCancel(c.Context())
			defer cancel()
			if test.cancelled {
				cancel()
			}

			output, err := os.CreateTemp(dir, "output-")
			tc.Assert(c, err, tc.IsNil)
			stdout, stderr := os.Stdout, os.Stderr
			c.Cleanup(func() {
				os.Stdout, os.Stderr = stdout, stderr
				_ = output.Close()
			})
			os.Stdout, os.Stderr = output, output
			err = runSecretTool(ctx, []byte(sensitive), test.args...)
			os.Stdout, os.Stderr = stdout, stderr

			captured, readErr := os.ReadFile(output.Name())
			tc.Assert(c, readErr, tc.IsNil)
			tc.Check(c, string(captured), tc.Equals, "")
			tc.Check(
				c,
				errors.Is(err, errSecretNotFound),
				tc.Equals,
				errors.Is(test.wantErr, errSecretNotFound),
			)
			if !test.wantFailure {
				tc.Check(c, err, tc.IsNil)
				return
			}
			tc.Assert(c, err, tc.NotNil)
			tc.Check(c, strings.Contains(err.Error(), sensitive), tc.IsFalse)
			if test.wantErr != nil {
				tc.Check(c, err, tc.ErrorIs, test.wantErr)
			}
		})
	}
}

// TestStoreFailure checks that store failures retain their underlying error.
func (secretToolSuite) TestStoreFailure(c *tc.C) {
	failure := errors.New("keyring unavailable")
	store := secretToolStore{
		run: func(context.Context, []byte, ...string) error {
			return failure
		},
	}

	err := store.Store(c.Context(), StoreSecretArgs{
		Attributes: map[string]string{"service": "workshop-tailnet"},
		Label:      "Workshop credentials",
		Secret:     []byte("private credential"),
	})
	c.Assert(err, tc.ErrorIs, failure)
	c.Check(err.Error(), tc.Contains, "storing secret: ")
}

// TestStoreRawBytes checks sorted metadata and unencoded stdin-only secrets.
func (secretToolSuite) TestStoreRawBytes(c *tc.C) {
	ctx := c.Context()
	calls := 0
	secret := []byte{'s', 'e', 'c', 'r', 'e', 't', '\n', 0, 0xff}
	store := secretToolStore{
		run: func(
			gotCtx context.Context,
			input []byte,
			args ...string,
		) error {
			calls++
			c.Check(gotCtx, tc.Equals, ctx)
			c.Check(input, tc.DeepEquals, secret)
			c.Check(args, tc.DeepEquals, []string{
				"store",
				"--label=Workshop credentials",
				"--collection=default",
				"--",
				"account", "workshop user",
				"service", "workshop-tailnet",
			})
			return nil
		},
	}

	err := store.Store(ctx, StoreSecretArgs{
		Attributes: map[string]string{
			"service": "workshop-tailnet",
			"account": "workshop user",
		},
		Label:  "Workshop credentials",
		Secret: secret,
	})
	c.Check(err, tc.IsNil)
	c.Check(calls, tc.Equals, 1)
}
