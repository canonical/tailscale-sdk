package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type authCallbackResult struct {
	err   error
	token string
}

// DeviceProvisioner exchanges an authorisation code for a one-time auth key.
type DeviceProvisioner interface {
	// ExchangeAuthCode exchanges an authorisation code for an auth key.
	ExchangeAuthCode(
		ctx context.Context,
		clientID string,
		clientSecret string,
		code string,
		redirectURI string,
	) (string, error)
}

const (
	authCredentialFilename = "tailscale.tailscale-oauth-app"
	authShutdownTimeout    = 5 * time.Second
	defaultAuthKeyPath     = "/run/user/1000/tailscale/auth-key"
	oauthAuthorizeURL      = "https://login.tailscale.com/a/oauth_authorize"
)

func authenticate(
	ctx context.Context,
	provisioner DeviceProvisioner,
	configPath string,
	authKeyPath string,
	out io.Writer,
) error {
	app, err := loadOAuthApp(configPath)
	if err != nil {
		return err
	}
	redirectURI := app.RedirectURIs[0]
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("parse OAuth redirect URI: %w", err)
	}
	if parsedRedirect.Scheme != "http" ||
		!isLoopbackHostname(parsedRedirect.Hostname()) {
		return fmt.Errorf(
			"authentication requires a loopback HTTP redirect URI",
		)
	}

	state, err := newOAuthState()
	if err != nil {
		return err
	}
	authorisationURL, err := makeAuthorisationURL(app, state)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", parsedRedirect.Host)
	if err != nil {
		return fmt.Errorf("listen for OAuth callback: %w", err)
	}
	callbacks := make(chan authCallbackResult, 1)
	handler := makeAuthHandler(
		ctx,
		provisioner,
		app,
		state,
		parsedRedirect.Path,
		callbacks,
	)
	server := &http.Server{Handler: handler}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()

	fmt.Fprintf(
		out,
		"Open this URL to authorise the workshop:\n%s\n",
		authorisationURL,
	)
	select {
	case result := <-callbacks:
		err = shutdownAuthServer(server)
		if err != nil {
			return err
		}
		if result.err != nil {
			return result.err
		}
		err = writePrivateFile(authKeyPath, []byte(result.token+"\n"))
		if err != nil {
			return fmt.Errorf("save one-time auth key: %w", err)
		}
		fmt.Fprintf(
			out,
			"Authentication complete. Auth key saved to %s.\n",
			authKeyPath,
		)
		return nil
	case err = <-serverErrors:
		return fmt.Errorf("serve OAuth callback: %w", err)
	case <-ctx.Done():
		shutdownErr := shutdownAuthServer(server)
		if shutdownErr != nil {
			return shutdownErr
		}
		return fmt.Errorf("authenticate: %w", ctx.Err())
	}
}

func defaultOAuthAppCredentialPath() (string, error) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		return "", fmt.Errorf("OAuth app credential is not available")
	}
	return filepath.Join(directory, authCredentialFilename), nil
}

func loadOAuthApp(path string) (storedOAuthApp, error) {
	var app storedOAuthApp
	encoded, err := os.ReadFile(path)
	if err != nil {
		return app, fmt.Errorf("read OAuth app credential: %w", err)
	}
	if len(bytes.TrimSpace(encoded)) == 0 {
		return app, fmt.Errorf("OAuth app credential is empty")
	}
	err = json.Unmarshal(encoded, &app)
	if err != nil {
		return app, fmt.Errorf("decode OAuth app credential: %w", err)
	}
	if app.ClientID == "" || app.ClientSecret == "" {
		return app, fmt.Errorf(
			"OAuth app credential must include client_id and client_secret",
		)
	}
	if len(app.RedirectURIs) != 1 {
		return app, fmt.Errorf(
			"OAuth app credential must include exactly one redirect URI",
		)
	}
	err = validateRedirectURI(app.RedirectURIs[0])
	if err != nil {
		return app, fmt.Errorf("invalid OAuth redirect URI: %w", err)
	}
	if !sameStrings(app.Scopes, []string{provisioningScope}) {
		return app, fmt.Errorf(
			"OAuth app credential must request %s",
			provisioningScope,
		)
	}
	return app, nil
}

func makeAuthHandler(
	ctx context.Context,
	provisioner DeviceProvisioner,
	app storedOAuthApp,
	state string,
	callbackPath string,
	results chan<- authCallbackResult,
) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		result := authCallbackResult{}
		if r.Method != http.MethodGet {
			result.err = fmt.Errorf("OAuth callback used a non-GET method")
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			sendAuthResult(results, result)
			return
		}
		returnedState := r.URL.Query().Get("state")
		stateMatches := subtle.ConstantTimeCompare(
			[]byte(returnedState),
			[]byte(state),
		) == 1
		if !stateMatches {
			result.err = fmt.Errorf("OAuth callback state did not match")
			http.Error(w, "Invalid OAuth state.", http.StatusBadRequest)
			sendAuthResult(results, result)
			return
		}
		if r.URL.Query().Get("error") != "" {
			result.err = fmt.Errorf("Tailscale authorisation was denied")
			http.Error(w, "Authorisation denied.", http.StatusBadRequest)
			sendAuthResult(results, result)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			result.err = fmt.Errorf("OAuth callback did not include a code")
			http.Error(w, "Missing authorisation code.", http.StatusBadRequest)
			sendAuthResult(results, result)
			return
		}

		token, err := provisioner.ExchangeAuthCode(
			ctx,
			app.ClientID,
			app.ClientSecret,
			code,
			app.RedirectURIs[0],
		)
		if err != nil {
			result.err = fmt.Errorf("exchange authorisation code: %w", err)
			http.Error(w, "Token exchange failed.", http.StatusBadGateway)
			sendAuthResult(results, result)
			return
		}
		result.token = token
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Authentication complete. You may close this window.")
		sendAuthResult(results, result)
	})
	return mux
}

func makeAuthorisationURL(
	app storedOAuthApp,
	state string,
) (string, error) {
	authorisationURL, err := url.Parse(oauthAuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse Tailscale authorisation URL: %w", err)
	}
	query := authorisationURL.Query()
	query.Set("client_id", app.ClientID)
	query.Set("redirect_uri", app.RedirectURIs[0])
	query.Set("response_type", "code")
	query.Set("scope", provisioningScope)
	query.Set("state", state)
	authorisationURL.RawQuery = query.Encode()
	return authorisationURL.String(), nil
}

func newOAuthState() (string, error) {
	value := make([]byte, 32)
	_, err := rand.Read(value)
	if err != nil {
		return "", fmt.Errorf("generate OAuth state: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func sendAuthResult(
	results chan<- authCallbackResult,
	result authCallbackResult,
) {
	select {
	case results <- result:
	default:
	}
}

func shutdownAuthServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		authShutdownTimeout,
	)
	defer cancel()
	err := server.Shutdown(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("stop OAuth callback server: %w", err)
	}
	return nil
}
