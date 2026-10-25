package main

import (
	"context"
	"fmt"
)

// fakeDeviceProvisioner records exchanges and returns a configured token.
type fakeDeviceProvisioner struct {
	clientID     string
	clientSecret string
	code         string
	err          error
	redirectURI  string
	token        string
}

// fakeOAuthAppClient records setup requests and returns configured responses.
type fakeOAuthAppClient struct {
	createApp   oauthApp
	createCalls int
	createErr   error
	getApp      oauthApp
	getCalls    int
	getErr      error
	name        string
	redirectURI string
	token       string
}

// fakePrompter supplies scripted answers to interactive prompts.
type fakePrompter struct {
	confirmation bool
	inputs       []string
	secretValue  string
}

// Confirm returns the configured confirmation answer.
func (f *fakePrompter) Confirm(
	label string,
	defaultYes bool,
) (bool, error) {
	return f.confirmation, nil
}

// CreateOAuthApp records the request and returns the configured response.
func (f *fakeOAuthAppClient) CreateOAuthApp(
	ctx context.Context,
	token string,
	name string,
	redirectURI string,
) (oauthApp, error) {
	f.createCalls++
	f.token = token
	f.name = name
	f.redirectURI = redirectURI
	return f.createApp, f.createErr
}

// ExchangeAuthCode records the exchange and returns the configured token.
func (f *fakeDeviceProvisioner) ExchangeAuthCode(
	ctx context.Context,
	clientID string,
	clientSecret string,
	code string,
	redirectURI string,
) (string, error) {
	f.clientID = clientID
	f.clientSecret = clientSecret
	f.code = code
	f.redirectURI = redirectURI
	return f.token, f.err
}

// GetOAuthApp records the request and returns the configured response.
func (f *fakeOAuthAppClient) GetOAuthApp(
	ctx context.Context,
	token string,
	id string,
) (oauthApp, error) {
	f.getCalls++
	f.token = token
	return f.getApp, f.getErr
}

// Input returns the next configured input answer.
func (f *fakePrompter) Input(
	label string,
	defaultValue string,
) (string, error) {
	if len(f.inputs) == 0 {
		return "", fmt.Errorf("unexpected input prompt: %s", label)
	}
	value := f.inputs[0]
	f.inputs = f.inputs[1:]
	return value, nil
}

// Secret returns the configured secret value.
func (f *fakePrompter) Secret(label string) (string, error) {
	return f.secretValue, nil
}
