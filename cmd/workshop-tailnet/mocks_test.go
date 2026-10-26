package main

import (
	"context"
	"fmt"
)

// fakeDeviceProvisioner records exchanges and returns a configured token.
type fakeDeviceProvisioner struct {
	args  ExchangeAuthCodeArgs
	err   error
	token string
}

// fakeOAuthAppClient records setup requests and returns configured responses.
type fakeOAuthAppClient struct {
	createApp   OAuthApp
	createArgs  CreateOAuthAppArgs
	createCalls int
	createErr   error
	deleteCalls int
	deleteErr   error
	deleteID    string
	getApp      OAuthApp
	getCalls    int
	getErr      error
	listApps    []OAuthApp
	listCalls   int
	listErr     error
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

// CreateOAuthApp records the arguments and returns the configured response.
func (f *fakeOAuthAppClient) CreateOAuthApp(
	ctx context.Context,
	token string,
	args CreateOAuthAppArgs,
) (OAuthApp, error) {
	f.createCalls++
	f.token = token
	f.createArgs = args
	return f.createApp, f.createErr
}

// DeleteOAuthApp records the removal and returns the configured response.
func (f *fakeOAuthAppClient) DeleteOAuthApp(
	ctx context.Context,
	token string,
	id string,
) error {
	f.deleteCalls++
	f.deleteID = id
	f.token = token
	return f.deleteErr
}

// ExchangeAuthCode records the exchange and returns the configured token.
func (f *fakeDeviceProvisioner) ExchangeAuthCode(
	ctx context.Context,
	args ExchangeAuthCodeArgs,
) (string, error) {
	f.args = args
	return f.token, f.err
}

// GetOAuthApp records the request and returns the configured response.
func (f *fakeOAuthAppClient) GetOAuthApp(
	ctx context.Context,
	token string,
	id string,
) (OAuthApp, error) {
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

// ListOAuthApps records the request and returns the configured apps.
func (f *fakeOAuthAppClient) ListOAuthApps(
	ctx context.Context,
	token string,
) ([]OAuthApp, error) {
	f.listCalls++
	f.token = token
	return f.listApps, f.listErr
}

// Secret returns the configured secret value.
func (f *fakePrompter) Secret(label string) (string, error) {
	return f.secretValue, nil
}
