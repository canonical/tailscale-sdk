package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultConfigPath returns the user's OAuth app configuration path.
func defaultConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf(
			"locating user configuration directory: %w",
			err,
		)
	}
	path := filepath.Join(
		configDir,
		"workshop-tailnet",
		"oauth-app.json",
	)
	return path, nil
}
