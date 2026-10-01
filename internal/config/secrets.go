package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveSecret loads a configured reference at the point an integration needs
// it. Secret values are never stored in Config or written to diagnostics.
func ResolveSecret(envName, credentialName string) (string, error) {
	if err := validateSecretRef("secret", envName, credentialName); err != nil {
		return "", err
	}
	if envName != "" {
		value := os.Getenv(envName)
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty or unset", envName)
		}
		return value, nil
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" || !filepath.IsAbs(directory) {
		return "", errors.New("CREDENTIALS_DIRECTORY is unavailable")
	}
	contents, err := os.ReadFile(filepath.Join(directory, credentialName))
	if err != nil {
		return "", fmt.Errorf("read systemd credential %s: %w", credentialName, err)
	}
	value := strings.TrimRight(string(contents), "\r\n")
	if value == "" {
		return "", fmt.Errorf("systemd credential %s is empty", credentialName)
	}
	return value, nil
}
