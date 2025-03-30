// Package config handles loading and validating application configurations.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/secretbay/console/internal/models"
)

// LoadConfigFromFile loads a VPN configuration request from a JSON file.
func LoadConfigFromFile(filePath string) (models.ConfigRequest, error) {
	var config models.ConfigRequest

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate the configuration
	if err := validateConfig(config); err != nil {
		return config, err
	}

	return config, nil
}

// validateConfig checks if a configuration request is valid.
func validateConfig(config models.ConfigRequest) error {
	// Check required fields
	if config.ServerIP == "" {
		return fmt.Errorf("server_ip is required")
	}

	if config.AuthCredential == "" {
		return fmt.Errorf("auth_credential is required")
	}

	// Set defaults
	if config.Username == "" {
		config.Username = "root"
	}

	// Validate auth method
	authMethod := strings.ToLower(config.AuthMethod)
	if authMethod != "password" && authMethod != "key" {
		return fmt.Errorf("auth_method must be 'password' or 'key'")
	}

	// Validate VPN type
	vpnType := strings.ToLower(config.VPNType)
	if vpnType != "openvpn" && vpnType != "ios" {
		return fmt.Errorf("vpn_type must be 'openvpn' or 'ios'")
	}

	return nil
}
