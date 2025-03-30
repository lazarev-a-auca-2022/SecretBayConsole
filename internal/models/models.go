// Package models defines data structures used throughout the SecretBay VPN configuration application.
package models

// ConfigRequest represents the client request for VPN configuration.
type ConfigRequest struct {
	// ServerIP is the IP address of the remote server to configure.
	ServerIP string `json:"server_ip"`

	// Username is the SSH username for login (defaults to "root").
	Username string `json:"username"`

	// AuthMethod specifies the authentication method ("password" or "key").
	AuthMethod string `json:"auth_method"`

	// AuthCredential is either the password or SSH key data.
	AuthCredential string `json:"auth_credential"`

	// VPNType specifies the VPN type to configure ("openvpn" or "ios").
	VPNType string `json:"vpn_type"`
}

// ConfigResult represents the result of a VPN configuration operation.
type ConfigResult struct {
	// Config contains the VPN configuration data.
	Config string

	// Filename is the suggested filename for the configuration file.
	Filename string

	// NewPassword is the new server password after configuration.
	NewPassword string
}

// ProgressUpdate defines a progress update during the configuration process.
type ProgressUpdate struct {
	// Stage is the current configuration stage.
	Stage string

	// Message provides details about the current operation.
	Message string

	// PercentComplete indicates the overall completion percentage.
	PercentComplete int
}

// Error codes for the application.
const (
	// ErrInvalidRequest indicates invalid request parameters.
	ErrInvalidRequest = "INVALID_REQUEST"

	// ErrConnectionFailed indicates failure to connect to the remote server.
	ErrConnectionFailed = "CONNECTION_FAILED"

	// ErrInstallationFailed indicates failure during software installation.
	ErrInstallationFailed = "INSTALLATION_FAILED"

	// ErrConfigurationFailed indicates failure during VPN configuration.
	ErrConfigurationFailed = "CONFIGURATION_FAILED"

	// ErrSecuritySetupFailed indicates failure during security setup.
	ErrSecuritySetupFailed = "SECURITY_SETUP_FAILED"

	// ErrCleanupFailed indicates failure during final cleanup.
	ErrCleanupFailed = "CLEANUP_FAILED"
)
