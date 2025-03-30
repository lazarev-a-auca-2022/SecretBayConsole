// Package vpn provides VPN server configuration capabilities.
package vpn

import (
	"fmt"
	"strings"

	"github.com/secretbay/console/internal/models"
	"github.com/secretbay/console/internal/progress"
	"github.com/secretbay/console/internal/security"
	"github.com/secretbay/console/internal/ssh"
	"github.com/secretbay/console/internal/vpn/openvpn"
	"github.com/secretbay/console/internal/vpn/strongswan"
)

// Configurator is the main VPN configuration orchestrator.
type Configurator struct {
	// request contains the VPN configuration request details.
	request models.ConfigRequest

	// sshClient is the SSH client for remote server communication.
	sshClient *ssh.Client

	// securityConfigurator handles server security configurations.
	securityConfigurator *security.SecurityConfigurator

	// progressBar is the console progress bar.
	progressBar *progress.Bar
}

// NewConfigurator creates a new VPN configurator with the given request.
func NewConfigurator(request models.ConfigRequest) (*Configurator, error) {
	// Normalize VPN type
	request.VPNType = strings.ToLower(request.VPNType)
	if request.VPNType != "openvpn" && request.VPNType != "ios" {
		return nil, fmt.Errorf("unsupported VPN type: %s", request.VPNType)
	}

	// Create SSH client
	sshPort := 22 // Default SSH port
	sshClient, err := ssh.NewClient(
		request.ServerIP,
		sshPort,
		request.Username,
		request.AuthMethod,
		request.AuthCredential,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %w", err)
	}

	// Create security configurator
	securityConfigurator := security.NewSecurityConfigurator(sshClient)

	// Create progress bar (10 total steps)
	progressBar := progress.NewBar(10)

	return &Configurator{
		request:              request,
		sshClient:            sshClient,
		securityConfigurator: securityConfigurator,
		progressBar:          progressBar,
	}, nil
}

// ConfigureVPN configures the VPN server based on the request.
func (c *Configurator) ConfigureVPN() (*models.ConfigResult, error) {
	// Step 1: Connect to the server
	c.progressBar.Update(1, "Connecting to remote server")
	if err := c.sshClient.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer c.sshClient.Close()

	// Step 2-3: Install and configure VPN
	var vpnConfig string
	var filename string

	// Different configuration based on VPN type
	if c.request.VPNType == "openvpn" {
		// Step 2: Installing OpenVPN
		c.progressBar.Update(2, "Installing OpenVPN")

		// Configure OpenVPN
		ovpnConfig, err := c.configureOpenVPN()
		if err != nil {
			return nil, fmt.Errorf("failed to configure OpenVPN: %w", err)
		}
		vpnConfig = ovpnConfig
		filename = "client.ovpn"
	} else if c.request.VPNType == "ios" {
		// Step 2: Installing StrongSwan
		c.progressBar.Update(2, "Installing StrongSwan for iOS")

		// Configure StrongSwan
		mobileConfig, err := c.configureIOS()
		if err != nil {
			return nil, fmt.Errorf("failed to configure iOS VPN: %w", err)
		}
		vpnConfig = mobileConfig
		filename = "vpn.mobileconfig"
	}

	// Step 6: Setup fail2ban
	c.progressBar.Update(6, "Installing fail2ban")
	if err := c.securityConfigurator.InstallFail2Ban(); err != nil {
		return nil, fmt.Errorf("failed to install fail2ban: %w", err)
	}

	// Step 7: Setup firewall
	c.progressBar.Update(7, "Configuring firewall")
	vpnPort := 1194
	if c.request.VPNType == "openvpn" {
		if err := c.securityConfigurator.SetupFirewall("openvpn", vpnPort); err != nil {
			return nil, fmt.Errorf("failed to set up firewall: %w", err)
		}
	} else {
		if err := c.securityConfigurator.SetupFirewall("ios", 0); err != nil {
			return nil, fmt.Errorf("failed to set up firewall: %w", err)
		}
	}

	// Step 8: Disable unused services
	c.progressBar.Update(8, "Disabling unnecessary services")
	if err := c.securityConfigurator.DisableUnusedServices(); err != nil {
		return nil, fmt.Errorf("failed to disable unused services: %w", err)
	}

	// Step 9: Change root password
	c.progressBar.Update(9, "Changing server password")
	newPassword, err := c.securityConfigurator.ChangeRootPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to change root password: %w", err)
	}

	// Step 10: Clean up
	c.progressBar.Update(10, "Cleaning up and finalizing")
	if err := c.securityConfigurator.CleanupUserData(); err != nil {
		return nil, fmt.Errorf("failed to clean up user data: %w", err)
	}

	// Complete progress bar
	c.progressBar.Complete("Configuration complete")

	// Create result
	result := &models.ConfigResult{
		Config:      vpnConfig,
		Filename:    filename,
		NewPassword: newPassword,
	}

	return result, nil
}

// configureOpenVPN installs and configures OpenVPN.
func (c *Configurator) configureOpenVPN() (string, error) {
	// Create OpenVPN configurator
	ovpnConf := openvpn.NewConfigurator(c.sshClient, c.request.ServerIP)

	// Step 3: Install OpenVPN
	if err := ovpnConf.Install(); err != nil {
		return "", fmt.Errorf("failed to install OpenVPN: %w", err)
	}

	// Step 4: Configure OpenVPN server
	c.progressBar.Update(4, "Configuring OpenVPN server")
	if err := ovpnConf.ConfigureServer(); err != nil {
		return "", fmt.Errorf("failed to configure OpenVPN server: %w", err)
	}

	// Step 5: Generate client configuration
	c.progressBar.Update(5, "Generating client configuration")
	clientConfig, err := ovpnConf.GenerateClientConfig()
	if err != nil {
		return "", fmt.Errorf("failed to generate client configuration: %w", err)
	}

	return clientConfig, nil
}

// configureIOS installs and configures StrongSwan for iOS VPN.
func (c *Configurator) configureIOS() (string, error) {
	// Create StrongSwan configurator
	ssConf := strongswan.NewConfigurator(c.sshClient, c.request.ServerIP)

	// Step 3: Install StrongSwan
	if err := ssConf.Install(); err != nil {
		return "", fmt.Errorf("failed to install StrongSwan: %w", err)
	}

	// Step 4: Configure StrongSwan server
	c.progressBar.Update(4, "Configuring StrongSwan server")
	if err := ssConf.ConfigureServer(); err != nil {
		return "", fmt.Errorf("failed to configure StrongSwan server: %w", err)
	}

	// Step 5: Generate mobile configuration
	c.progressBar.Update(5, "Generating iOS configuration profile")
	mobileConfig, err := ssConf.GenerateMobileConfig()
	if err != nil {
		return "", fmt.Errorf("failed to generate iOS configuration: %w", err)
	}

	return mobileConfig, nil
}
