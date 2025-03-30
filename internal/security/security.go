// Package security provides security-related utilities for hardening VPN servers.
package security

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/secretbay/console/internal/ssh"
)

// SecurityConfigurator handles security-related configurations on remote servers.
type SecurityConfigurator struct {
	// sshClient is the SSH client for executing commands on the remote server.
	sshClient *ssh.Client
}

// NewSecurityConfigurator creates a new security configurator with the given SSH client.
func NewSecurityConfigurator(sshClient *ssh.Client) *SecurityConfigurator {
	return &SecurityConfigurator{
		sshClient: sshClient,
	}
}

// SetupFirewall configures the firewall on the remote server.
func (s *SecurityConfigurator) SetupFirewall(vpnType string, vpnPort int) error {
	// Install ufw if not already installed
	_, err := s.sshClient.ExecuteCommand("apt-get update && apt-get install -y ufw")
	if err != nil {
		return fmt.Errorf("failed to install ufw: %w", err)
	}

	// Allow SSH traffic
	_, err = s.sshClient.ExecuteCommand("ufw allow 22/tcp")
	if err != nil {
		return fmt.Errorf("failed to allow SSH traffic: %w", err)
	}

	// Allow VPN traffic based on the type
	var vpnRule string
	if vpnType == "openvpn" {
		// Allow OpenVPN traffic (default port 1194 UDP)
		vpnRule = fmt.Sprintf("ufw allow %d/udp", vpnPort)
	} else if vpnType == "ios" {
		// Allow IKEv2 traffic for iOS VPN
		vpnRule = "ufw allow 500,4500/udp"
	}

	_, err = s.sshClient.ExecuteCommand(vpnRule)
	if err != nil {
		return fmt.Errorf("failed to allow VPN traffic: %w", err)
	}

	// Enable ufw
	_, err = s.sshClient.ExecuteCommand("echo 'y' | ufw enable")
	if err != nil {
		return fmt.Errorf("failed to enable ufw: %w", err)
	}

	return nil
}

// InstallFail2Ban installs and configures Fail2Ban for SSH protection.
func (s *SecurityConfigurator) InstallFail2Ban() error {
	// Install Fail2Ban
	_, err := s.sshClient.ExecuteCommand("apt-get update && apt-get install -y fail2ban")
	if err != nil {
		return fmt.Errorf("failed to install fail2ban: %w", err)
	}

	// Configure Fail2Ban
	fail2banConfig := `
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
`

	err = s.sshClient.UploadFile([]byte(fail2banConfig), "/etc/fail2ban/jail.local")
	if err != nil {
		return fmt.Errorf("failed to configure fail2ban: %w", err)
	}

	// Restart Fail2Ban
	_, err = s.sshClient.ExecuteCommand("systemctl restart fail2ban")
	if err != nil {
		return fmt.Errorf("failed to restart fail2ban: %w", err)
	}

	return nil
}

// DisableUnusedServices disables unnecessary services on the remote server.
func (s *SecurityConfigurator) DisableUnusedServices() error {
	// List of services to disable
	services := []string{
		"cups", "avahi-daemon", "bluetooth", "whoopsie",
	}

	for _, service := range services {
		_, err := s.sshClient.ExecuteCommand(fmt.Sprintf("systemctl stop %s && systemctl disable %s", service, service))
		if err != nil {
			// Don't fail if a service doesn't exist
			continue
		}
	}

	return nil
}

// GenerateStrongPassword generates a secure random password.
func (s *SecurityConfigurator) GenerateStrongPassword(length int) (string, error) {
	if length < 12 {
		length = 12 // Enforce minimum length for security
	}

	// Character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers := "0123456789"
	symbols := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	// All allowed characters
	all := lowercase + uppercase + numbers + symbols
	allLen := big.NewInt(int64(len(all)))

	var password strings.Builder

	// Ensure at least one character from each set
	password.WriteByte(randomChar(lowercase))
	password.WriteByte(randomChar(uppercase))
	password.WriteByte(randomChar(numbers))
	password.WriteByte(randomChar(symbols))

	// Fill the rest of the password
	for i := 4; i < length; i++ {
		n, err := rand.Int(rand.Reader, allLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		password.WriteByte(all[n.Int64()])
	}

	// Shuffle the password
	runes := []rune(password.String())
	for i := range runes {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(runes))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		jPos := j.Int64()
		runes[i], runes[jPos] = runes[jPos], runes[i]
	}

	return string(runes), nil
}

// ChangeRootPassword changes the root password on the remote server.
func (s *SecurityConfigurator) ChangeRootPassword() (string, error) {
	// Generate a new strong password
	newPassword, err := s.GenerateStrongPassword(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	// Change the password
	passwordCmd := fmt.Sprintf("echo 'root:%s' | chpasswd", newPassword)
	_, err = s.sshClient.ExecuteCommand(passwordCmd)
	if err != nil {
		return "", fmt.Errorf("failed to change root password: %w", err)
	}

	return newPassword, nil
}

// CleanupUserData removes client-related data from the server for security.
func (s *SecurityConfigurator) CleanupUserData() error {
	// Commands to clean up user data
	cleanupCommands := []string{
		"rm -f ~/.bash_history",
		"history -c",
		"find /root -type f -name '*.log' -delete",
		"find /tmp -type f -delete",
	}

	for _, cmd := range cleanupCommands {
		_, err := s.sshClient.ExecuteCommand(cmd)
		if err != nil {
			return fmt.Errorf("cleanup failed: %w", err)
		}
	}

	return nil
}

// randomChar returns a random character from the given string.
func randomChar(chars string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
	if err != nil {
		// This shouldn't happen, but if it does, use a fallback character
		return chars[0]
	}
	return chars[n.Int64()]
}
