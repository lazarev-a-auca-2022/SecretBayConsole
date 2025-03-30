// Package openvpn provides functionality for configuring OpenVPN servers.
package openvpn

import (
	"fmt"
	"strings"

	"github.com/secretbay/console/internal/ssh"
)

// Configurator handles the installation and configuration of OpenVPN on remote servers.
type Configurator struct {
	// sshClient is the SSH client for executing commands on the remote server.
	sshClient *ssh.Client

	// serverIP is the IP address of the remote server.
	serverIP string

	// Port for the OpenVPN server (default: 1194).
	port int
}

// NewConfigurator creates a new OpenVPN configurator.
func NewConfigurator(sshClient *ssh.Client, serverIP string) *Configurator {
	return &Configurator{
		sshClient: sshClient,
		serverIP:  serverIP,
		port:      1194, // Default OpenVPN port
	}
}

// SetPort sets a custom port for the OpenVPN server.
func (c *Configurator) SetPort(port int) {
	c.port = port
}

// Install installs OpenVPN and EasyRSA on the remote server.
func (c *Configurator) Install() error {
	// Update package lists
	_, err := c.sshClient.ExecuteCommand("apt-get update")
	if err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	// Install OpenVPN and EasyRSA
	_, err = c.sshClient.ExecuteCommand("apt-get install -y openvpn easy-rsa")
	if err != nil {
		return fmt.Errorf("failed to install OpenVPN and EasyRSA: %w", err)
	}

	return nil
}

// ConfigureServer sets up the OpenVPN server configuration.
func (c *Configurator) ConfigureServer() error {
	// Create the PKI directory
	_, err := c.sshClient.ExecuteCommand("mkdir -p /etc/openvpn/easy-rsa")
	if err != nil {
		return fmt.Errorf("failed to create PKI directory: %w", err)
	}

	// Copy EasyRSA files
	_, err = c.sshClient.ExecuteCommand("cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/")
	if err != nil {
		return fmt.Errorf("failed to copy EasyRSA files: %w", err)
	}

	// Initialize the PKI
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && ./easyrsa --batch init-pki")
	if err != nil {
		return fmt.Errorf("failed to initialize PKI: %w", err)
	}

	// Build CA
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && ./easyrsa --batch --req-cn='SecretBay CA' build-ca nopass")
	if err != nil {
		return fmt.Errorf("failed to build CA: %w", err)
	}

	// Generate server key
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && ./easyrsa --batch build-server-full server nopass")
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Generate Diffie-Hellman parameters
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && ./easyrsa gen-dh")
	if err != nil {
		return fmt.Errorf("failed to generate DH parameters: %w", err)
	}

	// Generate client key
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && ./easyrsa --batch build-client-full client nopass")
	if err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}

	// Generate TLS key
	_, err = c.sshClient.ExecuteCommand("cd /etc/openvpn/easy-rsa && openvpn --genkey secret ta.key")
	if err != nil {
		return fmt.Errorf("failed to generate TLS key: %w", err)
	}

	// Copy files to OpenVPN directory
	_, err = c.sshClient.ExecuteCommand(`cd /etc/openvpn/easy-rsa && cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/`)
	if err != nil {
		return fmt.Errorf("failed to copy certificates: %w", err)
	}

	// Create server configuration
	serverConfig := fmt.Sprintf(`port %d
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA512
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
status /dev/null
verb 0
log /dev/null
`, c.port)

	// Upload server configuration
	err = c.sshClient.UploadFile([]byte(serverConfig), "/etc/openvpn/server.conf")
	if err != nil {
		return fmt.Errorf("failed to upload server configuration: %w", err)
	}

	// Enable IP forwarding
	_, err = c.sshClient.ExecuteCommand(`echo 1 > /proc/sys/net/ipv4/ip_forward`)
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Make IP forwarding permanent
	sysctl := "net.ipv4.ip_forward=1"
	err = c.sshClient.UploadFile([]byte(sysctl), "/etc/sysctl.d/99-openvpn.conf")
	if err != nil {
		return fmt.Errorf("failed to configure permanent IP forwarding: %w", err)
	}

	// Apply sysctl changes
	_, err = c.sshClient.ExecuteCommand("sysctl --system")
	if err != nil {
		return fmt.Errorf("failed to apply sysctl changes: %w", err)
	}

	// Configure NAT
	natCommand := `iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE`
	_, err = c.sshClient.ExecuteCommand(natCommand)
	if err != nil {
		// Try with different interface
		natCommand = `iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE`
		_, err = c.sshClient.ExecuteCommand(natCommand)
		if err != nil {
			// Try with all interfaces
			natCommand = `iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE`
			_, err = c.sshClient.ExecuteCommand(natCommand)
			if err != nil {
				return fmt.Errorf("failed to configure NAT: %w", err)
			}
		}
	}

	// Make iptables rules persistent
	_, err = c.sshClient.ExecuteCommand("apt-get install -y iptables-persistent")
	if err != nil {
		return fmt.Errorf("failed to install iptables-persistent: %w", err)
	}

	// Save iptables rules
	_, err = c.sshClient.ExecuteCommand("iptables-save > /etc/iptables/rules.v4")
	if err != nil {
		return fmt.Errorf("failed to save iptables rules: %w", err)
	}

	// Enable and start OpenVPN service
	_, err = c.sshClient.ExecuteCommand("systemctl enable openvpn@server && systemctl start openvpn@server")
	if err != nil {
		return fmt.Errorf("failed to start OpenVPN service: %w", err)
	}

	return nil
}

// GenerateClientConfig generates a client configuration file.
func (c *Configurator) GenerateClientConfig() (string, error) {
	// Read client certificate and key
	caData, err := c.sshClient.DownloadFile("/etc/openvpn/ca.crt")
	if err != nil {
		return "", fmt.Errorf("failed to download CA certificate: %w", err)
	}

	clientCert, err := c.sshClient.DownloadFile("/etc/openvpn/easy-rsa/pki/issued/client.crt")
	if err != nil {
		return "", fmt.Errorf("failed to download client certificate: %w", err)
	}

	clientKey, err := c.sshClient.DownloadFile("/etc/openvpn/easy-rsa/pki/private/client.key")
	if err != nil {
		return "", fmt.Errorf("failed to download client key: %w", err)
	}

	taKey, err := c.sshClient.DownloadFile("/etc/openvpn/ta.key")
	if err != nil {
		return "", fmt.Errorf("failed to download TLS key: %w", err)
	}

	// Extract the certificate content (between BEGIN/END markers)
	clientCertContent := extractCertificate(string(clientCert))

	// Generate client configuration
	clientConfig := fmt.Sprintf(`client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA512
tls-client
remote-cert-tls server
verb 3
<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>
<tls-auth>
%s
</tls-auth>
key-direction 1
`, c.serverIP, c.port, string(caData), clientCertContent, string(clientKey), string(taKey))

	return clientConfig, nil
}

// extractCertificate extracts the certificate content from the raw output.
func extractCertificate(certData string) string {
	startMarker := "-----BEGIN CERTIFICATE-----"
	endMarker := "-----END CERTIFICATE-----"

	startIdx := strings.Index(certData, startMarker)
	endIdx := strings.Index(certData, endMarker)

	if startIdx != -1 && endIdx != -1 {
		return certData[startIdx : endIdx+len(endMarker)]
	}

	return certData // Return the original if markers not found
}
