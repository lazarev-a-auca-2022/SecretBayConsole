// Package strongswan provides functionality for configuring StrongSwan IKEv2 VPN servers for iOS devices.
package strongswan

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"text/template"

	"github.com/secretbay/console/internal/ssh"
)

// Configurator handles the installation and configuration of StrongSwan IKEv2 VPN.
type Configurator struct {
	// sshClient is the SSH client for executing commands on the remote server.
	sshClient *ssh.Client

	// serverIP is the IP address of the remote server.
	serverIP string

	// serverDomain will be used for certificate CommonName.
	serverDomain string
}

// NewConfigurator creates a new StrongSwan configurator.
func NewConfigurator(sshClient *ssh.Client, serverIP string) *Configurator {
	return &Configurator{
		sshClient:    sshClient,
		serverIP:     serverIP,
		serverDomain: serverIP, // Default to using IP as domain
	}
}

// SetServerDomain sets a custom domain for the server certificate.
func (c *Configurator) SetServerDomain(domain string) {
	c.serverDomain = domain
}

// Install installs StrongSwan on the remote server.
func (c *Configurator) Install() error {
	// Update package lists
	_, err := c.sshClient.ExecuteCommand("apt-get update")
	if err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	// Install StrongSwan
	_, err = c.sshClient.ExecuteCommand("apt-get install -y strongswan strongswan-pki libcharon-extra-plugins")
	if err != nil {
		return fmt.Errorf("failed to install StrongSwan: %w", err)
	}

	return nil
}

// ConfigureServer sets up the StrongSwan IKEv2 server configuration.
func (c *Configurator) ConfigureServer() error {
	// Create directories for certificates
	_, err := c.sshClient.ExecuteCommand("mkdir -p /etc/ipsec.d/private /etc/ipsec.d/cacerts /etc/ipsec.d/certs")
	if err != nil {
		return fmt.Errorf("failed to create certificate directories: %w", err)
	}

	// Generate CA key and certificate
	_, err = c.sshClient.ExecuteCommand(`
cd /etc/ipsec.d && \
pki --gen --type rsa --size 4096 --outform pem > private/ca.key.pem && \
pki --self --ca --lifetime 3650 --in private/ca.key.pem --type rsa --dn "CN=SecretBay VPN CA" --outform pem > cacerts/ca.cert.pem
`)
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Generate server key and certificate
	serverCertCmd := fmt.Sprintf(`
cd /etc/ipsec.d && \
pki --gen --type rsa --size 2048 --outform pem > private/server.key.pem && \
pki --pub --in private/server.key.pem | pki --issue --lifetime 3650 --cacert cacerts/ca.cert.pem --cakey private/ca.key.pem --dn "CN=%s" --san "%s" --flag serverAuth --flag ikeIntermediate --outform pem > certs/server.cert.pem
`, c.serverDomain, c.serverIP)

	_, err = c.sshClient.ExecuteCommand(serverCertCmd)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Generate client key and certificate
	_, err = c.sshClient.ExecuteCommand(`
cd /etc/ipsec.d && \
pki --gen --type rsa --size 2048 --outform pem > private/client.key.pem && \
pki --pub --in private/client.key.pem | pki --issue --lifetime 3650 --cacert cacerts/ca.cert.pem --cakey private/ca.key.pem --dn "CN=SecretBay VPN Client" --outform pem > certs/client.cert.pem
`)
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	// Configure ipsec.conf
	ipsecConf := fmt.Sprintf(`config setup
    charondebug="ike 0, knl 0, cfg 0, net 0, esp 0, dmn 0, mgr 0"

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%%any
    leftid=%s
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%%any
    rightid=%%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%%identity
`, c.serverDomain)

	err = c.sshClient.UploadFile([]byte(ipsecConf), "/etc/ipsec.conf")
	if err != nil {
		return fmt.Errorf("failed to upload ipsec.conf: %w", err)
	}

	// Configure ipsec.secrets
	ipsecSecrets := fmt.Sprintf(`: RSA "server.key.pem"
%s : EAP "vpnclient"
`, c.serverDomain)

	err = c.sshClient.UploadFile([]byte(ipsecSecrets), "/etc/ipsec.secrets")
	if err != nil {
		return fmt.Errorf("failed to upload ipsec.secrets: %w", err)
	}

	// Enable IP forwarding
	_, err = c.sshClient.ExecuteCommand(`echo 1 > /proc/sys/net/ipv4/ip_forward`)
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Make IP forwarding permanent
	sysctl := "net.ipv4.ip_forward=1"
	err = c.sshClient.UploadFile([]byte(sysctl), "/etc/sysctl.d/99-strongswan.conf")
	if err != nil {
		return fmt.Errorf("failed to configure permanent IP forwarding: %w", err)
	}

	// Apply sysctl changes
	_, err = c.sshClient.ExecuteCommand("sysctl --system")
	if err != nil {
		return fmt.Errorf("failed to apply sysctl changes: %w", err)
	}

	// Configure NAT
	natCommands := []string{
		"iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE",
		"iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ens3 -j MASQUERADE",
		"iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -j MASQUERADE",
	}

	success := false
	for _, cmd := range natCommands {
		_, err = c.sshClient.ExecuteCommand(cmd)
		if err == nil {
			success = true
			break
		}
	}

	if !success {
		return fmt.Errorf("failed to configure NAT: all commands failed")
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

	// Restart StrongSwan
	_, err = c.sshClient.ExecuteCommand("systemctl restart strongswan")
	if err != nil {
		return fmt.Errorf("failed to restart StrongSwan: %w", err)
	}

	return nil
}

// GenerateMobileConfig generates an Apple .mobileconfig file for iOS devices.
func (c *Configurator) GenerateMobileConfig() (string, error) {
	// Download the necessary certificates and keys
	caCert, err := c.sshClient.DownloadFile("/etc/ipsec.d/cacerts/ca.cert.pem")
	if err != nil {
		return "", fmt.Errorf("failed to download CA certificate: %w", err)
	}

	clientCert, err := c.sshClient.DownloadFile("/etc/ipsec.d/certs/client.cert.pem")
	if err != nil {
		return "", fmt.Errorf("failed to download client certificate: %w", err)
	}

	clientKey, err := c.sshClient.DownloadFile("/etc/ipsec.d/private/client.key.pem")
	if err != nil {
		return "", fmt.Errorf("failed to download client key: %w", err)
	}

	// Generate a UUID for the profile
	uuid, err := c.generateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}

	// Encode certificates and key to base64
	caBase64 := base64.StdEncoding.EncodeToString(caCert)
	clientCertBase64 := base64.StdEncoding.EncodeToString(clientCert)
	clientKeyBase64 := base64.StdEncoding.EncodeToString(clientKey)

	// Template for the mobileconfig file
	tmpl := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>IKEv2</key>
			<dict>
				<key>AuthenticationMethod</key>
				<string>Certificate</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>0</integer>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-256</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>LocalIdentifier</key>
				<string>SecretBay VPN Client</string>
				<key>RemoteAddress</key>
				<string>{{.ServerIP}}</string>
				<key>RemoteIdentifier</key>
				<string>{{.ServerDomain}}</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
			</dict>
			<key>PayloadDescription</key>
			<string>Configures VPN settings</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN</string>
			<key>PayloadIdentifier</key>
			<string>com.secretbay.vpn.{{.UUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>{{.UUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Proxies</key>
			<dict>
				<key>HTTPEnable</key>
				<integer>0</integer>
				<key>HTTPSEnable</key>
				<integer>0</integer>
			</dict>
			<key>VPNType</key>
			<string>IKEv2</string>
		</dict>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ca.cert.pem</string>
			<key>PayloadContent</key>
			<data>{{.CACert}}</data>
			<key>PayloadDescription</key>
			<string>CA certificate</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN CA</string>
			<key>PayloadIdentifier</key>
			<string>com.secretbay.vpn.ca.{{.UUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.UUID2}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>client.cert.pem</string>
			<key>PayloadContent</key>
			<data>{{.ClientCert}}</data>
			<key>PayloadDescription</key>
			<string>Client certificate</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN Client Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.secretbay.vpn.cert.{{.UUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs1</string>
			<key>PayloadUUID</key>
			<string>{{.UUID3}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>client.key.pem</string>
			<key>PayloadContent</key>
			<data>{{.ClientKey}}</data>
			<key>PayloadDescription</key>
			<string>Client private key</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN Client Key</string>
			<key>PayloadIdentifier</key>
			<string>com.secretbay.vpn.key.{{.UUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs8</string>
			<key>PayloadUUID</key>
			<string>{{.UUID4}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>SecretBay VPN</string>
	<key>PayloadIdentifier</key>
	<string>com.secretbay.vpn.profile.{{.UUID}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.UUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>`

	// Prepare template data
	data := struct {
		ServerIP     string
		ServerDomain string
		CACert       string
		ClientCert   string
		ClientKey    string
		UUID         string
		UUID2        string
		UUID3        string
		UUID4        string
	}{
		ServerIP:     c.serverIP,
		ServerDomain: c.serverDomain,
		CACert:       caBase64,
		ClientCert:   clientCertBase64,
		ClientKey:    clientKeyBase64,
		UUID:         uuid,
		UUID2:        c.generateUUIDString(),
		UUID3:        c.generateUUIDString(),
		UUID4:        c.generateUUIDString(),
	}

	// Execute template
	t, err := template.New("mobileconfig").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// generateUUID generates a UUID for the mobileconfig file.
func (c *Configurator) generateUUID() (string, error) {
	uuid := c.generateUUIDString()
	return uuid, nil
}

// generateUUIDString generates a UUID string.
func (c *Configurator) generateUUIDString() string {
	// Simple UUID generation - in production use a proper UUID library
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
