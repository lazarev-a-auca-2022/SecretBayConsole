// Package ssh provides functionality for SSH connections and command execution on remote servers.
package ssh

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client represents an SSH client for communicating with a remote server.
type Client struct {
	// config is the SSH client configuration.
	config *ssh.ClientConfig

	// serverAddress is the address of the remote server.
	serverAddress string

	// client is the underlying SSH client connection.
	client *ssh.Client
}

// NewClient creates a new SSH client with the given credentials.
func NewClient(host string, port int, username, authMethod, authCredential string) (*Client, error) {
	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity; consider using known hosts in production
		Timeout:         30 * time.Second,
	}

	// Set up authentication method
	switch authMethod {
	case "password":
		config.Auth = append(config.Auth, ssh.Password(authCredential))
	case "key":
		// Check if credential is a file path or key content
		var keyData []byte
		if _, err := os.Stat(authCredential); err == nil {
			// It's a file path
			keyData, err = os.ReadFile(authCredential)
			if err != nil {
				return nil, fmt.Errorf("failed to read SSH key file: %w", err)
			}
		} else {
			// Treat as key content directly
			keyData = []byte(authCredential)
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", authMethod)
	}

	// Format server address
	serverAddress := fmt.Sprintf("%s:%d", host, port)

	return &Client{
		config:        config,
		serverAddress: serverAddress,
	}, nil
}

// Connect establishes a connection to the remote server.
func (c *Client) Connect() error {
	client, err := ssh.Dial("tcp", c.serverAddress, c.config)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.client = client
	return nil
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// ExecuteCommand runs a command on the remote server and returns its output.
func (c *Client) ExecuteCommand(command string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("client not connected")
	}

	// Create a new session
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Capture output
	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Run the command
	err = session.Run(command)
	if err != nil {
		return "", fmt.Errorf("command failed: %w (stderr: %s)", err, stderrBuf.String())
	}

	return stdoutBuf.String(), nil
}

// UploadFile uploads a file to the remote server using a robust chunked method
// that works reliably across different server environments.
func (c *Client) UploadFile(content []byte, remotePath string) error {
	if c.client == nil {
		return fmt.Errorf("client not connected")
	}

	// First ensure the parent directory exists
	dirCmd := fmt.Sprintf("mkdir -p $(dirname %s)", remotePath)
	mkdirSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for directory creation: %w", err)
	}
	err = mkdirSession.Run(dirCmd)
	mkdirSession.Close()
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create a temporary file for the transfer
	tmpFilePath := fmt.Sprintf("/tmp/secretbay-%d", time.Now().UnixNano())

	// Clear any existing temporary file
	clearSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for temp file cleanup: %w", err)
	}
	clearSession.Run(fmt.Sprintf("rm -f %s", tmpFilePath))
	clearSession.Close()

	// Split content into smaller chunks to avoid command line size limits
	const chunkSize = 1024 // 1KB chunks are safe for most systems

	for i := 0; i < len(content); i += chunkSize {
		end := i + chunkSize
		if end > len(content) {
			end = len(content)
		}

		chunk := content[i:end]

		// Convert chunk to hex representation for reliable transfer
		hexChunk := ""
		for _, b := range chunk {
			hexChunk += fmt.Sprintf("\\x%02x", b)
		}

		// Append chunk to temporary file using printf with hex escapes
		appendCmd := fmt.Sprintf("printf '%s' >> %s", hexChunk, tmpFilePath)
		appendSession, err := c.client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session for chunk append: %w", err)
		}

		err = appendSession.Run(appendCmd)
		appendSession.Close()
		if err != nil {
			return fmt.Errorf("failed to append chunk to temp file: %w", err)
		}
	}

	// Move temporary file to final destination
	moveSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for file move: %w", err)
	}
	err = moveSession.Run(fmt.Sprintf("mv %s %s", tmpFilePath, remotePath))
	moveSession.Close()
	if err != nil {
		return fmt.Errorf("failed to move file to destination: %w", err)
	}

	// Set proper permissions
	chmodSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for permissions: %w", err)
	}
	err = chmodSession.Run(fmt.Sprintf("chmod 644 %s", remotePath))
	chmodSession.Close()
	if err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// DownloadFile downloads a file from the remote server.
func (c *Client) DownloadFile(remotePath string) ([]byte, error) {
	if c.client == nil {
		return nil, fmt.Errorf("client not connected")
	}

	// Create a new session
	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Capture output
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	// Run the cat command to get file content
	err = session.Run(fmt.Sprintf("cat %s", remotePath))
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}

	return stdoutBuf.Bytes(), nil
}
