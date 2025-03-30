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

// UploadFile uploads a file to the remote server.
func (c *Client) UploadFile(content []byte, remotePath string) error {
	if c.client == nil {
		return fmt.Errorf("client not connected")
	}

	// Create the directory if needed
	dirPath := fmt.Sprintf("dirname %s", remotePath)
	dirSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for directory creation: %w", err)
	}
	dirSession.Run(dirPath)
	dirSession.Close()

	mkdirSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for directory creation: %w", err)
	}
	mkdirSession.Run(fmt.Sprintf("mkdir -p $(dirname %s)", remotePath))
	mkdirSession.Close()

	// Use a more reliable method - upload to temp file then move
	tmpFile := fmt.Sprintf("/tmp/secretbay_upload_%d", time.Now().UnixNano())

	// Create a new session
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Get the stdin pipe
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	// Capture stderr for better error reporting
	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Start the SCP command in receive mode
	if err := session.Start(fmt.Sprintf("cat > %s", tmpFile)); err != nil {
		return fmt.Errorf("failed to start file upload: %w", err)
	}

	// Write file content to stdin
	_, err = stdin.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	// Close stdin to signal the end of file
	stdin.Close()

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		return fmt.Errorf("file upload failed: %w (stderr: %s)", err, stderr.String())
	}

	// Move the file to the final destination
	moveSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for moving file: %w", err)
	}
	defer moveSession.Close()

	var moveStderr bytes.Buffer
	moveSession.Stderr = &moveStderr

	// Move the file with proper permissions
	if err := moveSession.Run(fmt.Sprintf("mv %s %s && chmod 644 %s", tmpFile, remotePath, remotePath)); err != nil {
		return fmt.Errorf("failed to move file: %w (stderr: %s)", err, moveStderr.String())
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
