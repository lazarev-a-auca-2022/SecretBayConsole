// Package ssh provides functionality for SSH connections and command execution on remote servers.
package ssh

import (
	"bytes"
	"fmt"
	"log"
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

	// Log detailed information about the upload operation
	log.Printf("Attempting to upload %d bytes to %s", len(content), remotePath)

	// Create the directory if needed
	dirCmd := fmt.Sprintf("mkdir -p $(dirname %s)", remotePath)
	log.Printf("Creating directory with command: %s", dirCmd)

	mkdirSession, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session for directory creation: %w", err)
	}

	var mkdirStderr bytes.Buffer
	mkdirSession.Stderr = &mkdirStderr

	err = mkdirSession.Run(dirCmd)
	if err != nil {
		log.Printf("Directory creation stderr: %s", mkdirStderr.String())
		return fmt.Errorf("failed to create directory: %w", err)
	}
	mkdirSession.Close()

	// Use a more reliable method - upload to temp file then move
	tmpFile := fmt.Sprintf("/tmp/secretbay_upload_%d", time.Now().UnixNano())
	log.Printf("Using temporary file: %s", tmpFile)

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

	// Start the cat command to write to temp file
	uploadCmd := fmt.Sprintf("cat > %s", tmpFile)
	log.Printf("Running upload command: %s", uploadCmd)

	if err := session.Start(uploadCmd); err != nil {
		return fmt.Errorf("failed to start file upload: %w", err)
	}

	// Write file content to stdin
	bytesWritten, err := stdin.Write(content)
	if err != nil {
		log.Printf("Write error after %d bytes: %v", bytesWritten, err)
		return fmt.Errorf("failed to write file content: %w", err)
	}
	log.Printf("Wrote %d bytes to stdin", bytesWritten)

	// Close stdin to signal the end of file
	stdin.Close()

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		log.Printf("Upload stderr: %s", stderr.String())
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
	moveCmd := fmt.Sprintf("mv %s %s && chmod 644 %s", tmpFile, remotePath, remotePath)
	log.Printf("Running move command: %s", moveCmd)

	if err := moveSession.Run(moveCmd); err != nil {
		log.Printf("Move stderr: %s", moveStderr.String())
		return fmt.Errorf("failed to move file: %w (stderr: %s)", err, moveStderr.String())
	}

	log.Printf("Successfully uploaded file to %s", remotePath)
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
