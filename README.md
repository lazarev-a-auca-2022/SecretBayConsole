# SecretBay VPN Configurator

A production-ready console application for automating VPN server configuration on Ubuntu systems.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23.3-blue.svg)

## Features

- **Quick VPN Server Setup**: Automates the complete process of configuring a VPN server
- **Multiple VPN Types**:
  - OpenVPN (standard VPN protocol for most devices)
  - iOS VPN (using StrongSwan/IKEv2 for native iOS support)
- **Security Hardening**:
  - Automatic fail2ban installation
  - Firewall configuration
  - Secure password generation
  - Unused services disabled
- **Password Management**: Automatically changes server root password
- **Visual Progress Tracking**: Real-time progress bar with percentage display
- **Flexible Configuration**: Command-line arguments or JSON configuration files
- **Containerization**: Docker and Docker Compose support for easy scalability
- **Detailed Logging**: Comprehensive log files for troubleshooting

## Requirements

### For Local Development/Use

- Go 1.23.3 or higher
- SSH access to a target Ubuntu 22.04 server
- Internet connectivity for package downloads

### For Docker Deployment

- Docker and Docker Compose
- SSH access to target servers 
- Volume mounts for configuration and output

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourorg/secretbay-console.git
cd secretbay-console

# Build the application
go build -o secretbay ./cmd/secretbay

# Make executable (Linux/macOS)
chmod +x secretbay
```

### Using Docker

```bash
# Build the Docker image
docker build -t secretbay .
```

## Usage

### Command-Line Options

```
secretbay [options]

Options:
  -server string       Remote server IP address
  -user string         Username for SSH connection (default "root")
  -auth string         Authentication method (password or key) (default "password")
  -credential string   Password or path to SSH key file
  -vpn string          VPN type (openvpn or ios) (default "openvpn")
  -config string       Path to JSON configuration file
  -output string       Directory to save VPN configuration files (default "./output")
```

### Basic Examples

#### Setting up OpenVPN with password authentication:

```bash
./secretbay -server 192.168.1.100 -auth password -credential your-password -vpn openvpn
```

#### Setting up iOS VPN (StrongSwan) with SSH key authentication:

```bash
./secretbay -server 192.168.1.100 -auth key -credential ~/.ssh/id_rsa -vpn ios
```

### Using Configuration Files

You can use a JSON configuration file instead of command-line arguments:

```json
{
  "server_ip": "192.168.1.100",
  "username": "root",
  "auth_method": "password",
  "auth_credential": "your-secure-password",
  "vpn_type": "openvpn"
}
```

Run with:

```bash
./secretbay -config your-config.json
```

### Docker Usage

```bash
# Run with command-line arguments
docker run -v $(pwd)/output:/app/output secretbay -server 192.168.1.100 -auth password -credential your-password

# Run with a configuration file
docker run -v $(pwd)/output:/app/output -v $(pwd)/config.json:/app/config.json secretbay -config /app/config.json
```

## Deployment with Docker Compose

The application can be easily scaled using Docker Compose:

1. Create configuration files:
   ```bash
   mkdir -p config output logs
   cp config-example.json config/config.json
   # Edit config/config.json with your server details
   ```

2. Run with Docker Compose:
   ```bash
   docker-compose up
   ```

3. For scaling (handling multiple servers):
   ```bash
   docker-compose up --scale secretbay-worker=5
   ```

## Application Workflow

When you run the application, it performs these steps:

1. **Connection**: Establishes SSH connection to the remote server
2. **Software Installation**: Installs OpenVPN/StrongSwan and dependencies
3. **VPN Configuration**: Configures the VPN server with secure settings
4. **Certificate Generation**: Creates and configures all necessary certificates
5. **Security Setup**: Installs fail2ban, configures firewall, disables unused services
6. **Password Management**: Generates and sets a new secure server password
7. **Cleanup**: Removes temporary files and sensitive data
8. **Output Generation**: Saves client configuration files to the output directory

The console displays a progress bar showing current operation and completion percentage.

## Output Files

After successful execution, you'll find these files in your output directory:

- For OpenVPN: `client.ovpn` - OpenVPN client configuration file
- For iOS VPN: `vpn.mobileconfig` - Apple configuration profile
- `new_password.txt` - The new server root password

## Troubleshooting

If you encounter issues, check the log file (`secretbay.log`) for detailed error information.

Common issues:
- **SSH connection problems**: Verify IP address, credentials, and server availability
- **Permission errors**: Ensure your user has sufficient permissions
- **Network issues**: Check if required ports are open in your firewall

## Security Considerations

- Credential files are sensitive - protect them appropriately
- The generated VPN configuration contains private keys - keep secure
- Server password is stored in plain text in the output directory - secure or delete after use

## Project Structure

```
SecretBayConsole/
├── cmd/
│   └── secretbay/          # Application entry point
├── internal/
│   ├── config/             # Configuration handling
│   ├── models/             # Data structures
│   ├── progress/           # Progress bar implementation
│   ├── security/           # Security hardening features
│   ├── ssh/                # SSH connection handling
│   └── vpn/                # VPN configuration
│       ├── openvpn/        # OpenVPN configuration
│       └── strongswan/     # iOS VPN configuration
├── config-example.json     # Example configuration
├── docker-compose.yml      # Docker Compose definition
├── Dockerfile              # Docker build definition
└── README.md               # This file
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- OpenVPN Project
- StrongSwan Project
- Go SSH libraries