package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/secretbay/console/internal/config"
	"github.com/secretbay/console/internal/models"
	"github.com/secretbay/console/internal/vpn"
)

// main is the entry point for the SecretBay VPN configuration console application.
// It parses command-line arguments, validates input data, and orchestrates the
// VPN configuration process.
func main() {
	// Define command-line flags
	serverIP := flag.String("server", "", "Remote server IP address")
	username := flag.String("user", "root", "Username for SSH connection")
	authMethod := flag.String("auth", "password", "Authentication method (password or key)")
	authCredential := flag.String("credential", "", "Password or path to SSH key file")
	vpnType := flag.String("vpn", "openvpn", "VPN type (openvpn or ios)")
	configFile := flag.String("config", "", "Path to JSON configuration file (alternative to command-line args)")
	outputDir := flag.String("output", "./output", "Directory to save VPN configuration files")
	
	flag.Parse()
	
	// Set up logging
	logFile, err := os.OpenFile("secretbay.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	
	// Handle configuration from file or command-line arguments
	var request models.ConfigRequest
	if *configFile != "" {
		request, err = config.LoadConfigFromFile(*configFile)
		if err != nil {
			fmt.Printf("Error loading configuration: %v\n", err)
			log.Fatalf("Error loading configuration: %v", err)
		}
	} else {
		// Validate required parameters
		if *serverIP == "" {
			fmt.Println("Error: Server IP address is required")
			flag.Usage()
			os.Exit(1)
		}
		if *authCredential == "" {
			fmt.Println("Error: Authentication credential is required")
			flag.Usage()
			os.Exit(1)
		}
		
		// Create request from command-line arguments
		request = models.ConfigRequest{
			ServerIP:       *serverIP,
			Username:       *username,
			AuthMethod:     *authMethod,
			AuthCredential: *authCredential,
			VPNType:        *vpnType,
		}
	}
	
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		log.Fatalf("Error creating output directory: %v", err)
	}
	
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal. Cleaning up...")
		// Perform cleanup if needed
		os.Exit(0)
	}()
	
	fmt.Println("Starting VPN configuration process...")
	fmt.Printf("Target server: %s\n", request.ServerIP)
	fmt.Printf("VPN type: %s\n", request.VPNType)
	
	// Initialize the VPN configurator
	configurator, err := vpn.NewConfigurator(request)
	if err != nil {
		fmt.Printf("Error initializing VPN configurator: %v\n", err)
		log.Fatalf("Error initializing VPN configurator: %v", err)
	}
	
	// Run the configuration process
	result, err := configurator.ConfigureVPN()
	if err != nil {
		fmt.Printf("Error configuring VPN: %v\n", err)
		log.Fatalf("Error configuring VPN: %v", err)
	}
	
	// Save configuration files
	configFilePath := fmt.Sprintf("%s/%s", *outputDir, result.Filename)
	if err := os.WriteFile(configFilePath, []byte(result.Config), 0644); err != nil {
		fmt.Printf("Error saving configuration file: %v\n", err)
		log.Fatalf("Error saving configuration file: %v", err)
	}
	
	passwordFilePath := fmt.Sprintf("%s/new_password.txt", *outputDir)
	if err := os.WriteFile(passwordFilePath, []byte(result.NewPassword), 0644); err != nil {
		fmt.Printf("Error saving new password: %v\n", err)
		log.Fatalf("Error saving new password: %v", err)
	}
	
	fmt.Println("VPN configuration completed successfully!")
	fmt.Printf("Configuration file saved to: %s\n", configFilePath)
	fmt.Printf("New server password saved to: %s\n", passwordFilePath)
}