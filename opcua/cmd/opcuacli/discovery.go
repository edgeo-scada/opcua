package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/edgeo/drivers/opcua"
	"github.com/spf13/cobra"
)

var discoveryCmd = &cobra.Command{
	Use:   "discovery",
	Short: "Discover OPC UA servers and endpoints",
	Long: `Discover available OPC UA servers and their endpoints.

This command attempts to connect using SecurityPolicyNone to retrieve
endpoint information. It will try multiple discovery URL patterns if
the initial connection fails.

Examples:
  opcuacli discovery -e opc.tcp://localhost:4840
  opcuacli discovery -e opc.tcp://opcuaserver.com:48010`,
	RunE: runDiscovery,
}

func runDiscovery(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	addr := parseEndpoint(endpoint)

	// Try multiple discovery URL patterns
	discoveryURLs := buildDiscoveryURLs(endpoint)

	var lastErr error
	for _, discoveryURL := range discoveryURLs {
		if verbose {
			fmt.Printf("Trying discovery URL: %s\n", discoveryURL)
		}

		endpoints, err := tryDiscovery(ctx, addr, discoveryURL)
		if err != nil {
			lastErr = err
			if verbose {
				fmt.Printf("  Failed: %v\n", err)
			}
			continue
		}

		// Success - display results
		displayDiscoveryResults(discoveryURL, endpoints)
		return nil
	}

	return fmt.Errorf("discovery failed on all URLs: %w", lastErr)
}

func buildDiscoveryURLs(baseURL string) []string {
	urls := []string{baseURL}

	// Add common discovery endpoint suffixes if not already present
	suffixes := []string{"/discovery", "/Discovery", ""}

	for _, suffix := range suffixes {
		if suffix == "" {
			continue
		}
		// Remove trailing slash from base URL
		base := strings.TrimSuffix(baseURL, "/")
		candidate := base + suffix
		if candidate != baseURL {
			urls = append(urls, candidate)
		}
	}

	return urls
}

func tryDiscovery(ctx context.Context, addr, discoveryURL string) ([]opcua.EndpointDescription, error) {
	// Build options from CLI flags
	opts, err := buildClientOptions()
	if err != nil {
		return nil, err
	}

	// Override endpoint URL for this discovery attempt
	opts = append(opts, opcua.WithEndpoint(discoveryURL))

	client, err := opcua.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	endpoints, err := client.GetEndpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	return endpoints, nil
}

func displayDiscoveryResults(discoveryURL string, endpoints []opcua.EndpointDescription) {
	fmt.Printf("OPC UA Discovery Results\n")
	fmt.Printf("========================\n\n")
	fmt.Printf("Discovery URL: %s\n\n", discoveryURL)

	if len(endpoints) == 0 {
		fmt.Println("No endpoints found.")
		return
	}

	// Display server info from first endpoint
	server := endpoints[0].Server
	fmt.Printf("Server Information:\n")
	fmt.Printf("  Application URI:  %s\n", server.ApplicationURI)
	fmt.Printf("  Product URI:      %s\n", server.ProductURI)
	fmt.Printf("  Application Name: %s\n", server.ApplicationName.Text)
	fmt.Printf("  Application Type: %s\n", getApplicationTypeName(server.ApplicationType))
	if len(server.DiscoveryURLs) > 0 {
		fmt.Printf("  Discovery URLs:\n")
		for _, url := range server.DiscoveryURLs {
			fmt.Printf("    - %s\n", url)
		}
	}
	fmt.Println()

	// Group endpoints by security level
	fmt.Printf("Available Endpoints (%d):\n", len(endpoints))
	fmt.Printf("─────────────────────────\n\n")

	for i, ep := range endpoints {
		securityPolicy := getSecurityPolicyName(ep.SecurityPolicyURI)
		securityMode := getSecurityModeName(ep.SecurityMode)

		fmt.Printf("[%d] %s\n", i+1, ep.EndpointURL)
		fmt.Printf("    Security Policy: %s\n", securityPolicy)
		fmt.Printf("    Security Mode:   %s\n", securityMode)
		fmt.Printf("    Security Level:  %d\n", ep.SecurityLevel)
		fmt.Printf("    Transport:       %s\n", ep.TransportProfileURI)

		if len(ep.UserIdentityTokens) > 0 {
			fmt.Printf("    Authentication:\n")
			for _, token := range ep.UserIdentityTokens {
				tokenType := getUserTokenTypeName(token.TokenType)
				if token.SecurityPolicyURI != "" && token.SecurityPolicyURI != string(opcua.SecurityPolicyNone) {
					fmt.Printf("      - %s (%s, requires %s)\n",
						token.PolicyID, tokenType, getSecurityPolicyName(token.SecurityPolicyURI))
				} else {
					fmt.Printf("      - %s (%s)\n", token.PolicyID, tokenType)
				}
			}
		}

		// Show certificate info if present
		if len(ep.ServerCertificate) > 0 {
			fmt.Printf("    Certificate:     Present (%d bytes)\n", len(ep.ServerCertificate))
		}

		fmt.Println()
	}

	// Summary
	fmt.Printf("Summary:\n")
	fmt.Printf("────────\n")

	hasNoSecurity := false
	hasSignOnly := false
	hasSignAndEncrypt := false

	for _, ep := range endpoints {
		switch ep.SecurityMode {
		case opcua.MessageSecurityModeNone:
			hasNoSecurity = true
		case opcua.MessageSecurityModeSign:
			hasSignOnly = true
		case opcua.MessageSecurityModeSignAndEncrypt:
			hasSignAndEncrypt = true
		}
	}

	if hasNoSecurity {
		fmt.Printf("  ✓ Server supports unsecured connections (SecurityPolicyNone)\n")
	} else {
		fmt.Printf("  ✗ Server requires security - no unsecured endpoints available\n")
	}

	if hasSignOnly {
		fmt.Printf("  ✓ Server supports Sign mode\n")
	}

	if hasSignAndEncrypt {
		fmt.Printf("  ✓ Server supports SignAndEncrypt mode\n")
	}

	// Suggest connection command
	fmt.Printf("\nConnection Examples:\n")
	fmt.Printf("────────────────────\n")

	if hasNoSecurity {
		for _, ep := range endpoints {
			if ep.SecurityMode == opcua.MessageSecurityModeNone {
				fmt.Printf("  Unsecured: opcuacli browse -e %s\n", ep.EndpointURL)
				break
			}
		}
	}

	for _, ep := range endpoints {
		if ep.SecurityMode == opcua.MessageSecurityModeSignAndEncrypt {
			policy := getSecurityPolicyShortName(ep.SecurityPolicyURI)
			fmt.Printf("  Secured:   opcuacli browse -e %s --security-policy %s --security-mode SignAndEncrypt\n",
				ep.EndpointURL, policy)
			break
		}
	}
}

func getSecurityModeName(mode opcua.MessageSecurityMode) string {
	switch mode {
	case opcua.MessageSecurityModeInvalid:
		return "Invalid"
	case opcua.MessageSecurityModeNone:
		return "None"
	case opcua.MessageSecurityModeSign:
		return "Sign"
	case opcua.MessageSecurityModeSignAndEncrypt:
		return "SignAndEncrypt"
	default:
		return fmt.Sprintf("Unknown(%d)", mode)
	}
}

func getSecurityPolicyShortName(uri string) string {
	switch uri {
	case string(opcua.SecurityPolicyNone):
		return "None"
	case string(opcua.SecurityPolicyBasic128Rsa15):
		return "Basic128Rsa15"
	case string(opcua.SecurityPolicyBasic256):
		return "Basic256"
	case string(opcua.SecurityPolicyBasic256Sha256):
		return "Basic256Sha256"
	case string(opcua.SecurityPolicyAes128Sha256):
		return "Aes128Sha256RsaOaep"
	case string(opcua.SecurityPolicyAes256Sha256):
		return "Aes256Sha256RsaPss"
	default:
		// Extract short name from URI
		parts := strings.Split(uri, "#")
		if len(parts) > 1 {
			return parts[1]
		}
		return uri
	}
}
