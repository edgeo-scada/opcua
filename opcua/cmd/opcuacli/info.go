package main

import (
	"context"
	"fmt"
	"time"

	"github.com/edgeo/drivers/opcua"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get information about an OPC UA server",
	Long: `Retrieve and display information about an OPC UA server including
available endpoints and their security settings.

Examples:
  opcuacli info -e opc.tcp://localhost:4840`,
	RunE: runInfo,
}

func runInfo(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	addr := parseEndpoint(endpoint)

	opts, err := buildClientOptions()
	if err != nil {
		return err
	}

	client, err := opcua.NewClient(addr, opts...)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	// Connect (without session for GetEndpoints)
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Get endpoints
	endpoints, err := client.GetEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("failed to get endpoints: %w", err)
	}

	fmt.Printf("OPC UA Server Information\n")
	fmt.Printf("=========================\n\n")
	fmt.Printf("Endpoint: %s\n\n", endpoint)

	if len(endpoints) == 0 {
		fmt.Println("No endpoints found.")
		return nil
	}

	// Display server info from first endpoint
	if len(endpoints) > 0 {
		server := endpoints[0].Server
		fmt.Printf("Server:\n")
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
	}

	fmt.Printf("Available Endpoints (%d):\n\n", len(endpoints))

	for i, ep := range endpoints {
		fmt.Printf("[%d] %s\n", i+1, ep.EndpointURL)
		fmt.Printf("    Security Mode:   %s\n", ep.SecurityMode)
		fmt.Printf("    Security Policy: %s\n", getSecurityPolicyName(ep.SecurityPolicyURI))
		fmt.Printf("    Security Level:  %d\n", ep.SecurityLevel)

		if len(ep.UserIdentityTokens) > 0 {
			fmt.Printf("    User Identity Tokens:\n")
			for _, token := range ep.UserIdentityTokens {
				fmt.Printf("      - %s (%s)\n", token.PolicyID, getUserTokenTypeName(token.TokenType))
			}
		}
		fmt.Println()
	}

	return nil
}

func getApplicationTypeName(t opcua.ApplicationType) string {
	switch t {
	case opcua.ApplicationTypeServer:
		return "Server"
	case opcua.ApplicationTypeClient:
		return "Client"
	case opcua.ApplicationTypeClientAndServer:
		return "ClientAndServer"
	case opcua.ApplicationTypeDiscoveryServer:
		return "DiscoveryServer"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func getSecurityPolicyName(uri string) string {
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
		return "Aes128_Sha256_RsaOaep"
	case string(opcua.SecurityPolicyAes256Sha256):
		return "Aes256_Sha256_RsaPss"
	default:
		return uri
	}
}

func getUserTokenTypeName(t opcua.UserTokenType) string {
	switch t {
	case opcua.UserTokenTypeAnonymous:
		return "Anonymous"
	case opcua.UserTokenTypeUserName:
		return "UserName"
	case opcua.UserTokenTypeCertificate:
		return "Certificate"
	case opcua.UserTokenTypeIssuedToken:
		return "IssuedToken"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
