package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	certOutput      string
	keyOutput       string
	certOrg         string
	certCountry     string
	certLocality    string
	certAppURI      string
	certDNSNames    string
	certIPAddresses string
	certValidDays   int
	certKeySize     int
)

var gencertCmd = &cobra.Command{
	Use:   "gencert",
	Short: "Generate a self-signed certificate for OPC UA client authentication",
	Long: `Generate a self-signed X.509 certificate and private key for OPC UA client authentication.

The generated certificate includes the required extensions for OPC UA:
- Subject Alternative Name with Application URI
- Key Usage: Digital Signature, Key Encipherment, Data Encipherment
- Extended Key Usage: Client Authentication

Examples:
  # Generate certificate with defaults
  opcuacli gencert

  # Generate certificate with custom output paths
  opcuacli gencert --cert ./my-cert.pem --key ./my-key.pem

  # Generate certificate with custom application URI
  opcuacli gencert --app-uri "urn:mycompany:myapp:client"

  # Generate certificate valid for specific hostnames
  opcuacli gencert --dns "localhost,myhost.local" --ip "127.0.0.1,192.168.1.100"`,
	RunE: runGencert,
}

func init() {
	gencertCmd.Flags().StringVar(&certOutput, "cert", "client-cert.pem", "Output path for certificate")
	gencertCmd.Flags().StringVar(&keyOutput, "key", "client-key.pem", "Output path for private key")
	gencertCmd.Flags().StringVar(&certOrg, "org", "OPC UA Client", "Organization name")
	gencertCmd.Flags().StringVar(&certCountry, "country", "US", "Country code (2 letters)")
	gencertCmd.Flags().StringVar(&certLocality, "locality", "", "Locality/City name")
	gencertCmd.Flags().StringVar(&certAppURI, "app-uri", "urn:opcua:client:app", "OPC UA Application URI")
	gencertCmd.Flags().StringVar(&certDNSNames, "dns", "", "Comma-separated DNS names (e.g., localhost,myhost.local)")
	gencertCmd.Flags().StringVar(&certIPAddresses, "ip", "", "Comma-separated IP addresses (e.g., 127.0.0.1,192.168.1.100)")
	gencertCmd.Flags().IntVar(&certValidDays, "days", 365, "Certificate validity in days")
	gencertCmd.Flags().IntVar(&certKeySize, "key-size", 2048, "RSA key size in bits (2048 or 4096)")
}

func runGencert(cmd *cobra.Command, args []string) error {
	// Validate key size
	if certKeySize != 2048 && certKeySize != 4096 {
		return fmt.Errorf("key size must be 2048 or 4096, got %d", certKeySize)
	}

	// Generate private key
	fmt.Printf("Generating %d-bit RSA key pair...\n", certKeySize)
	privateKey, err := rsa.GenerateKey(rand.Reader, certKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, certValidDays)

	subject := pkix.Name{
		Organization: []string{certOrg},
		Country:      []string{certCountry},
		CommonName:   "OPC UA Client",
	}
	if certLocality != "" {
		subject.Locality = []string{certLocality}
	}

	// Build Subject Alternative Names
	var dnsNames []string
	var ipAddresses []net.IP
	var uris []*url.URL

	// Add Application URI
	appURI, err := url.Parse(certAppURI)
	if err != nil {
		return fmt.Errorf("invalid application URI: %w", err)
	}
	uris = append(uris, appURI)

	// Add DNS names
	if certDNSNames != "" {
		for _, name := range strings.Split(certDNSNames, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				dnsNames = append(dnsNames, name)
			}
		}
	}

	// Add default localhost if no DNS names specified
	if len(dnsNames) == 0 {
		dnsNames = append(dnsNames, "localhost")
	}

	// Add IP addresses
	if certIPAddresses != "" {
		for _, ipStr := range strings.Split(certIPAddresses, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return fmt.Errorf("invalid IP address: %s", ipStr)
				}
				ipAddresses = append(ipAddresses, ip)
			}
		}
	}

	// Add default localhost IP if no IPs specified
	if len(ipAddresses) == 0 {
		ipAddresses = append(ipAddresses, net.ParseIP("127.0.0.1"))
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		// Key usage for OPC UA client
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,

		// Extended key usage for client authentication
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},

		// Subject Alternative Names
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		URIs:        uris,

		// Basic constraints
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create self-signed certificate
	fmt.Println("Creating self-signed certificate...")
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure output directories exist
	if dir := filepath.Dir(certOutput); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create certificate directory: %w", err)
		}
	}
	if dir := filepath.Dir(keyOutput); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
	}

	// Write certificate to file
	certFile, err := os.Create(certOutput)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key to file
	keyFile, err := os.OpenFile(keyOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Print summary
	fmt.Println()
	fmt.Println("Certificate generated successfully!")
	fmt.Println()
	fmt.Printf("Certificate: %s\n", certOutput)
	fmt.Printf("Private Key: %s\n", keyOutput)
	fmt.Println()
	fmt.Println("Certificate Details:")
	fmt.Printf("  Subject:         CN=%s, O=%s, C=%s\n", subject.CommonName, certOrg, certCountry)
	fmt.Printf("  Application URI: %s\n", certAppURI)
	fmt.Printf("  Valid From:      %s\n", notBefore.Format(time.RFC3339))
	fmt.Printf("  Valid Until:     %s\n", notAfter.Format(time.RFC3339))
	fmt.Printf("  Key Size:        %d bits\n", certKeySize)
	fmt.Printf("  DNS Names:       %s\n", strings.Join(dnsNames, ", "))
	fmt.Printf("  IP Addresses:    %v\n", ipAddresses)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  opcuacli discovery -e <endpoint> -s Basic256Sha256 -m SignAndEncrypt --cert %s --key %s\n", certOutput, keyOutput)

	return nil
}
