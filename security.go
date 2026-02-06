// Copyright 2025 Edgeo SCADA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opcua

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
)

// SecurityConfig holds the security configuration for a connection.
type SecurityConfig struct {
	Policy           SecurityPolicy
	Mode             MessageSecurityMode
	LocalCertificate []byte // DER encoded
	LocalPrivateKey  *rsa.PrivateKey
	RemoteCertificate []byte // DER encoded (server's certificate)

	// Derived keys for symmetric encryption (after secure channel is established)
	ClientSigningKey   []byte
	ClientEncryptingKey []byte
	ClientIV           []byte
	ServerSigningKey   []byte
	ServerEncryptingKey []byte
	ServerIV           []byte
}

// SecurityAlgorithm represents the algorithms used for a security policy.
type SecurityAlgorithm struct {
	AsymmetricSignature   string
	AsymmetricEncryption  string
	SymmetricSignature    string
	SymmetricEncryption   string
	KeyDerivation         string
	SignatureKeyLength    int
	EncryptionKeyLength   int
	EncryptionBlockSize   int
	MinAsymmetricKeyLength int
	MaxAsymmetricKeyLength int
}

// GetSecurityAlgorithm returns the algorithms for a security policy.
func GetSecurityAlgorithm(policy SecurityPolicy) (*SecurityAlgorithm, error) {
	switch policy {
	case SecurityPolicyNone:
		return &SecurityAlgorithm{}, nil

	case SecurityPolicyBasic128Rsa15:
		return &SecurityAlgorithm{
			AsymmetricSignature:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			AsymmetricEncryption:  "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
			SymmetricSignature:    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
			SymmetricEncryption:   "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			KeyDerivation:         "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1",
			SignatureKeyLength:    16,
			EncryptionKeyLength:   16,
			EncryptionBlockSize:   16,
			MinAsymmetricKeyLength: 1024,
			MaxAsymmetricKeyLength: 2048,
		}, nil

	case SecurityPolicyBasic256:
		return &SecurityAlgorithm{
			AsymmetricSignature:   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			AsymmetricEncryption:  "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
			SymmetricSignature:    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
			SymmetricEncryption:   "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			KeyDerivation:         "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1",
			SignatureKeyLength:    24,
			EncryptionKeyLength:   32,
			EncryptionBlockSize:   16,
			MinAsymmetricKeyLength: 1024,
			MaxAsymmetricKeyLength: 2048,
		}, nil

	case SecurityPolicyBasic256Sha256:
		return &SecurityAlgorithm{
			AsymmetricSignature:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			AsymmetricEncryption:  "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
			SymmetricSignature:    "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
			SymmetricEncryption:   "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			KeyDerivation:         "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256",
			SignatureKeyLength:    32,
			EncryptionKeyLength:   32,
			EncryptionBlockSize:   16,
			MinAsymmetricKeyLength: 2048,
			MaxAsymmetricKeyLength: 4096,
		}, nil

	case SecurityPolicyAes128Sha256:
		return &SecurityAlgorithm{
			AsymmetricSignature:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			AsymmetricEncryption:  "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
			SymmetricSignature:    "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
			SymmetricEncryption:   "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			KeyDerivation:         "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256",
			SignatureKeyLength:    32,
			EncryptionKeyLength:   16,
			EncryptionBlockSize:   16,
			MinAsymmetricKeyLength: 2048,
			MaxAsymmetricKeyLength: 4096,
		}, nil

	case SecurityPolicyAes256Sha256:
		return &SecurityAlgorithm{
			AsymmetricSignature:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			AsymmetricEncryption:  "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
			SymmetricSignature:    "http://www.w3.org/2000/09/xmldsig#hmac-sha256",
			SymmetricEncryption:   "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			KeyDerivation:         "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256",
			SignatureKeyLength:    32,
			EncryptionKeyLength:   32,
			EncryptionBlockSize:   16,
			MinAsymmetricKeyLength: 2048,
			MaxAsymmetricKeyLength: 4096,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported security policy: %s", policy)
	}
}

// LoadCertificate loads a certificate from PEM encoded bytes.
func LoadCertificate(pemData []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("expected CERTIFICATE, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, block.Bytes, nil
}

// LoadPrivateKey loads an RSA private key from PEM encoded bytes.
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		return key, nil

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// Thumbprint computes the SHA-1 thumbprint of a DER encoded certificate.
func Thumbprint(derCert []byte) []byte {
	h := sha1.Sum(derCert)
	return h[:]
}

// NewSecurityConfig creates a security configuration from PEM encoded certificate and key.
func NewSecurityConfig(policy SecurityPolicy, mode MessageSecurityMode, certPEM, keyPEM []byte) (*SecurityConfig, error) {
	config := &SecurityConfig{
		Policy: policy,
		Mode:   mode,
	}

	if policy == SecurityPolicyNone || mode == MessageSecurityModeNone {
		return config, nil
	}

	if certPEM == nil || keyPEM == nil {
		return nil, fmt.Errorf("certificate and key required for security policy %s", policy)
	}

	// Load certificate
	_, derCert, err := LoadCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	config.LocalCertificate = derCert

	// Load private key
	key, err := LoadPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	config.LocalPrivateKey = key

	return config, nil
}

// AsymmetricSign signs data using the appropriate algorithm for the security policy.
func (c *SecurityConfig) AsymmetricSign(data []byte) ([]byte, error) {
	if c.LocalPrivateKey == nil {
		return nil, fmt.Errorf("no private key configured")
	}

	var h hash.Hash
	var hashType crypto.Hash

	switch c.Policy {
	case SecurityPolicyBasic128Rsa15, SecurityPolicyBasic256:
		h = sha1.New()
		hashType = crypto.SHA1
	case SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256, SecurityPolicyAes256Sha256:
		h = sha256.New()
		hashType = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported security policy for signing: %s", c.Policy)
	}

	h.Write(data)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, c.LocalPrivateKey, hashType, hashed)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// AsymmetricEncrypt encrypts data using the server's public key.
func (c *SecurityConfig) AsymmetricEncrypt(data []byte) ([]byte, error) {
	if c.RemoteCertificate == nil {
		return nil, fmt.Errorf("no server certificate configured")
	}

	cert, err := x509.ParseCertificate(c.RemoteCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("server certificate does not contain RSA public key")
	}

	// Get the maximum plaintext size for this key
	keySize := pubKey.Size()
	var maxPlaintext int
	var encrypted []byte

	switch c.Policy {
	case SecurityPolicyBasic128Rsa15:
		// PKCS#1 v1.5 padding: max plaintext = keySize - 11
		maxPlaintext = keySize - 11

		// Encrypt in blocks
		for i := 0; i < len(data); i += maxPlaintext {
			end := i + maxPlaintext
			if end > len(data) {
				end = len(data)
			}
			block, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data[i:end])
			if err != nil {
				return nil, fmt.Errorf("encryption failed: %w", err)
			}
			encrypted = append(encrypted, block...)
		}

	case SecurityPolicyBasic256, SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256:
		// OAEP with SHA-1: max plaintext = keySize - 2*hashSize - 2 = keySize - 42
		maxPlaintext = keySize - 42

		for i := 0; i < len(data); i += maxPlaintext {
			end := i + maxPlaintext
			if end > len(data) {
				end = len(data)
			}
			block, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, data[i:end], nil)
			if err != nil {
				return nil, fmt.Errorf("encryption failed: %w", err)
			}
			encrypted = append(encrypted, block...)
		}

	case SecurityPolicyAes256Sha256:
		// OAEP with SHA-256: max plaintext = keySize - 2*hashSize - 2 = keySize - 66
		maxPlaintext = keySize - 66

		for i := 0; i < len(data); i += maxPlaintext {
			end := i + maxPlaintext
			if end > len(data) {
				end = len(data)
			}
			block, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data[i:end], nil)
			if err != nil {
				return nil, fmt.Errorf("encryption failed: %w", err)
			}
			encrypted = append(encrypted, block...)
		}

	default:
		return nil, fmt.Errorf("unsupported security policy for encryption: %s", c.Policy)
	}

	return encrypted, nil
}

// AsymmetricDecrypt decrypts data using the local private key.
func (c *SecurityConfig) AsymmetricDecrypt(data []byte) ([]byte, error) {
	if c.LocalPrivateKey == nil {
		return nil, fmt.Errorf("no private key configured")
	}

	keySize := c.LocalPrivateKey.Size()
	var decrypted []byte

	switch c.Policy {
	case SecurityPolicyBasic128Rsa15:
		for i := 0; i < len(data); i += keySize {
			end := i + keySize
			if end > len(data) {
				return nil, fmt.Errorf("invalid ciphertext length")
			}
			block, err := rsa.DecryptPKCS1v15(rand.Reader, c.LocalPrivateKey, data[i:end])
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			decrypted = append(decrypted, block...)
		}

	case SecurityPolicyBasic256, SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256:
		for i := 0; i < len(data); i += keySize {
			end := i + keySize
			if end > len(data) {
				return nil, fmt.Errorf("invalid ciphertext length")
			}
			block, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.LocalPrivateKey, data[i:end], nil)
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			decrypted = append(decrypted, block...)
		}

	case SecurityPolicyAes256Sha256:
		for i := 0; i < len(data); i += keySize {
			end := i + keySize
			if end > len(data) {
				return nil, fmt.Errorf("invalid ciphertext length")
			}
			block, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.LocalPrivateKey, data[i:end], nil)
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			decrypted = append(decrypted, block...)
		}

	default:
		return nil, fmt.Errorf("unsupported security policy for decryption: %s", c.Policy)
	}

	return decrypted, nil
}

// GetSignatureSize returns the size of the asymmetric signature in bytes.
func (c *SecurityConfig) GetSignatureSize() int {
	if c.LocalPrivateKey == nil {
		return 0
	}
	return c.LocalPrivateKey.Size()
}

// GetRemoteKeySize returns the size of the server's public key in bytes.
func (c *SecurityConfig) GetRemoteKeySize() (int, error) {
	if c.RemoteCertificate == nil {
		return 0, fmt.Errorf("no server certificate configured")
	}

	cert, err := x509.ParseCertificate(c.RemoteCertificate)
	if err != nil {
		return 0, err
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("not an RSA key")
	}

	return pubKey.Size(), nil
}

// GenerateNonce generates a cryptographic nonce of the specified length.
func GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GetNonceLength returns the required nonce length for a security policy.
func GetNonceLength(policy SecurityPolicy) int {
	switch policy {
	case SecurityPolicyNone:
		return 0
	case SecurityPolicyBasic128Rsa15:
		return 16
	case SecurityPolicyBasic256, SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256, SecurityPolicyAes256Sha256:
		return 32
	default:
		return 32
	}
}
