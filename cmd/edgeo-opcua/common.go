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

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/edgeo-scada/opcua/opcua"
)

// parseSecurityPolicy converts a string to SecurityPolicy
func parseSecurityPolicy(s string) (opcua.SecurityPolicy, error) {
	switch strings.ToLower(s) {
	case "none", "":
		return opcua.SecurityPolicyNone, nil
	case "basic128rsa15":
		return opcua.SecurityPolicyBasic128Rsa15, nil
	case "basic256":
		return opcua.SecurityPolicyBasic256, nil
	case "basic256sha256":
		return opcua.SecurityPolicyBasic256Sha256, nil
	case "aes128sha256rsaoaep", "aes128sha256":
		return opcua.SecurityPolicyAes128Sha256, nil
	case "aes256sha256rsapss", "aes256sha256":
		return opcua.SecurityPolicyAes256Sha256, nil
	default:
		return "", fmt.Errorf("unknown security policy: %s", s)
	}
}

// parseSecurityMode converts a string to MessageSecurityMode
func parseSecurityMode(s string) (opcua.MessageSecurityMode, error) {
	switch strings.ToLower(s) {
	case "none", "":
		return opcua.MessageSecurityModeNone, nil
	case "sign":
		return opcua.MessageSecurityModeSign, nil
	case "signandencrypt", "sign_and_encrypt":
		return opcua.MessageSecurityModeSignAndEncrypt, nil
	default:
		return 0, fmt.Errorf("unknown security mode: %s", s)
	}
}

// buildClientOptions creates client options from CLI flags
func buildClientOptions() ([]opcua.Option, error) {
	opts := []opcua.Option{
		opcua.WithEndpoint(endpoint),
		opcua.WithTimeout(time.Duration(timeout) * time.Millisecond),
	}

	// Parse security policy
	policy, err := parseSecurityPolicy(securityPolicy)
	if err != nil {
		return nil, err
	}
	opts = append(opts, opcua.WithSecurityPolicy(policy))

	// Parse security mode
	mode, err := parseSecurityMode(securityMode)
	if err != nil {
		return nil, err
	}
	opts = append(opts, opcua.WithSecurityMode(mode))

	// Load certificate if provided
	if certFile != "" && keyFile != "" {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate: %w", err)
		}
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
		opts = append(opts, opcua.WithCertificate(cert, key))
	} else if certFile != "" || keyFile != "" {
		return nil, fmt.Errorf("both --cert and --key must be specified together")
	}

	// Validate security configuration
	if mode != opcua.MessageSecurityModeNone && policy == opcua.SecurityPolicyNone {
		return nil, fmt.Errorf("security mode %s requires a security policy other than None", securityMode)
	}

	if mode != opcua.MessageSecurityModeNone && certFile == "" {
		return nil, fmt.Errorf("security mode %s requires a client certificate (use --cert and --key)", securityMode)
	}

	return opts, nil
}
