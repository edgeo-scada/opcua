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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"time"

	"github.com/edgeo-scada/opcua/opcua/internal/transport"
)

// Client is an OPC UA TCP client with support for automatic reconnection.
type Client struct {
	addr   string
	opts   *clientOptions

	transport    *transport.TCPTransport
	requestIDGen RequestIDGenerator
	seqNumGen    SequenceNumberGenerator

	mu              sync.Mutex
	state           ConnectionState
	closed          bool
	closeCh         chan struct{}
	metrics         *Metrics

	// Security configuration
	security *SecurityConfig

	// Secure channel state
	secureChannelID uint32
	tokenID         uint32
	clientNonce     []byte
	serverNonce     []byte

	// Session state
	sessionID           NodeID
	authenticationToken NodeID
	sessionTimeout      float64

	// Subscriptions
	subscriptions sync.Map // uint32 -> *Subscription

	logger *slog.Logger
}

// NewClient creates a new OPC UA TCP client.
func NewClient(addr string, opts ...Option) (*Client, error) {
	if addr == "" {
		return nil, errors.New("opcua: address cannot be empty")
	}

	options := defaultOptions()
	options.endpoint = addr
	for _, opt := range opts {
		opt(options)
	}

	// Initialize security configuration
	security, err := NewSecurityConfig(
		options.securityPolicy,
		options.securityMode,
		options.certificate,
		options.privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security: %w", err)
	}

	// Load server certificate if provided
	if options.serverCertificate != nil {
		_, derCert, err := LoadCertificate(options.serverCertificate)
		if err != nil {
			return nil, fmt.Errorf("failed to load server certificate: %w", err)
		}
		security.RemoteCertificate = derCert
	}

	c := &Client{
		addr:      addr,
		opts:      options,
		transport: transport.NewTCPTransport(addr, options.timeout),
		state:     StateDisconnected,
		closeCh:   make(chan struct{}),
		metrics:   NewMetrics(),
		security:  security,
		logger:    options.logger,
	}

	return c, nil
}

// Connect establishes a connection to the OPC UA server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrConnectionClosed
	}
	if c.state == StateConnected || c.state == StateSecureChannelOpen || c.state == StateSessionActive {
		c.mu.Unlock()
		return nil
	}
	c.state = StateConnecting
	c.mu.Unlock()

	c.logger.Debug("connecting", slog.String("addr", c.addr))

	// Establish TCP connection
	if err := c.transport.Connect(ctx); err != nil {
		c.mu.Lock()
		c.state = StateDisconnected
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	c.state = StateConnected
	c.metrics.ActiveConns.Add(1)
	c.mu.Unlock()

	c.logger.Info("TCP connected", slog.String("addr", c.addr))

	// Send Hello message
	if err := c.sendHello(ctx); err != nil {
		c.handleDisconnect(err)
		return fmt.Errorf("hello failed: %w", err)
	}

	// Open secure channel
	if err := c.openSecureChannel(ctx); err != nil {
		c.handleDisconnect(err)
		return fmt.Errorf("open secure channel failed: %w", err)
	}

	c.mu.Lock()
	c.state = StateSecureChannelOpen
	c.mu.Unlock()

	c.logger.Info("secure channel opened", slog.String("addr", c.addr))

	if c.opts.onConnect != nil {
		c.opts.onConnect()
	}

	return nil
}

// ConnectAndActivateSession connects and activates a session.
func (c *Client) ConnectAndActivateSession(ctx context.Context) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}

	// Create session
	if err := c.createSession(ctx); err != nil {
		c.handleDisconnect(err)
		return fmt.Errorf("create session failed: %w", err)
	}

	// Activate session
	if err := c.activateSession(ctx); err != nil {
		c.handleDisconnect(err)
		return fmt.Errorf("activate session failed: %w", err)
	}

	c.mu.Lock()
	c.state = StateSessionActive
	c.metrics.ActiveSessions.Add(1)
	c.mu.Unlock()

	c.logger.Info("session activated", slog.String("addr", c.addr))

	if c.opts.onSessionActivated != nil {
		c.opts.onSessionActivated()
	}

	return nil
}

func (c *Client) sendHello(ctx context.Context) error {
	hello := &HelloMessage{
		ProtocolVersion:   ProtocolVersion,
		ReceiveBufferSize: DefaultReceiveBufferSize,
		SendBufferSize:    DefaultSendBufferSize,
		MaxMessageSize:    DefaultMaxMessageSize,
		MaxChunkCount:     MaxChunkCount,
		EndpointURL:       c.opts.endpoint,
	}

	// Build Hello message
	helloData := hello.Encode()
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + len(helloData)),
	}
	copy(header.MessageType[:], MessageTypeHello)

	msg := append(header.Encode(), helloData...)

	// Send and receive
	resp, err := c.transport.SendRaw(ctx, msg)
	if err != nil {
		return err
	}

	// Parse response header
	var respHeader MessageHeader
	if err := respHeader.Decode(resp); err != nil {
		return err
	}

	msgType := string(respHeader.MessageType[:])
	if msgType == MessageTypeError {
		var errMsg ErrorMessage
		if err := errMsg.Decode(resp[8:]); err != nil {
			return err
		}
		sc := StatusCode(errMsg.Error)
		if errMsg.Reason != "" {
			return fmt.Errorf("server error: %s: %s", sc.Error(), errMsg.Reason)
		}
		return fmt.Errorf("server error: %s", sc.Error())
	}

	if msgType != MessageTypeAcknowledge {
		return fmt.Errorf("unexpected message type: %s", msgType)
	}

	var ack AcknowledgeMessage
	if err := ack.Decode(resp[8:]); err != nil {
		return err
	}

	c.logger.Debug("received acknowledge",
		slog.Uint64("protocol_version", uint64(ack.ProtocolVersion)),
		slog.Uint64("receive_buffer", uint64(ack.ReceiveBufferSize)),
		slog.Uint64("send_buffer", uint64(ack.SendBufferSize)))

	return nil
}

func (c *Client) openSecureChannel(ctx context.Context) error {
	// For SecurityPolicyNone, use simpler implementation
	if c.security.Policy == SecurityPolicyNone {
		return c.openSecureChannelUnsecured(ctx)
	}

	// Secure channel implementation
	return c.openSecureChannelSecured(ctx)
}

func (c *Client) openSecureChannelUnsecured(ctx context.Context) error {
	// Build OpenSecureChannel request (original simple implementation)
	e := NewEncoder()

	// Asymmetric security header
	e.WriteString(string(c.opts.securityPolicy))
	e.WriteByteString(nil) // No certificate for SecurityPolicyNone
	e.WriteByteString(nil) // Server certificate thumbprint

	// Sequence header
	seqNum := c.seqNumGen.Next()
	reqID := c.requestIDGen.Next()
	e.WriteUInt32(seqNum)
	e.WriteUInt32(reqID)

	// OpenSecureChannelRequest type ID
	e.WriteNodeID(NewNumericNodeID(0, 446)) // OpenSecureChannelRequest

	// Request header
	e.WriteNodeID(NodeID{}) // AuthenticationToken (null)
	e.WriteInt64(time.Now().UnixNano()/100 + 116444736000000000) // Timestamp
	e.WriteUInt32(reqID) // RequestHandle
	e.WriteUInt32(0)     // ReturnDiagnostics
	e.WriteString("")    // AuditEntryID
	e.WriteUInt32(uint32(c.opts.timeout.Milliseconds())) // TimeoutHint
	// AdditionalHeader (null ExtensionObject): TypeId + Encoding
	e.WriteNodeID(NodeID{}) // TypeId = null NodeID
	e.WriteByte(0x00)       // Encoding = no body

	// OpenSecureChannelRequest body
	e.WriteUInt32(0) // ClientProtocolVersion
	e.WriteUInt32(0) // RequestType: Issue
	e.WriteUInt32(uint32(c.opts.securityMode))
	e.WriteByteString(nil) // ClientNonce (not needed for SecurityPolicyNone)
	e.WriteUInt32(3600000) // RequestedLifetime (1 hour in ms)

	body := e.Bytes()

	// Build message header
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + 4 + len(body)), // header + secure channel ID + body
	}
	copy(header.MessageType[:], MessageTypeOpenChannel)

	// Combine: header + secure channel ID (0) + body
	msg := make([]byte, 0, header.MessageSize)
	msg = append(msg, header.Encode()...)
	msg = append(msg, 0, 0, 0, 0) // Secure channel ID = 0 for initial request
	msg = append(msg, body...)

	c.logger.Debug("sending OpenSecureChannel (unsecured)",
		slog.String("policy", string(c.security.Policy)),
		slog.Int("message_size", len(msg)))

	// Send and receive
	resp, err := c.transport.SendRaw(ctx, msg)
	if err != nil {
		return err
	}

	// Parse response
	var respHeader MessageHeader
	if err := respHeader.Decode(resp); err != nil {
		return err
	}

	if string(respHeader.MessageType[:]) == MessageTypeError {
		var errMsg ErrorMessage
		if err := errMsg.Decode(resp[8:]); err != nil {
			return err
		}
		sc := StatusCode(errMsg.Error)
		if errMsg.Reason != "" {
			return fmt.Errorf("open secure channel error: %s: %s", sc.Error(), errMsg.Reason)
		}
		return fmt.Errorf("open secure channel error: %s", sc.Error())
	}

	// Extract secure channel ID (at offset 8, after message header)
	c.secureChannelID = uint32(resp[8]) | uint32(resp[9])<<8 | uint32(resp[10])<<16 | uint32(resp[11])<<24

	// Parse OpenSecureChannel response properly
	// Skip: header(8) + secureChannelID(4) + asymmetric security header + sequence header
	// For SecurityPolicyNone, security header is: policyURI + null cert + null thumbprint

	// Find the start of the body by parsing the security header
	d := NewDecoder(resp[12:]) // Start after header + secure channel ID

	// Read security policy URI
	_, _ = d.ReadString()
	// Read sender certificate
	_, _ = d.ReadByteString()
	// Read receiver thumbprint
	_, _ = d.ReadByteString()

	// Skip sequence header (8 bytes)
	_, _ = d.ReadUInt32() // sequence number
	_, _ = d.ReadUInt32() // request id

	// Skip response type NodeID
	_, _ = d.ReadNodeID()

	// Now we're at the response header - skip it
	_, _ = d.ReadInt64()    // Timestamp
	_, _ = d.ReadUInt32()   // RequestHandle
	serviceResult, _ := d.ReadStatusCode() // ServiceResult
	_, _ = d.ReadByte()     // ServiceDiagnostics encoding
	_, _ = d.ReadInt32()    // StringTable array length (-1 for null)
	_, _ = d.ReadNodeID()   // AdditionalHeader TypeId
	_, _ = d.ReadByte()     // AdditionalHeader Encoding

	if serviceResult.IsBad() {
		return fmt.Errorf("open secure channel failed: %s", serviceResult.Error())
	}

	// OpenSecureChannelResponse body
	_, _ = d.ReadUInt32() // ServerProtocolVersion

	// SecurityToken
	channelID, _ := d.ReadUInt32()
	tokenID, _ := d.ReadUInt32()

	c.secureChannelID = channelID
	c.tokenID = tokenID

	c.logger.Debug("secure channel opened",
		slog.Uint64("channel_id", uint64(c.secureChannelID)),
		slog.Uint64("token_id", uint64(c.tokenID)))

	return nil
}

func (c *Client) openSecureChannelSecured(ctx context.Context) error {
	// Generate client nonce for key derivation
	nonceLength := GetNonceLength(c.security.Policy)
	if nonceLength > 0 {
		nonce, err := GenerateNonce(nonceLength)
		if err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}
		c.clientNonce = nonce
	}

	// Encryption required - need server certificate
	if c.security.RemoteCertificate == nil {
		return fmt.Errorf("server certificate required for security policy %s", c.security.Policy)
	}

	// Build the message body (sequence header + request)
	bodyEncoder := NewEncoder()

	// Sequence header
	seqNum := c.seqNumGen.Next()
	reqID := c.requestIDGen.Next()
	bodyEncoder.WriteUInt32(seqNum)
	bodyEncoder.WriteUInt32(reqID)

	// OpenSecureChannelRequest type ID
	bodyEncoder.WriteNodeID(NewNumericNodeID(0, 446)) // OpenSecureChannelRequest

	// Request header
	bodyEncoder.WriteNodeID(NodeID{}) // AuthenticationToken (null)
	bodyEncoder.WriteInt64(time.Now().UnixNano()/100 + 116444736000000000) // Timestamp
	bodyEncoder.WriteUInt32(reqID) // RequestHandle
	bodyEncoder.WriteUInt32(0)     // ReturnDiagnostics
	bodyEncoder.WriteString("")    // AuditEntryID
	bodyEncoder.WriteUInt32(uint32(c.opts.timeout.Milliseconds())) // TimeoutHint
	// AdditionalHeader (null ExtensionObject): TypeId + Encoding
	bodyEncoder.WriteNodeID(NodeID{}) // TypeId = null NodeID
	bodyEncoder.WriteByte(0x00)       // Encoding = no body

	// OpenSecureChannelRequest body
	bodyEncoder.WriteUInt32(0) // ClientProtocolVersion
	bodyEncoder.WriteUInt32(0) // RequestType: Issue
	bodyEncoder.WriteUInt32(uint32(c.opts.securityMode))
	bodyEncoder.WriteByteString(c.clientNonce)
	bodyEncoder.WriteUInt32(3600000) // RequestedLifetime (1 hour in ms)

	messageBody := bodyEncoder.Bytes()

	// Build asymmetric security header
	secHeaderEncoder := NewEncoder()
	secHeaderEncoder.WriteString(string(c.security.Policy))
	secHeaderEncoder.WriteByteString(c.security.LocalCertificate) // DER encoded
	thumbprint := Thumbprint(c.security.RemoteCertificate)
	secHeaderEncoder.WriteByteString(thumbprint)

	securityHeader := secHeaderEncoder.Bytes()

	// Get signature size
	signatureSize := c.security.GetSignatureSize()

	// Get the remote key size for padding calculation
	remoteKeySize, err := c.security.GetRemoteKeySize()
	if err != nil {
		return fmt.Errorf("failed to get server key size: %w", err)
	}

	// Calculate plain text block size
	var plainBlockSize int
	switch c.security.Policy {
	case SecurityPolicyBasic128Rsa15:
		plainBlockSize = remoteKeySize - 11
	default:
		plainBlockSize = remoteKeySize - 42 // OAEP SHA-1
	}

	// Calculate padding needed
	dataToEncrypt := len(messageBody) + 1 + signatureSize
	var paddingSize int
	if dataToEncrypt%plainBlockSize != 0 {
		paddingSize = plainBlockSize - (dataToEncrypt % plainBlockSize)
	}

	// Build padded body
	paddedBody := make([]byte, len(messageBody)+paddingSize+1)
	copy(paddedBody, messageBody)
	for i := len(messageBody); i < len(paddedBody)-1; i++ {
		paddedBody[i] = byte(paddingSize)
	}
	paddedBody[len(paddedBody)-1] = byte(paddingSize)

	// Sign the message
	dataToSign := append(securityHeader, paddedBody...)
	signature, err := c.security.AsymmetricSign(dataToSign)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Encrypt
	dataToEncryptBytes := append(paddedBody, signature...)
	encryptedData, err := c.security.AsymmetricEncrypt(dataToEncryptBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Calculate total message size
	totalSize := 8 + 4 + len(securityHeader) + len(encryptedData)

	// Build message header
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(totalSize),
	}
	copy(header.MessageType[:], MessageTypeOpenChannel)

	// Assemble the complete message
	msg := make([]byte, 0, totalSize)
	msg = append(msg, header.Encode()...)
	msg = append(msg, 0, 0, 0, 0) // Secure channel ID = 0 for initial request
	msg = append(msg, securityHeader...)
	msg = append(msg, encryptedData...)

	c.logger.Debug("sending OpenSecureChannel (secured)",
		slog.String("policy", string(c.security.Policy)),
		slog.Int("mode", int(c.security.Mode)),
		slog.Int("message_size", len(msg)))

	// Send and receive
	resp, err := c.transport.SendRaw(ctx, msg)
	if err != nil {
		return err
	}

	// Parse response
	var respHeader MessageHeader
	if err := respHeader.Decode(resp); err != nil {
		return err
	}

	if string(respHeader.MessageType[:]) == MessageTypeError {
		var errMsg ErrorMessage
		if err := errMsg.Decode(resp[8:]); err != nil {
			return err
		}
		sc := StatusCode(errMsg.Error)
		if errMsg.Reason != "" {
			return fmt.Errorf("open secure channel error: %s: %s", sc.Error(), errMsg.Reason)
		}
		return fmt.Errorf("open secure channel error: %s", sc.Error())
	}

	// Extract secure channel ID
	c.secureChannelID = uint32(resp[8]) | uint32(resp[9])<<8 | uint32(resp[10])<<16 | uint32(resp[11])<<24

	// TODO: Decrypt response and extract token ID properly
	if len(resp) > 50 {
		c.tokenID = uint32(resp[44]) | uint32(resp[45])<<8 | uint32(resp[46])<<16 | uint32(resp[47])<<24
	}

	c.logger.Debug("secure channel opened",
		slog.Uint64("channel_id", uint64(c.secureChannelID)),
		slog.Uint64("token_id", uint64(c.tokenID)))

	return nil
}

func (c *Client) createSession(ctx context.Context) error {
	c.logger.Debug("creating session", slog.String("name", c.opts.sessionName))

	// Generate client nonce for session
	clientNonce, err := GenerateNonce(32)
	if err != nil {
		return fmt.Errorf("failed to generate client nonce: %w", err)
	}

	req := &CreateSessionRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: NodeID{}, // Null for CreateSession
			Timestamp:           time.Now().UnixNano()/100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		ClientDescription: ApplicationDescription{
			ApplicationURI:  c.opts.applicationURI,
			ProductURI:      c.opts.productURI,
			ApplicationName: LocalizedText{Text: c.opts.applicationName},
			ApplicationType: ApplicationTypeClient,
		},
		ServerURI:               "",
		EndpointURL:             c.opts.endpoint,
		SessionName:             c.opts.sessionName,
		ClientNonce:             clientNonce,
		ClientCertificate:       c.security.LocalCertificate, // May be nil for unsecured
		RequestedSessionTimeout: c.opts.sessionTimeout.Seconds() * 1000,
		MaxResponseMessageSize:  0, // No limit
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return fmt.Errorf("create session request failed: %w", err)
	}

	var resp CreateSessionResponseMsg
	if err := resp.Decode(respData); err != nil {
		return fmt.Errorf("failed to decode create session response: %w", err)
	}

	// Store session state
	c.sessionID = resp.SessionID
	c.authenticationToken = resp.AuthenticationToken
	c.sessionTimeout = resp.RevisedSessionTimeout
	c.serverNonce = resp.ServerNonce

	c.logger.Debug("session created",
		slog.String("session_id", fmt.Sprintf("%v", c.sessionID)),
		slog.Float64("timeout_ms", c.sessionTimeout))

	return nil
}

func (c *Client) activateSession(ctx context.Context) error {
	c.logger.Debug("activating session")

	// Get endpoints to find the correct policy ID for our auth type
	// This is a simplified approach - we fetch endpoints via GetEndpoints service
	endpoints, err := c.GetEndpoints(ctx)
	if err != nil {
		c.logger.Warn("failed to get endpoints for policy ID, using defaults", slog.String("error", err.Error()))
		endpoints = nil
	}

	// Find the correct policy ID for our authentication type
	policyID := c.findPolicyID(endpoints)

	// Build user identity token based on authentication type
	var userIdentityToken interface{}
	var userTokenSignature SignatureData

	switch c.opts.authType {
	case AuthTypeAnonymous:
		userIdentityToken = &AnonymousIdentityToken{
			PolicyID: policyID,
		}
	case AuthTypeUserPassword:
		userIdentityToken = &UserNameIdentityToken{
			PolicyID:            policyID,
			UserName:            c.opts.username,
			Password:            []byte(c.opts.password),
			EncryptionAlgorithm: "",
		}
	case AuthTypeCertificate:
		userIdentityToken = &X509IdentityToken{
			PolicyID:        policyID,
			CertificateData: c.opts.userCert,
		}
		// For certificate auth, we may need to sign with user key
	}

	// Client signature (for secured connections, sign server cert + server nonce)
	var clientSignature SignatureData
	if c.security.Policy != SecurityPolicyNone && c.serverNonce != nil {
		// Create signature of (ServerCertificate + ServerNonce)
		dataToSign := append(c.security.RemoteCertificate, c.serverNonce...)
		signature, err := c.security.AsymmetricSign(dataToSign)
		if err == nil {
			algo, _ := GetSecurityAlgorithm(c.security.Policy)
			clientSignature = SignatureData{
				Algorithm: algo.AsymmetricSignature,
				Signature: signature,
			}
		}
	}

	req := &ActivateSessionRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano()/100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		ClientSignature:            clientSignature,
		ClientSoftwareCertificates: nil,
		LocaleIDs:                  []string{"en"},
		UserIdentityToken:          userIdentityToken,
		UserTokenSignature:         userTokenSignature,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return fmt.Errorf("activate session request failed: %w", err)
	}

	var resp ActivateSessionResponseMsg
	if err := resp.Decode(respData); err != nil {
		return fmt.Errorf("failed to decode activate session response: %w", err)
	}

	// Update server nonce
	if resp.ServerNonce != nil {
		c.serverNonce = resp.ServerNonce
	}

	c.logger.Debug("session activated")

	return nil
}

// findPolicyID finds the policy ID for the current auth type from endpoint descriptions.
func (c *Client) findPolicyID(endpoints []EndpointDescription) string {
	// Determine which token type we need
	var targetType UserTokenType
	switch c.opts.authType {
	case AuthTypeAnonymous:
		targetType = UserTokenTypeAnonymous
	case AuthTypeUserPassword:
		targetType = UserTokenTypeUserName
	case AuthTypeCertificate:
		targetType = UserTokenTypeCertificate
	}

	// Search through endpoints to find matching policy
	for _, ep := range endpoints {
		// Match endpoint by security policy and mode
		if ep.SecurityPolicyURI == string(c.opts.securityPolicy) &&
			ep.SecurityMode == c.opts.securityMode {
			for _, token := range ep.UserIdentityTokens {
				if token.TokenType == targetType {
					c.logger.Debug("found policy ID",
						slog.String("policy_id", token.PolicyID),
						slog.Uint64("token_type", uint64(token.TokenType)))
					return token.PolicyID
				}
			}
		}
	}

	// If no exact match, try to find any endpoint with matching auth type
	for _, ep := range endpoints {
		for _, token := range ep.UserIdentityTokens {
			if token.TokenType == targetType {
				c.logger.Debug("found fallback policy ID",
					slog.String("policy_id", token.PolicyID),
					slog.Uint64("token_type", uint64(token.TokenType)))
				return token.PolicyID
			}
		}
	}

	// Default fallback policy IDs
	switch c.opts.authType {
	case AuthTypeAnonymous:
		return "anonymous"
	case AuthTypeUserPassword:
		return "username"
	case AuthTypeCertificate:
		return "certificate"
	default:
		return ""
	}
}

// Close closes the client connection.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeCh)
	wasSessionActive := c.state == StateSessionActive
	wasConnected := c.state >= StateConnected
	c.state = StateDisconnected
	if wasSessionActive {
		c.metrics.ActiveSessions.Add(-1)
	}
	if wasConnected {
		c.metrics.ActiveConns.Add(-1)
	}
	c.mu.Unlock()

	c.logger.Debug("closing connection", slog.String("addr", c.addr))
	return c.transport.Close()
}

// State returns the current connection state.
func (c *Client) State() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// IsConnected returns true if the client is connected.
func (c *Client) IsConnected() bool {
	return c.State() >= StateConnected
}

// IsSessionActive returns true if the session is active.
func (c *Client) IsSessionActive() bool {
	return c.State() == StateSessionActive
}

// Metrics returns the client metrics.
func (c *Client) Metrics() *Metrics {
	return c.metrics
}

// Address returns the server address.
func (c *Client) Address() string {
	return c.addr
}

// send sends a request and receives the response with optional retry logic.
func (c *Client) send(ctx context.Context, req Request) ([]byte, error) {
	var lastErr error
	maxRetries := 1
	if c.opts.autoReconnect {
		maxRetries = c.opts.maxRetries
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debug("retrying request",
				slog.Int("attempt", attempt+1),
				slog.Int("max", maxRetries))

			if err := c.reconnect(ctx); err != nil {
				lastErr = err
				continue
			}
		}

		resp, err := c.doSend(ctx, req)
		if err != nil {
			lastErr = err
			if !c.opts.autoReconnect || !isRetryableError(err) {
				return nil, err
			}
			c.handleDisconnect(err)
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}

func (c *Client) doSend(ctx context.Context, req Request) ([]byte, error) {
	c.mu.Lock()
	if c.state < StateSecureChannelOpen {
		c.mu.Unlock()
		return nil, ErrNotConnected
	}
	c.mu.Unlock()

	start := time.Now()
	c.metrics.RequestsTotal.Add(1)

	// Encode request
	reqData, err := req.Encode()
	if err != nil {
		c.metrics.RequestsErrors.Add(1)
		return nil, err
	}

	// Build message
	e := NewEncoder()

	// Security header (symmetric)
	e.WriteUInt32(c.tokenID)

	// Sequence header
	seqNum := c.seqNumGen.Next()
	reqID := c.requestIDGen.Next()
	e.WriteUInt32(seqNum)
	e.WriteUInt32(reqID)

	// Service request type ID
	e.WriteNodeID(NewNumericNodeID(0, uint32(req.ServiceID())))

	// Request data
	e.buf.Write(reqData)

	body := e.Bytes()

	// Message header
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + 4 + len(body)), // header + secure channel ID + body
	}
	copy(header.MessageType[:], MessageTypeMessage)

	// Build complete message
	msg := make([]byte, 0, header.MessageSize)
	msg = append(msg, header.Encode()...)

	// Secure channel ID
	var scID [4]byte
	scID[0] = byte(c.secureChannelID)
	scID[1] = byte(c.secureChannelID >> 8)
	scID[2] = byte(c.secureChannelID >> 16)
	scID[3] = byte(c.secureChannelID >> 24)
	msg = append(msg, scID[:]...)

	msg = append(msg, body...)

	c.logger.Debug("sending request",
		slog.String("service", req.ServiceID().String()),
		slog.Uint64("request_id", uint64(reqID)))

	// Send and receive
	respData, err := c.transport.SendRaw(ctx, msg)
	if err != nil {
		c.metrics.RequestsErrors.Add(1)
		return nil, err
	}

	// Parse response header
	var respHeader MessageHeader
	if err := respHeader.Decode(respData); err != nil {
		c.metrics.RequestsErrors.Add(1)
		return nil, err
	}

	if string(respHeader.MessageType[:]) == MessageTypeError {
		c.metrics.RequestsErrors.Add(1)
		var errMsg ErrorMessage
		if err := errMsg.Decode(respData[8:]); err != nil {
			return nil, err
		}
		sc := StatusCode(errMsg.Error)
		if errMsg.Reason != "" {
			return nil, fmt.Errorf("service error: %s: %s", sc.Error(), errMsg.Reason)
		}
		return nil, fmt.Errorf("service error: %s", sc.Error())
	}

	// Parse response to find body start
	// Structure: header(8) + secureChannelID(4) + tokenID(4) + sequenceHeader(8) + NodeID + body
	if len(respData) < 24 {
		c.metrics.RequestsErrors.Add(1)
		return nil, ErrInvalidResponse
	}

	// Skip past fixed headers (8 + 4 + 4 + 8 = 24 bytes)
	d := NewDecoder(respData[24:])

	// Skip response type NodeID
	_, err = d.ReadNodeID()
	if err != nil {
		c.metrics.RequestsErrors.Add(1)
		return nil, fmt.Errorf("failed to read response type: %w", err)
	}

	// bodyStart is the current position in the decoder + the 24 bytes we skipped
	bodyStart := 24 + (len(respData[24:]) - d.Remaining())

	duration := time.Since(start)
	c.metrics.RequestsSuccess.Add(1)
	c.metrics.Latency.Observe(duration)

	c.logger.Debug("received response",
		slog.String("service", req.ServiceID().String()),
		slog.Duration("duration", duration))

	return respData[bodyStart:], nil
}

func (c *Client) handleDisconnect(err error) {
	c.mu.Lock()
	wasSessionActive := c.state == StateSessionActive
	wasConnected := c.state >= StateConnected
	c.state = StateDisconnected
	if wasSessionActive {
		c.metrics.ActiveSessions.Add(-1)
	}
	if wasConnected {
		c.metrics.ActiveConns.Add(-1)
	}
	c.mu.Unlock()

	c.transport.Close()

	c.logger.Warn("disconnected", slog.String("error", err.Error()))

	if c.opts.onDisconnect != nil {
		c.opts.onDisconnect(err)
	}
}

func (c *Client) reconnect(ctx context.Context) error {
	backoff := c.opts.reconnectBackoff

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeCh:
			return ErrConnectionClosed
		default:
		}

		c.logger.Info("attempting reconnection",
			slog.String("addr", c.addr),
			slog.Duration("backoff", backoff))

		c.metrics.Reconnections.Add(1)

		// Reset transport
		c.transport = transport.NewTCPTransport(c.addr, c.opts.timeout)

		if err := c.ConnectAndActivateSession(ctx); err == nil {
			c.logger.Info("reconnected", slog.String("addr", c.addr))
			return nil
		}

		// Exponential backoff
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.closeCh:
			return ErrConnectionClosed
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(
			float64(backoff)*2,
			float64(c.opts.maxReconnectTime),
		))
	}
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Don't retry OPC UA protocol errors
	var opcuaErr *OPCUAError
	if errors.As(err, &opcuaErr) {
		return false
	}
	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Retry connection errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return true
}

// Read reads values from the server.
func (c *Client) Read(ctx context.Context, nodesToRead []ReadValueID) ([]DataValue, error) {
	req := &ReadRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		MaxAge:             0,
		TimestampsToReturn: TimestampsToReturnBoth,
		NodesToRead:        nodesToRead,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp ReadResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// ReadValue reads a single value from a node.
func (c *Client) ReadValue(ctx context.Context, nodeID NodeID) (*DataValue, error) {
	results, err := c.Read(ctx, []ReadValueID{
		{NodeID: nodeID, AttributeID: AttributeValue},
	})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrInvalidResponse
	}
	return &results[0], nil
}

// Write writes values to the server.
func (c *Client) Write(ctx context.Context, nodesToWrite []WriteValue) ([]StatusCode, error) {
	req := &WriteRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		NodesToWrite: nodesToWrite,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp WriteResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// WriteValue writes a single value to a node.
func (c *Client) WriteValue(ctx context.Context, nodeID NodeID, value *Variant) error {
	results, err := c.Write(ctx, []WriteValue{
		{
			NodeID:      nodeID,
			AttributeID: AttributeValue,
			Value:       DataValue{Value: value},
		},
	})
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return ErrInvalidResponse
	}
	if results[0].IsBad() {
		return NewOPCUAError(ServiceWrite, results[0], "")
	}
	return nil
}

// Browse browses nodes in the address space.
func (c *Client) Browse(ctx context.Context, nodesToBrowse []BrowseDescription) ([]BrowseResult, error) {
	req := &BrowseRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		RequestedMaxReferencesPerNode: 0, // No limit
		NodesToBrowse:                 nodesToBrowse,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp BrowseResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// BrowseNode browses a single node.
func (c *Client) BrowseNode(ctx context.Context, nodeID NodeID, direction BrowseDirection) ([]ReferenceDescription, error) {
	results, err := c.Browse(ctx, []BrowseDescription{
		{
			NodeID:          nodeID,
			BrowseDirection: direction,
			IncludeSubtypes: true,
			NodeClassMask:   0, // All node classes
			ResultMask:      0x3F, // All fields
		},
	})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrInvalidResponse
	}
	if results[0].StatusCode.IsBad() {
		return nil, NewOPCUAError(ServiceBrowse, results[0].StatusCode, "")
	}
	return results[0].References, nil
}

// Call calls methods on the server.
func (c *Client) Call(ctx context.Context, methodsToCall []CallMethodRequest) ([]CallMethodResult, error) {
	req := &CallRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		MethodsToCall: methodsToCall,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp CallResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	return resp.Results, nil
}

// CallMethod calls a single method.
func (c *Client) CallMethod(ctx context.Context, objectID, methodID NodeID, args ...Variant) ([]Variant, error) {
	results, err := c.Call(ctx, []CallMethodRequest{
		{
			ObjectID:       objectID,
			MethodID:       methodID,
			InputArguments: args,
		},
	})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrInvalidResponse
	}
	if results[0].StatusCode.IsBad() {
		return nil, NewOPCUAError(ServiceCall, results[0].StatusCode, "")
	}
	return results[0].OutputArguments, nil
}

// GetEndpoints retrieves the available endpoints from a server.
func (c *Client) GetEndpoints(ctx context.Context) ([]EndpointDescription, error) {
	req := &GetEndpointsRequest{
		RequestHeader: RequestHeader{
			Timestamp:     time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle: c.requestIDGen.Next(),
			TimeoutHint:   uint32(c.opts.timeout.Milliseconds()),
		},
		EndpointURL: c.opts.endpoint,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp GetEndpointsResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	return resp.Endpoints, nil
}

// Subscription represents an OPC UA subscription.
type Subscription struct {
	ID                      uint32
	RevisedPublishingInterval float64
	RevisedLifetimeCount    uint32
	RevisedMaxKeepAliveCount uint32
	client                  *Client
	monitoredItems          sync.Map // uint32 -> *MonitoredItem
	notificationCh          chan DataChangeNotification
	closeCh                 chan struct{}
}

// MonitoredItem represents an OPC UA monitored item.
type MonitoredItem struct {
	ID                     uint32
	ClientHandle           uint32
	RevisedSamplingInterval float64
	RevisedQueueSize       uint32
	NodeID                 NodeID
	AttributeID            AttributeID
}

// DataChangeNotification represents a data change notification.
type DataChangeNotification struct {
	ClientHandle uint32
	Value        DataValue
}

// CreateSubscription creates a new subscription.
func (c *Client) CreateSubscription(ctx context.Context, opts ...SubscriptionOption) (*Subscription, error) {
	options := defaultSubscriptionOptions()
	for _, opt := range opts {
		opt(options)
	}

	req := &CreateSubscriptionRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: c.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       c.requestIDGen.Next(),
			TimeoutHint:         uint32(c.opts.timeout.Milliseconds()),
		},
		RequestedPublishingInterval: options.publishingInterval,
		RequestedLifetimeCount:      options.lifetimeCount,
		RequestedMaxKeepAliveCount:  options.maxKeepAliveCount,
		MaxNotificationsPerPublish:  options.maxNotifications,
		PublishingEnabled:           options.publishingEnabled,
		Priority:                    options.priority,
	}

	respData, err := c.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp CreateSubscriptionResponseMsg
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	sub := &Subscription{
		ID:                      resp.SubscriptionID,
		RevisedPublishingInterval: resp.RevisedPublishingInterval,
		RevisedLifetimeCount:    resp.RevisedLifetimeCount,
		RevisedMaxKeepAliveCount: resp.RevisedMaxKeepAliveCount,
		client:                  c,
		notificationCh:          make(chan DataChangeNotification, 100),
		closeCh:                 make(chan struct{}),
	}

	c.subscriptions.Store(sub.ID, sub)
	c.metrics.ActiveSubscriptions.Add(1)

	c.logger.Info("subscription created",
		slog.Uint64("subscription_id", uint64(sub.ID)),
		slog.Float64("publishing_interval", sub.RevisedPublishingInterval))

	return sub, nil
}

// CreateMonitoredItems creates monitored items in a subscription.
func (s *Subscription) CreateMonitoredItems(ctx context.Context, itemsToCreate []ReadValueID, opts ...MonitoredItemOption) ([]*MonitoredItem, error) {
	options := defaultMonitoredItemOptions()
	for _, opt := range opts {
		opt(options)
	}

	createRequests := make([]MonitoredItemCreateRequest, len(itemsToCreate))
	for i, item := range itemsToCreate {
		createRequests[i] = MonitoredItemCreateRequest{
			ItemToMonitor:  item,
			MonitoringMode: options.monitoringMode,
			RequestedParameters: MonitoringParameters{
				ClientHandle:     uint32(i + 1),
				SamplingInterval: options.samplingInterval,
				QueueSize:        options.queueSize,
				DiscardOldest:    options.discardOldest,
			},
		}
	}

	req := &CreateMonitoredItemsRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: s.client.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       s.client.requestIDGen.Next(),
			TimeoutHint:         uint32(s.client.opts.timeout.Milliseconds()),
		},
		SubscriptionID:     s.ID,
		TimestampsToReturn: TimestampsToReturnBoth,
		ItemsToCreate:      createRequests,
	}

	respData, err := s.client.send(ctx, req)
	if err != nil {
		return nil, err
	}

	var resp CreateMonitoredItemsResponse
	if err := resp.Decode(respData); err != nil {
		return nil, err
	}

	items := make([]*MonitoredItem, len(resp.Results))
	for i, result := range resp.Results {
		if result.StatusCode.IsBad() {
			continue
		}
		item := &MonitoredItem{
			ID:                     result.MonitoredItemID,
			ClientHandle:           createRequests[i].RequestedParameters.ClientHandle,
			RevisedSamplingInterval: result.RevisedSamplingInterval,
			RevisedQueueSize:       result.RevisedQueueSize,
			NodeID:                 itemsToCreate[i].NodeID,
			AttributeID:            itemsToCreate[i].AttributeID,
		}
		items[i] = item
		s.monitoredItems.Store(item.ID, item)
		s.client.metrics.MonitoredItems.Add(1)
	}

	return items, nil
}

// Delete deletes the subscription.
func (s *Subscription) Delete(ctx context.Context) error {
	req := &DeleteSubscriptionsRequest{
		RequestHeader: RequestHeader{
			AuthenticationToken: s.client.authenticationToken,
			Timestamp:           time.Now().UnixNano() / 100 + 116444736000000000,
			RequestHandle:       s.client.requestIDGen.Next(),
			TimeoutHint:         uint32(s.client.opts.timeout.Milliseconds()),
		},
		SubscriptionIDs: []uint32{s.ID},
	}

	respData, err := s.client.send(ctx, req)
	if err != nil {
		return err
	}

	var resp DeleteSubscriptionsResponse
	if err := resp.Decode(respData); err != nil {
		return err
	}

	if len(resp.Results) > 0 && resp.Results[0].IsBad() {
		return NewOPCUAError(ServiceDeleteSubscriptions, resp.Results[0], "")
	}

	s.client.subscriptions.Delete(s.ID)
	s.client.metrics.ActiveSubscriptions.Add(-1)
	close(s.closeCh)

	return nil
}

// Notifications returns the channel for receiving data change notifications.
func (s *Subscription) Notifications() <-chan DataChangeNotification {
	return s.notificationCh
}

// Run starts the publish loop for receiving notifications.
// This should be called in a goroutine after creating monitored items.
func (s *Subscription) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.RevisedPublishingInterval) * time.Millisecond)
	defer ticker.Stop()

	var acks []SubscriptionAcknowledgement

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeCh:
			return
		case <-ticker.C:
			// Send Publish request
			req := &PublishRequest{
				RequestHeader: RequestHeader{
					AuthenticationToken: s.client.authenticationToken,
					Timestamp:           time.Now().UnixNano()/100 + 116444736000000000,
					RequestHandle:       s.client.requestIDGen.Next(),
					TimeoutHint:         uint32(s.RevisedPublishingInterval * 2),
				},
				SubscriptionAcknowledgements: acks,
			}

			respData, err := s.client.send(ctx, req)
			if err != nil {
				s.client.logger.Debug("publish request failed", slog.String("error", err.Error()))
				continue
			}

			var resp PublishResponse
			if err := resp.Decode(respData); err != nil {
				s.client.logger.Debug("failed to decode publish response", slog.String("error", err.Error()))
				continue
			}

			// Acknowledge this notification
			acks = []SubscriptionAcknowledgement{
				{
					SubscriptionID: resp.SubscriptionID,
					SequenceNumber: resp.NotificationMessage.SequenceNumber,
				},
			}

			// Process notifications - extract from raw notification data
			s.processNotifications(&resp)
		}
	}
}

// processNotifications extracts data change notifications from the publish response.
func (s *Subscription) processNotifications(resp *PublishResponse) {
	for _, notifData := range resp.NotificationMessage.NotificationData {
		if dcn, ok := notifData.(*DataChangeNotificationData); ok {
			for _, item := range dcn.MonitoredItems {
				select {
				case s.notificationCh <- DataChangeNotification{
					ClientHandle: item.ClientHandle,
					Value:        item.Value,
				}:
				default:
					// Channel full, drop notification
					s.client.logger.Warn("notification channel full, dropping notification")
				}
			}
		}
	}
}
