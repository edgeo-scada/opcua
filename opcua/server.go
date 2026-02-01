package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server is an OPC UA TCP server.
type Server struct {
	addr     string
	opts     *serverOptions
	handler  Handler
	listener net.Listener
	metrics  *ServerMetrics
	logger   *slog.Logger

	mu       sync.Mutex
	running  bool
	closeCh  chan struct{}
	sessions sync.Map // sessionID -> *serverSession
	connCount int32
}

// serverSession represents a server-side session.
type serverSession struct {
	id                 uint32
	authenticationToken NodeID
	timeout            float64
	conn               net.Conn
	secureChannelID    uint32
	tokenID            uint32
	seqNumGen          SequenceNumberGenerator
	lastActivity       time.Time
}

// NewServer creates a new OPC UA TCP server.
func NewServer(addr string, handler Handler, opts ...ServerOption) (*Server, error) {
	if addr == "" {
		return nil, errors.New("opcua: address cannot be empty")
	}
	if handler == nil {
		return nil, errors.New("opcua: handler cannot be nil")
	}

	options := defaultServerOptions()
	options.endpoint = addr
	for _, opt := range opts {
		opt(options)
	}

	return &Server{
		addr:    addr,
		opts:    options,
		handler: handler,
		metrics: NewServerMetrics(),
		logger:  options.logger,
		closeCh: make(chan struct{}),
	}, nil
}

// Start starts the server.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("opcua: server already running")
	}

	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("opcua: listen failed: %w", err)
	}

	s.listener = listener
	s.running = true
	s.mu.Unlock()

	s.logger.Info("server started", slog.String("addr", s.addr))

	go s.acceptLoop()

	return nil
}

// Stop stops the server.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.closeCh)
	s.mu.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}

	// Close all sessions
	s.sessions.Range(func(key, value interface{}) bool {
		session := value.(*serverSession)
		session.conn.Close()
		return true
	})

	s.logger.Info("server stopped")
	return nil
}

// Metrics returns the server metrics.
func (s *Server) Metrics() *ServerMetrics {
	return s.metrics
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closeCh:
				return
			default:
				s.logger.Error("accept failed", slog.String("error", err.Error()))
				continue
			}
		}

		// Check connection limit
		if int(atomic.LoadInt32(&s.connCount)) >= s.opts.maxConns {
			s.logger.Warn("connection limit reached, rejecting connection")
			conn.Close()
			continue
		}

		atomic.AddInt32(&s.connCount, 1)
		s.metrics.ActiveConnections.Add(1)

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		atomic.AddInt32(&s.connCount, -1)
		s.metrics.ActiveConnections.Add(-1)
	}()

	// Enable TCP keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	s.logger.Debug("new connection", slog.String("remote", conn.RemoteAddr().String()))

	var session *serverSession

	for {
		select {
		case <-s.closeCh:
			return
		default:
		}

		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(s.opts.readTimeout))

		// Read message header
		header := make([]byte, 8)
		_, err := io.ReadFull(conn, header)
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				s.logger.Debug("read header failed", slog.String("error", err.Error()))
			}
			return
		}

		msgType := string(header[0:3])
		messageSize := binary.LittleEndian.Uint32(header[4:8])

		if messageSize < 8 || messageSize > 16*1024*1024 {
			s.logger.Warn("invalid message size", slog.Uint64("size", uint64(messageSize)))
			return
		}

		// Read message body
		body := make([]byte, messageSize-8)
		_, err = io.ReadFull(conn, body)
		if err != nil {
			s.logger.Debug("read body failed", slog.String("error", err.Error()))
			return
		}

		s.metrics.TotalRequests.Add(1)

		// Handle message based on type
		var response []byte
		switch msgType {
		case MessageTypeHello:
			response, err = s.handleHello(body)
		case MessageTypeOpenChannel:
			response, session, err = s.handleOpenSecureChannel(conn, body)
		case MessageTypeMessage:
			response, err = s.handleMessage(session, header, body)
		case MessageTypeCloseChannel:
			s.handleCloseSecureChannel(session)
			return
		default:
			s.logger.Warn("unknown message type", slog.String("type", msgType))
			return
		}

		if err != nil {
			s.logger.Debug("handle message failed", slog.String("error", err.Error()))
			s.metrics.Errors.Add(1)
			// Send error response
			errResp := s.buildErrorResponse(0x80010000, err.Error())
			conn.Write(errResp)
			return
		}

		if response != nil {
			conn.SetWriteDeadline(time.Now().Add(s.opts.readTimeout))
			_, err = conn.Write(response)
			if err != nil {
				s.logger.Debug("write response failed", slog.String("error", err.Error()))
				return
			}
		}
	}
}

func (s *Server) handleHello(body []byte) ([]byte, error) {
	var hello HelloMessage
	if err := hello.Decode(body); err != nil {
		return nil, err
	}

	s.logger.Debug("received hello",
		slog.String("endpoint", hello.EndpointURL),
		slog.Uint64("protocol_version", uint64(hello.ProtocolVersion)))

	// Build Acknowledge response
	ack := AcknowledgeMessage{
		ProtocolVersion:   ProtocolVersion,
		ReceiveBufferSize: DefaultReceiveBufferSize,
		SendBufferSize:    DefaultSendBufferSize,
		MaxMessageSize:    DefaultMaxMessageSize,
		MaxChunkCount:     MaxChunkCount,
	}

	ackData := ack.Encode()
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + len(ackData)),
	}
	copy(header.MessageType[:], MessageTypeAcknowledge)

	return append(header.Encode(), ackData...), nil
}

func (s *Server) handleOpenSecureChannel(conn net.Conn, body []byte) ([]byte, *serverSession, error) {
	// Parse secure channel ID (first 4 bytes after header)
	if len(body) < 4 {
		return nil, nil, errors.New("message too short")
	}

	// Create new session
	session := &serverSession{
		id:              uint32(time.Now().UnixNano() & 0xFFFFFFFF),
		secureChannelID: uint32(time.Now().UnixNano() & 0xFFFFFFFF),
		tokenID:         uint32(time.Now().UnixNano() & 0xFFFFFFFF),
		conn:            conn,
		lastActivity:    time.Now(),
	}

	s.sessions.Store(session.secureChannelID, session)
	s.metrics.ActiveSessions.Add(1)

	s.logger.Debug("opened secure channel",
		slog.Uint64("channel_id", uint64(session.secureChannelID)),
		slog.Uint64("token_id", uint64(session.tokenID)))

	// Build response
	e := NewEncoder()

	// Secure channel ID
	e.WriteUInt32(session.secureChannelID)

	// Security header
	e.WriteString(string(SecurityPolicyNone))
	e.WriteByteString(nil) // Sender certificate
	e.WriteByteString(nil) // Receiver certificate thumbprint

	// Sequence header
	seqNum := session.seqNumGen.Next()
	e.WriteUInt32(seqNum)
	e.WriteUInt32(1) // Request ID

	// OpenSecureChannelResponse type ID
	e.WriteNodeID(NewNumericNodeID(0, 449))

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000) // Timestamp
	e.WriteUInt32(1)                        // RequestHandle
	e.WriteStatusCode(StatusGood)           // ServiceResult
	e.WriteByte(0)                          // ServiceDiagnostics (null)
	e.WriteInt32(0)                         // StringTable (empty)
	e.WriteByte(0)                          // AdditionalHeader (null)

	// OpenSecureChannelResponse body
	e.WriteUInt32(0)                        // ServerProtocolVersion
	e.WriteUInt32(session.secureChannelID)  // SecurityToken.ChannelId
	e.WriteUInt32(session.tokenID)          // SecurityToken.TokenId
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000) // SecurityToken.CreatedAt
	e.WriteUInt32(3600000)                  // SecurityToken.RevisedLifetime
	e.WriteByteString(nil)                  // ServerNonce

	responseBody := e.Bytes()

	// Build message header
	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + len(responseBody)),
	}
	copy(header.MessageType[:], MessageTypeOpenChannel)

	return append(header.Encode(), responseBody...), session, nil
}

func (s *Server) handleMessage(session *serverSession, header, body []byte) ([]byte, error) {
	if session == nil {
		return nil, errors.New("no active session")
	}

	session.lastActivity = time.Now()

	// Skip secure channel ID (4 bytes) + token ID (4 bytes) + sequence header (8 bytes)
	if len(body) < 16 {
		return nil, errors.New("message too short")
	}

	// Find request type ID
	d := NewDecoder(body[16:])
	typeID, err := d.ReadNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to read type ID: %w", err)
	}

	serviceID := ServiceID(typeID.Numeric)

	s.logger.Debug("handling service request",
		slog.String("service", serviceID.String()),
		slog.Uint64("type_id", uint64(typeID.Numeric)))

	// Handle based on service
	var responseBody []byte
	switch serviceID {
	case ServiceGetEndpoints:
		responseBody, err = s.handleGetEndpoints(d)
	case ServiceRead:
		responseBody, err = s.handleRead(d)
	case ServiceWrite:
		responseBody, err = s.handleWrite(d)
	case ServiceBrowse:
		responseBody, err = s.handleBrowse(d)
	case ServiceCreateSubscription:
		responseBody, err = s.handleCreateSubscription(d)
	case ServiceCreateMonitoredItems:
		responseBody, err = s.handleCreateMonitoredItems(d)
	case ServiceDeleteSubscriptions:
		responseBody, err = s.handleDeleteSubscriptions(d)
	case ServicePublish:
		responseBody, err = s.handlePublish(d)
	default:
		return nil, fmt.Errorf("unsupported service: %s", serviceID)
	}

	if err != nil {
		return nil, err
	}

	// Build response message
	e := NewEncoder()

	// Secure channel ID
	e.WriteUInt32(session.secureChannelID)

	// Security header
	e.WriteUInt32(session.tokenID)

	// Sequence header
	seqNum := session.seqNumGen.Next()
	e.WriteUInt32(seqNum)
	e.WriteUInt32(1) // Request ID

	// Response type ID (service ID + 3 for response)
	e.WriteNodeID(NewNumericNodeID(0, uint32(serviceID)+3))

	// Response body
	e.buf.Write(responseBody)

	msgBody := e.Bytes()

	// Message header
	msgHeader := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + len(msgBody)),
	}
	copy(msgHeader.MessageType[:], MessageTypeMessage)

	return append(msgHeader.Encode(), msgBody...), nil
}

func (s *Server) handleCloseSecureChannel(session *serverSession) {
	if session == nil {
		return
	}
	s.sessions.Delete(session.secureChannelID)
	s.metrics.ActiveSessions.Add(-1)
	s.logger.Debug("closed secure channel", slog.Uint64("channel_id", uint64(session.secureChannelID)))
}

func (s *Server) handleGetEndpoints(d *Decoder) ([]byte, error) {
	// Skip request header
	// For simplicity, return a basic endpoint

	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)  // DiagnosticInfo
	e.WriteInt32(0) // StringTable
	e.WriteByte(0)  // AdditionalHeader

	// Endpoints array (1 endpoint)
	e.WriteInt32(1)

	// EndpointDescription
	e.WriteString(s.opts.endpoint) // EndpointURL

	// Server (ApplicationDescription)
	e.WriteString(s.opts.applicationURI)
	e.WriteString(s.opts.productURI)
	e.WriteLocalizedText(LocalizedText{Text: s.opts.applicationName})
	e.WriteUInt32(uint32(ApplicationTypeServer))
	e.WriteString("")  // GatewayServerURI
	e.WriteString("")  // DiscoveryProfileURI
	e.WriteInt32(1)    // DiscoveryURLs
	e.WriteString(s.opts.endpoint)

	e.WriteByteString(s.opts.certificate) // ServerCertificate
	e.WriteUInt32(uint32(MessageSecurityModeNone))
	e.WriteString(string(SecurityPolicyNone))

	// UserIdentityTokens (1 token - anonymous)
	e.WriteInt32(1)
	e.WriteString("anonymous")
	e.WriteUInt32(uint32(UserTokenTypeAnonymous))
	e.WriteString("")
	e.WriteString("")
	e.WriteString("")

	e.WriteString("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
	e.WriteByte(0) // SecurityLevel

	return e.Bytes(), nil
}

func (s *Server) handleRead(d *Decoder) ([]byte, error) {
	// Skip request header (simplified)
	// In a full implementation, parse the complete request

	// Call handler
	results, err := s.handler.Read(0, TimestampsToReturnBoth, nil)
	if err != nil {
		return nil, err
	}

	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// Results
	e.WriteInt32(int32(len(results)))
	for _, dv := range results {
		encodeDataValue(e, &dv)
	}

	// DiagnosticInfos
	e.WriteInt32(0)

	return e.Bytes(), nil
}

func (s *Server) handleWrite(d *Decoder) ([]byte, error) {
	results, err := s.handler.Write(nil)
	if err != nil {
		return nil, err
	}

	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// Results
	e.WriteInt32(int32(len(results)))
	for _, sc := range results {
		e.WriteStatusCode(sc)
	}

	// DiagnosticInfos
	e.WriteInt32(0)

	return e.Bytes(), nil
}

func (s *Server) handleBrowse(d *Decoder) ([]byte, error) {
	results, err := s.handler.Browse(nil, 0)
	if err != nil {
		return nil, err
	}

	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// Results
	e.WriteInt32(int32(len(results)))
	for _, br := range results {
		e.WriteStatusCode(br.StatusCode)
		e.WriteByteString(br.ContinuationPoint)
		e.WriteInt32(int32(len(br.References)))
		for _, ref := range br.References {
			e.WriteNodeID(ref.ReferenceTypeID)
			e.WriteBoolean(ref.IsForward)
			e.WriteByte(0) // ExpandedNodeID encoding
			e.WriteNodeID(ref.NodeID)
			e.WriteQualifiedName(ref.BrowseName)
			e.WriteLocalizedText(ref.DisplayName)
			e.WriteUInt32(uint32(ref.NodeClass))
			e.WriteByte(0) // TypeDefinition (ExpandedNodeID)
			e.WriteNodeID(ref.TypeDefinition)
		}
	}

	// DiagnosticInfos
	e.WriteInt32(0)

	return e.Bytes(), nil
}

func (s *Server) handleCreateSubscription(d *Decoder) ([]byte, error) {
	// Create a subscription (simplified)
	subID := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// CreateSubscriptionResponse
	e.WriteUInt32(subID)
	e.WriteDouble(1000) // RevisedPublishingInterval
	e.WriteUInt32(10000) // RevisedLifetimeCount
	e.WriteUInt32(10) // RevisedMaxKeepAliveCount

	s.metrics.ActiveSubscriptions.Add(1)

	return e.Bytes(), nil
}

func (s *Server) handleCreateMonitoredItems(d *Decoder) ([]byte, error) {
	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// Results (empty for now)
	e.WriteInt32(0)

	// DiagnosticInfos
	e.WriteInt32(0)

	return e.Bytes(), nil
}

func (s *Server) handleDeleteSubscriptions(d *Decoder) ([]byte, error) {
	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// Results (empty for now)
	e.WriteInt32(0)

	// DiagnosticInfos
	e.WriteInt32(0)

	s.metrics.ActiveSubscriptions.Add(-1)

	return e.Bytes(), nil
}

func (s *Server) handlePublish(d *Decoder) ([]byte, error) {
	e := NewEncoder()

	// Response header
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000)
	e.WriteUInt32(1)
	e.WriteStatusCode(StatusGood)
	e.WriteByte(0)
	e.WriteInt32(0)
	e.WriteByte(0)

	// PublishResponse
	e.WriteUInt32(0)     // SubscriptionID
	e.WriteInt32(0)      // AvailableSequenceNumbers
	e.WriteBoolean(false) // MoreNotifications

	// NotificationMessage
	e.WriteUInt32(0)     // SequenceNumber
	e.WriteInt64(time.Now().UnixNano() / 100 + 116444736000000000) // PublishTime
	e.WriteInt32(0)      // NotificationData

	// Results
	e.WriteInt32(0)

	// DiagnosticInfos
	e.WriteInt32(0)

	return e.Bytes(), nil
}

func (s *Server) buildErrorResponse(errorCode uint32, reason string) []byte {
	errMsg := ErrorMessage{
		Error:  errorCode,
		Reason: reason,
	}
	errData := errMsg.Encode()

	header := MessageHeader{
		ChunkType:   ChunkTypeFinal,
		MessageSize: uint32(8 + len(errData)),
	}
	copy(header.MessageType[:], MessageTypeError)

	return append(header.Encode(), errData...)
}

// MemoryHandler is a simple in-memory implementation of the Handler interface.
type MemoryHandler struct {
	mu       sync.RWMutex
	nodes    map[string]*memoryNode
}

type memoryNode struct {
	nodeID      NodeID
	nodeClass   NodeClass
	browseName  QualifiedName
	displayName LocalizedText
	description LocalizedText
	value       *Variant
	dataType    NodeID
	references  []ReferenceDescription
}

// NewMemoryHandler creates a new in-memory handler.
func NewMemoryHandler() *MemoryHandler {
	h := &MemoryHandler{
		nodes: make(map[string]*memoryNode),
	}
	h.initDefaultNodes()
	return h
}

func (h *MemoryHandler) initDefaultNodes() {
	// Add root node
	h.nodes["i=84"] = &memoryNode{
		nodeID:      NewNumericNodeID(0, 84),
		nodeClass:   NodeClassObject,
		browseName:  QualifiedName{Name: "Root"},
		displayName: LocalizedText{Text: "Root"},
	}

	// Add Objects folder
	h.nodes["i=85"] = &memoryNode{
		nodeID:      NewNumericNodeID(0, 85),
		nodeClass:   NodeClassObject,
		browseName:  QualifiedName{Name: "Objects"},
		displayName: LocalizedText{Text: "Objects"},
	}

	// Add Server node
	h.nodes["i=2253"] = &memoryNode{
		nodeID:      NewNumericNodeID(0, 2253),
		nodeClass:   NodeClassObject,
		browseName:  QualifiedName{Name: "Server"},
		displayName: LocalizedText{Text: "Server"},
	}
}

func (h *MemoryHandler) FindServers(endpointURL string) ([]ApplicationDescription, error) {
	return []ApplicationDescription{}, nil
}

func (h *MemoryHandler) GetEndpoints(endpointURL string) ([]EndpointDescription, error) {
	return []EndpointDescription{}, nil
}

func (h *MemoryHandler) CreateSession(clientDescription ApplicationDescription, serverURI string, endpointURL string, sessionName string, clientNonce []byte, clientCertificate []byte, requestedSessionTimeout float64, maxResponseMessageSize uint32) (*CreateSessionResponse, error) {
	return &CreateSessionResponse{}, nil
}

func (h *MemoryHandler) ActivateSession(clientSignature SignatureData, clientSoftwareCertificates []SignedSoftwareCertificate, localeIDs []string, userIdentityToken interface{}, userTokenSignature SignatureData) (*ActivateSessionResponse, error) {
	return &ActivateSessionResponse{}, nil
}

func (h *MemoryHandler) CloseSession(deleteSubscriptions bool) error {
	return nil
}

func (h *MemoryHandler) Browse(nodesToBrowse []BrowseDescription, maxReferencesPerNode uint32) ([]BrowseResult, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	results := make([]BrowseResult, len(nodesToBrowse))
	for i, desc := range nodesToBrowse {
		key := fmt.Sprintf("i=%d", desc.NodeID.Numeric)
		if node, ok := h.nodes[key]; ok {
			results[i] = BrowseResult{
				StatusCode: StatusGood,
				References: node.references,
			}
		} else {
			results[i] = BrowseResult{
				StatusCode: StatusBadNodeIdUnknown,
			}
		}
	}
	return results, nil
}

func (h *MemoryHandler) BrowseNext(releaseContinuationPoints bool, continuationPoints [][]byte) ([]BrowseResult, error) {
	return []BrowseResult{}, nil
}

func (h *MemoryHandler) TranslateBrowsePathsToNodeIds(browsePaths []BrowsePath) ([]BrowsePathResult, error) {
	return []BrowsePathResult{}, nil
}

func (h *MemoryHandler) RegisterNodes(nodesToRegister []NodeID) ([]NodeID, error) {
	return nodesToRegister, nil
}

func (h *MemoryHandler) UnregisterNodes(nodesToUnregister []NodeID) error {
	return nil
}

func (h *MemoryHandler) Read(maxAge float64, timestampsToReturn TimestampsToReturn, nodesToRead []ReadValueID) ([]DataValue, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	results := make([]DataValue, len(nodesToRead))
	for i, req := range nodesToRead {
		key := fmt.Sprintf("i=%d", req.NodeID.Numeric)
		if node, ok := h.nodes[key]; ok {
			results[i] = DataValue{
				Value:           node.value,
				StatusCode:      StatusGood,
				SourceTimestamp: time.Now(),
				ServerTimestamp: time.Now(),
			}
		} else {
			results[i] = DataValue{
				StatusCode: StatusBadNodeIdUnknown,
			}
		}
	}
	return results, nil
}

func (h *MemoryHandler) Write(nodesToWrite []WriteValue) ([]StatusCode, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	results := make([]StatusCode, len(nodesToWrite))
	for i, req := range nodesToWrite {
		key := fmt.Sprintf("i=%d", req.NodeID.Numeric)
		if node, ok := h.nodes[key]; ok {
			if node.nodeClass == NodeClassVariable {
				node.value = req.Value.Value
				results[i] = StatusGood
			} else {
				results[i] = StatusBadNotWritable
			}
		} else {
			results[i] = StatusBadNodeIdUnknown
		}
	}
	return results, nil
}

func (h *MemoryHandler) HistoryRead(historyReadDetails interface{}, timestampsToReturn TimestampsToReturn, releaseContinuationPoints bool, nodesToRead []HistoryReadValueID) ([]HistoryReadResult, error) {
	return []HistoryReadResult{}, nil
}

func (h *MemoryHandler) Call(methodsToCall []CallMethodRequest) ([]CallMethodResult, error) {
	results := make([]CallMethodResult, len(methodsToCall))
	for i := range methodsToCall {
		results[i] = CallMethodResult{
			StatusCode: StatusBadMethodInvalid,
		}
	}
	return results, nil
}

func (h *MemoryHandler) CreateSubscription(requestedPublishingInterval float64, requestedLifetimeCount uint32, requestedMaxKeepAliveCount uint32, maxNotificationsPerPublish uint32, publishingEnabled bool, priority uint8) (*CreateSubscriptionResponse, error) {
	return &CreateSubscriptionResponse{
		SubscriptionID:            uint32(time.Now().UnixNano() & 0xFFFFFFFF),
		RevisedPublishingInterval: requestedPublishingInterval,
		RevisedLifetimeCount:      requestedLifetimeCount,
		RevisedMaxKeepAliveCount:  requestedMaxKeepAliveCount,
	}, nil
}

func (h *MemoryHandler) ModifySubscription(subscriptionID uint32, requestedPublishingInterval float64, requestedLifetimeCount uint32, requestedMaxKeepAliveCount uint32, maxNotificationsPerPublish uint32, priority uint8) (*ModifySubscriptionResponse, error) {
	return &ModifySubscriptionResponse{}, nil
}

func (h *MemoryHandler) DeleteSubscriptions(subscriptionIDs []uint32) ([]StatusCode, error) {
	results := make([]StatusCode, len(subscriptionIDs))
	for i := range subscriptionIDs {
		results[i] = StatusGood
	}
	return results, nil
}

func (h *MemoryHandler) SetPublishingMode(publishingEnabled bool, subscriptionIDs []uint32) ([]StatusCode, error) {
	results := make([]StatusCode, len(subscriptionIDs))
	for i := range subscriptionIDs {
		results[i] = StatusGood
	}
	return results, nil
}

func (h *MemoryHandler) CreateMonitoredItems(subscriptionID uint32, timestampsToReturn TimestampsToReturn, itemsToCreate []MonitoredItemCreateRequest) ([]MonitoredItemCreateResult, error) {
	results := make([]MonitoredItemCreateResult, len(itemsToCreate))
	for i, item := range itemsToCreate {
		results[i] = MonitoredItemCreateResult{
			StatusCode:             StatusGood,
			MonitoredItemID:        uint32(i + 1),
			RevisedSamplingInterval: item.RequestedParameters.SamplingInterval,
			RevisedQueueSize:       item.RequestedParameters.QueueSize,
		}
	}
	return results, nil
}

func (h *MemoryHandler) ModifyMonitoredItems(subscriptionID uint32, timestampsToReturn TimestampsToReturn, itemsToModify []MonitoredItemModifyRequest) ([]MonitoredItemModifyResult, error) {
	return []MonitoredItemModifyResult{}, nil
}

func (h *MemoryHandler) DeleteMonitoredItems(subscriptionID uint32, monitoredItemIDs []uint32) ([]StatusCode, error) {
	results := make([]StatusCode, len(monitoredItemIDs))
	for i := range monitoredItemIDs {
		results[i] = StatusGood
	}
	return results, nil
}

func (h *MemoryHandler) SetMonitoringMode(subscriptionID uint32, monitoringMode MonitoringMode, monitoredItemIDs []uint32) ([]StatusCode, error) {
	results := make([]StatusCode, len(monitoredItemIDs))
	for i := range monitoredItemIDs {
		results[i] = StatusGood
	}
	return results, nil
}

// SetValue sets a value for a node.
func (h *MemoryHandler) SetValue(nodeID NodeID, value *Variant) {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := fmt.Sprintf("i=%d", nodeID.Numeric)
	if node, ok := h.nodes[key]; ok {
		node.value = value
	} else {
		h.nodes[key] = &memoryNode{
			nodeID:    nodeID,
			nodeClass: NodeClassVariable,
			value:     value,
		}
	}
}

// AddNode adds a new node.
func (h *MemoryHandler) AddNode(nodeID NodeID, nodeClass NodeClass, browseName string, displayName string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := fmt.Sprintf("i=%d", nodeID.Numeric)
	h.nodes[key] = &memoryNode{
		nodeID:      nodeID,
		nodeClass:   nodeClass,
		browseName:  QualifiedName{Name: browseName},
		displayName: LocalizedText{Text: displayName},
	}
}
