package opcua

import (
	"crypto/tls"
	"log/slog"
	"time"
)

// Option is a functional option for configuring the client.
type Option func(*clientOptions)

type clientOptions struct {
	// Connection settings
	endpoint string
	timeout  time.Duration

	// Security settings
	securityPolicy    SecurityPolicy
	securityMode      MessageSecurityMode
	certificate       []byte // PEM encoded
	privateKey        []byte // PEM encoded
	serverCertificate []byte // PEM encoded (optional, for servers requiring security)
	tlsConfig         *tls.Config

	// Session settings
	sessionName    string
	sessionTimeout time.Duration

	// Authentication settings
	authType     AuthType
	username     string
	password     string
	userCert     []byte
	userKey      []byte

	// Reconnection settings
	autoReconnect    bool
	reconnectBackoff time.Duration
	maxReconnectTime time.Duration
	maxRetries       int

	// Callbacks
	onConnect    func()
	onDisconnect func(error)
	onSessionActivated func()
	onSessionClosed func(error)

	// Logging
	logger *slog.Logger

	// Pool settings (for pool creation)
	poolSize int

	// Application description
	applicationURI  string
	productURI      string
	applicationName string
}

// AuthType represents the type of authentication.
type AuthType int

const (
	AuthTypeAnonymous AuthType = iota
	AuthTypeUserPassword
	AuthTypeCertificate
)

func defaultOptions() *clientOptions {
	return &clientOptions{
		timeout:          DefaultTimeout,
		securityPolicy:   SecurityPolicyNone,
		securityMode:     MessageSecurityModeNone,
		sessionName:      "OPC UA Client Session",
		sessionTimeout:   time.Hour,
		authType:         AuthTypeAnonymous,
		autoReconnect:    false,
		reconnectBackoff: 1 * time.Second,
		maxReconnectTime: 30 * time.Second,
		maxRetries:       3,
		logger:           slog.Default(),
		poolSize:         5,
		applicationURI:   "urn:edgeo:opcua:client",
		productURI:       "urn:edgeo:opcua",
		applicationName:  "Edgeo OPC UA Client",
	}
}

// WithEndpoint sets the endpoint URL.
func WithEndpoint(endpoint string) Option {
	return func(o *clientOptions) {
		o.endpoint = endpoint
	}
}

// WithTimeout sets the timeout for operations.
func WithTimeout(d time.Duration) Option {
	return func(o *clientOptions) {
		o.timeout = d
	}
}

// WithSecurityPolicy sets the security policy.
func WithSecurityPolicy(policy SecurityPolicy) Option {
	return func(o *clientOptions) {
		o.securityPolicy = policy
	}
}

// WithSecurityMode sets the security mode.
func WithSecurityMode(mode MessageSecurityMode) Option {
	return func(o *clientOptions) {
		o.securityMode = mode
	}
}

// WithCertificate sets the client certificate and private key (PEM encoded).
func WithCertificate(cert, key []byte) Option {
	return func(o *clientOptions) {
		o.certificate = cert
		o.privateKey = key
	}
}

// WithRemoteCertificate sets the remote server's certificate (PEM encoded).
// This is required when connecting to servers that don't support SecurityPolicyNone
// for discovery. You can obtain this certificate out-of-band or from a configuration file.
func WithRemoteCertificate(cert []byte) Option {
	return func(o *clientOptions) {
		o.serverCertificate = cert
	}
}

// WithTLSConfig sets the TLS configuration.
func WithTLSConfig(config *tls.Config) Option {
	return func(o *clientOptions) {
		o.tlsConfig = config
	}
}

// WithSessionName sets the session name.
func WithSessionName(name string) Option {
	return func(o *clientOptions) {
		o.sessionName = name
	}
}

// WithSessionTimeout sets the session timeout.
func WithSessionTimeout(d time.Duration) Option {
	return func(o *clientOptions) {
		o.sessionTimeout = d
	}
}

// WithAnonymousAuth configures anonymous authentication.
func WithAnonymousAuth() Option {
	return func(o *clientOptions) {
		o.authType = AuthTypeAnonymous
	}
}

// WithUserPasswordAuth configures username/password authentication.
func WithUserPasswordAuth(username, password string) Option {
	return func(o *clientOptions) {
		o.authType = AuthTypeUserPassword
		o.username = username
		o.password = password
	}
}

// WithCertificateAuth configures certificate authentication.
func WithCertificateAuth(cert, key []byte) Option {
	return func(o *clientOptions) {
		o.authType = AuthTypeCertificate
		o.userCert = cert
		o.userKey = key
	}
}

// WithAutoReconnect enables automatic reconnection on connection loss.
func WithAutoReconnect(enable bool) Option {
	return func(o *clientOptions) {
		o.autoReconnect = enable
	}
}

// WithReconnectBackoff sets the initial backoff duration for reconnection attempts.
func WithReconnectBackoff(d time.Duration) Option {
	return func(o *clientOptions) {
		o.reconnectBackoff = d
	}
}

// WithMaxReconnectTime sets the maximum time between reconnection attempts.
func WithMaxReconnectTime(d time.Duration) Option {
	return func(o *clientOptions) {
		o.maxReconnectTime = d
	}
}

// WithMaxRetries sets the maximum number of retries for operations.
func WithMaxRetries(n int) Option {
	return func(o *clientOptions) {
		o.maxRetries = n
	}
}

// WithOnConnect sets a callback to be called when the connection is established.
func WithOnConnect(fn func()) Option {
	return func(o *clientOptions) {
		o.onConnect = fn
	}
}

// WithOnDisconnect sets a callback to be called when the connection is lost.
func WithOnDisconnect(fn func(error)) Option {
	return func(o *clientOptions) {
		o.onDisconnect = fn
	}
}

// WithOnSessionActivated sets a callback to be called when the session is activated.
func WithOnSessionActivated(fn func()) Option {
	return func(o *clientOptions) {
		o.onSessionActivated = fn
	}
}

// WithOnSessionClosed sets a callback to be called when the session is closed.
func WithOnSessionClosed(fn func(error)) Option {
	return func(o *clientOptions) {
		o.onSessionClosed = fn
	}
}

// WithLogger sets the logger for the client.
func WithLogger(logger *slog.Logger) Option {
	return func(o *clientOptions) {
		o.logger = logger
	}
}

// WithPoolSize sets the connection pool size.
func WithPoolSize(size int) Option {
	return func(o *clientOptions) {
		o.poolSize = size
	}
}

// WithApplicationURI sets the application URI.
func WithApplicationURI(uri string) Option {
	return func(o *clientOptions) {
		o.applicationURI = uri
	}
}

// WithProductURI sets the product URI.
func WithProductURI(uri string) Option {
	return func(o *clientOptions) {
		o.productURI = uri
	}
}

// WithApplicationName sets the application name.
func WithApplicationName(name string) Option {
	return func(o *clientOptions) {
		o.applicationName = name
	}
}

// ServerOption is a functional option for configuring the server.
type ServerOption func(*serverOptions)

type serverOptions struct {
	logger        *slog.Logger
	maxConns      int
	readTimeout   time.Duration
	endpoint      string
	serverName    string

	// Security settings
	securityPolicies []SecurityPolicy
	securityModes    []MessageSecurityMode
	certificate      []byte
	privateKey       []byte

	// User authentication
	userValidator UserValidator

	// Application description
	applicationURI  string
	productURI      string
	applicationName string
}

// UserValidator validates user credentials.
type UserValidator interface {
	ValidateAnonymous() error
	ValidateUserPassword(username, password string) error
	ValidateCertificate(cert []byte) error
}

func defaultServerOptions() *serverOptions {
	return &serverOptions{
		logger:           slog.Default(),
		maxConns:         100,
		readTimeout:      30 * time.Second,
		securityPolicies: []SecurityPolicy{SecurityPolicyNone},
		securityModes:    []MessageSecurityMode{MessageSecurityModeNone},
		applicationURI:   "urn:edgeo:opcua:server",
		productURI:       "urn:edgeo:opcua",
		applicationName:  "Edgeo OPC UA Server",
	}
}

// WithServerLogger sets the logger for the server.
func WithServerLogger(logger *slog.Logger) ServerOption {
	return func(o *serverOptions) {
		o.logger = logger
	}
}

// WithMaxConnections sets the maximum number of concurrent connections.
func WithMaxConnections(n int) ServerOption {
	return func(o *serverOptions) {
		o.maxConns = n
	}
}

// WithReadTimeout sets the read timeout for client connections.
func WithReadTimeout(d time.Duration) ServerOption {
	return func(o *serverOptions) {
		o.readTimeout = d
	}
}

// WithServerEndpoint sets the server endpoint URL.
func WithServerEndpoint(endpoint string) ServerOption {
	return func(o *serverOptions) {
		o.endpoint = endpoint
	}
}

// WithServerName sets the server name.
func WithServerName(name string) ServerOption {
	return func(o *serverOptions) {
		o.serverName = name
	}
}

// WithServerSecurityPolicies sets the supported security policies.
func WithServerSecurityPolicies(policies []SecurityPolicy) ServerOption {
	return func(o *serverOptions) {
		o.securityPolicies = policies
	}
}

// WithServerSecurityModes sets the supported security modes.
func WithServerSecurityModes(modes []MessageSecurityMode) ServerOption {
	return func(o *serverOptions) {
		o.securityModes = modes
	}
}

// WithServerCertificate sets the server certificate and private key.
func WithServerCertificate(cert, key []byte) ServerOption {
	return func(o *serverOptions) {
		o.certificate = cert
		o.privateKey = key
	}
}

// WithUserValidator sets the user validator.
func WithUserValidator(validator UserValidator) ServerOption {
	return func(o *serverOptions) {
		o.userValidator = validator
	}
}

// WithServerApplicationURI sets the server application URI.
func WithServerApplicationURI(uri string) ServerOption {
	return func(o *serverOptions) {
		o.applicationURI = uri
	}
}

// WithServerProductURI sets the server product URI.
func WithServerProductURI(uri string) ServerOption {
	return func(o *serverOptions) {
		o.productURI = uri
	}
}

// WithServerApplicationName sets the server application name.
func WithServerApplicationName(name string) ServerOption {
	return func(o *serverOptions) {
		o.applicationName = name
	}
}

// PoolOption is a functional option for configuring the connection pool.
type PoolOption func(*poolOptions)

type poolOptions struct {
	size            int
	maxIdleTime     time.Duration
	healthCheckFreq time.Duration
	clientOpts      []Option
}

func defaultPoolOptions() *poolOptions {
	return &poolOptions{
		size:            5,
		maxIdleTime:     5 * time.Minute,
		healthCheckFreq: 1 * time.Minute,
	}
}

// WithSize sets the pool size.
func WithSize(size int) PoolOption {
	return func(o *poolOptions) {
		o.size = size
	}
}

// WithMaxIdleTime sets the maximum idle time before a connection is closed.
func WithMaxIdleTime(d time.Duration) PoolOption {
	return func(o *poolOptions) {
		o.maxIdleTime = d
	}
}

// WithHealthCheckFrequency sets how often to check connection health.
func WithHealthCheckFrequency(d time.Duration) PoolOption {
	return func(o *poolOptions) {
		o.healthCheckFreq = d
	}
}

// WithClientOptions sets the options to use when creating new client connections.
func WithClientOptions(opts ...Option) PoolOption {
	return func(o *poolOptions) {
		o.clientOpts = opts
	}
}

// SubscriptionOption is a functional option for configuring subscriptions.
type SubscriptionOption func(*subscriptionOptions)

type subscriptionOptions struct {
	publishingInterval float64
	lifetimeCount      uint32
	maxKeepAliveCount  uint32
	maxNotifications   uint32
	publishingEnabled  bool
	priority           uint8
}

func defaultSubscriptionOptions() *subscriptionOptions {
	return &subscriptionOptions{
		publishingInterval: 1000, // 1 second
		lifetimeCount:      10000,
		maxKeepAliveCount:  10,
		maxNotifications:   0, // unlimited
		publishingEnabled:  true,
		priority:           0,
	}
}

// WithPublishingInterval sets the publishing interval in milliseconds.
func WithPublishingInterval(interval float64) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.publishingInterval = interval
	}
}

// WithLifetimeCount sets the lifetime count.
func WithLifetimeCount(count uint32) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.lifetimeCount = count
	}
}

// WithMaxKeepAliveCount sets the max keep alive count.
func WithMaxKeepAliveCount(count uint32) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.maxKeepAliveCount = count
	}
}

// WithMaxNotificationsPerPublish sets the max notifications per publish.
func WithMaxNotificationsPerPublish(count uint32) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.maxNotifications = count
	}
}

// WithPublishingEnabled sets whether publishing is enabled.
func WithPublishingEnabled(enabled bool) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.publishingEnabled = enabled
	}
}

// WithPriority sets the subscription priority.
func WithPriority(priority uint8) SubscriptionOption {
	return func(o *subscriptionOptions) {
		o.priority = priority
	}
}

// MonitoredItemOption is a functional option for configuring monitored items.
type MonitoredItemOption func(*monitoredItemOptions)

type monitoredItemOptions struct {
	samplingInterval float64
	queueSize        uint32
	discardOldest    bool
	monitoringMode   MonitoringMode
	filter           interface{}
}

func defaultMonitoredItemOptions() *monitoredItemOptions {
	return &monitoredItemOptions{
		samplingInterval: 250, // 250 ms
		queueSize:        10,
		discardOldest:    true,
		monitoringMode:   MonitoringModeReporting,
	}
}

// WithSamplingInterval sets the sampling interval in milliseconds.
func WithSamplingInterval(interval float64) MonitoredItemOption {
	return func(o *monitoredItemOptions) {
		o.samplingInterval = interval
	}
}

// WithQueueSize sets the queue size.
func WithQueueSize(size uint32) MonitoredItemOption {
	return func(o *monitoredItemOptions) {
		o.queueSize = size
	}
}

// WithDiscardOldest sets whether to discard oldest values when queue is full.
func WithDiscardOldest(discard bool) MonitoredItemOption {
	return func(o *monitoredItemOptions) {
		o.discardOldest = discard
	}
}

// WithMonitoringMode sets the monitoring mode.
func WithMonitoringMode(mode MonitoringMode) MonitoredItemOption {
	return func(o *monitoredItemOptions) {
		o.monitoringMode = mode
	}
}

// WithFilter sets the data change filter.
func WithFilter(filter interface{}) MonitoredItemOption {
	return func(o *monitoredItemOptions) {
		o.filter = filter
	}
}
