# Configuration

The OPC UA client and server use the functional options pattern for configuration.

## Client Options

### Connection

```go
// Server endpoint
opcua.WithEndpoint("opc.tcp://localhost:4840")

// Operation timeout
opcua.WithTimeout(10 * time.Second)
```

### Security

```go
// Security policy
opcua.WithSecurityPolicy(opcua.SecurityPolicyNone)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic128Rsa15)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyAes128Sha256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyAes256Sha256)

// Security mode
opcua.WithSecurityMode(opcua.MessageSecurityModeNone)
opcua.WithSecurityMode(opcua.MessageSecurityModeSign)
opcua.WithSecurityMode(opcua.MessageSecurityModeSignAndEncrypt)

// Client certificate
opcua.WithCertificate(certPEM, keyPEM)

// Custom TLS configuration
opcua.WithTLSConfig(&tls.Config{...})
```

### Session

```go
// Session name
opcua.WithSessionName("My Application")

// Session timeout
opcua.WithSessionTimeout(time.Hour)
```

### Authentication

```go
// Anonymous authentication (default)
opcua.WithAnonymousAuth()

// Username/password authentication
opcua.WithUserPassword("user", "password")

// Certificate authentication
opcua.WithCertificateAuth(userCert, userKey)
```

### Automatic Reconnection

```go
// Enable automatic reconnection
opcua.WithAutoReconnect(true)

// Initial delay between attempts
opcua.WithReconnectBackoff(time.Second)

// Maximum delay between attempts
opcua.WithMaxReconnectTime(30 * time.Second)

// Maximum number of attempts
opcua.WithMaxRetries(5)
```

### Application

```go
// Application URI
opcua.WithApplicationURI("urn:my:app")

// Product URI
opcua.WithProductURI("urn:my:product")

// Application name
opcua.WithApplicationName("My Application")
```

### Logging

```go
// Custom logger
opcua.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
```

### Callbacks

```go
// Called on connection
opcua.WithOnConnect(func() {
    log.Println("Connected")
})

// Called on disconnection
opcua.WithOnDisconnect(func(err error) {
    log.Printf("Disconnected: %v", err)
})

// Called on session activation
opcua.WithOnSessionActivated(func() {
    log.Println("Session activated")
})

// Called on session close
opcua.WithOnSessionClosed(func(err error) {
    log.Printf("Session closed: %v", err)
})
```

## Default Values

| Option | Default Value |
|--------|---------------|
| Timeout | 30 seconds |
| Security Policy | None |
| Security Mode | None |
| Session Name | "OPC UA Client Session" |
| Session Timeout | 1 hour |
| Auth Type | Anonymous |
| Auto Reconnect | false |
| Reconnect Backoff | 1 second |
| Max Reconnect Time | 30 seconds |
| Max Retries | 3 |
| Pool Size | 5 |

## Subscription Options

```go
// Publishing interval (ms)
opcua.WithPublishingInterval(1000)

// Lifetime count
opcua.WithLifetimeCount(10)

// Max keep-alive count
opcua.WithMaxKeepAliveCount(3)

// Max notifications per publish
opcua.WithMaxNotifications(100)

// Publishing enabled
opcua.WithPublishingEnabled(true)

// Priority
opcua.WithPriority(0)
```

## Monitored Item Options

```go
// Sampling interval (ms)
opcua.WithSamplingInterval(250)

// Monitoring mode
opcua.WithMonitoringMode(opcua.MonitoringModeReporting)

// Queue size
opcua.WithQueueSize(10)

// Discard oldest
opcua.WithDiscardOldest(true)
```

## Pool Options

```go
// Pool size
opcua.WithPoolSize(10)

// Maximum idle time
opcua.WithPoolMaxIdleTime(5 * time.Minute)

// Client options for pool connections
opcua.WithPoolClientOptions(
    opcua.WithTimeout(10 * time.Second),
    opcua.WithAutoReconnect(true),
)
```

## Complete Example

```go
client, err := opcua.NewClient("localhost:4840",
    // Connection
    opcua.WithEndpoint("opc.tcp://localhost:4840"),
    opcua.WithTimeout(10*time.Second),

    // Security
    opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256),
    opcua.WithSecurityMode(opcua.MessageSecurityModeSignAndEncrypt),
    opcua.WithCertificate(cert, key),

    // Session
    opcua.WithSessionName("Production Application"),
    opcua.WithSessionTimeout(2*time.Hour),

    // Authentication
    opcua.WithUserPassword("operator", "secret"),

    // Reconnection
    opcua.WithAutoReconnect(true),
    opcua.WithReconnectBackoff(2*time.Second),
    opcua.WithMaxReconnectTime(time.Minute),
    opcua.WithMaxRetries(10),

    // Application
    opcua.WithApplicationURI("urn:example:myapp"),
    opcua.WithProductURI("urn:example:product"),
    opcua.WithApplicationName("My Production Application"),

    // Logging
    opcua.WithLogger(productionLogger),

    // Callbacks
    opcua.WithOnConnect(func() {
        metrics.ConnectionEstablished()
    }),
    opcua.WithOnDisconnect(func(err error) {
        metrics.ConnectionLost(err)
    }),
)
```
