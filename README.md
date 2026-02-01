# OPC UA Driver

A comprehensive OPC UA client library and CLI tool written in Go.

## Features

### Library (`opcua/`)

- Full OPC UA TCP protocol implementation
- All core services (Browse, Read, Write, Subscribe, Call)
- Complete security support (Sign, SignAndEncrypt)
- Multiple security policies (Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss)
- Multiple authentication methods (Anonymous, Username/Password, Certificate)
- Thread-safe client with automatic reconnection
- Clean API with context support
- Subscription and monitored items support with real-time data change notifications
- Connection pooling

### CLI (`opcuacli`)

- Browse address space
- Read/write node values
- Subscribe to data changes with live updates
- Server endpoint discovery
- Certificate generation for secure connections
- Support for all security policies and modes

## Installation

### CLI Tool

```bash
go install github.com/edgeo/drivers/opcua/cmd/opcuacli@latest
```

### Library

```bash
go get github.com/edgeo/drivers/opcua
```

## Quick Start

### CLI Examples

```bash
# Discover server endpoints and security options
opcuacli discovery -e opc.tcp://localhost:4840

# Browse the address space from root
opcuacli browse -e opc.tcp://localhost:4840

# Browse a specific node
opcuacli browse -e opc.tcp://localhost:4840 -n "i=85"

# Read a node value
opcuacli read -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Read multiple nodes
opcuacli read -e opc.tcp://localhost:4840 -n "i=2258" -n "i=2259"

# Write a value
opcuacli write -e opc.tcp://localhost:4840 -n "ns=2;i=1" --value 42

# Write with explicit type
opcuacli write -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" --value 25.5 -T double

# Subscribe to data changes
opcuacli subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Subscribe with custom intervals
opcuacli subscribe -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -i 1000 --sample 250

# Generate a client certificate for secure connections
opcuacli gencert --cert client-cert.pem --key client-key.pem

# Connect with security
opcuacli browse -e opc.tcp://localhost:4840 \
  -s Basic256Sha256 -m SignAndEncrypt \
  --cert client-cert.pem --key client-key.pem
```

### Library Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/edgeo/drivers/opcua"
)

func main() {
    // Create a new client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithSessionName("My Client"),
        opcua.WithAutoReconnect(true),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Connect and activate session
    if err := client.ConnectAndActivateSession(ctx); err != nil {
        log.Fatal(err)
    }

    // Browse the Objects folder (i=85)
    refs, err := client.BrowseNode(ctx, opcua.NewNumericNodeID(0, 85), opcua.BrowseDirectionForward)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Found %d nodes\n", len(refs))

    // Read a node value
    results, err := client.Read(ctx, []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Value: %v\n", results[0].Value)

    // Write a value
    err = client.WriteValue(ctx,
        opcua.NewNumericNodeID(2, 1),
        &opcua.Variant{Type: opcua.TypeInt32, Value: int32(42)},
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create a subscription
    sub, err := client.CreateSubscription(ctx,
        opcua.WithPublishingInterval(1000),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer sub.Delete(ctx)

    // Create monitored items
    items, err := sub.CreateMonitoredItems(ctx, []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Monitoring %d items\n", len(items))

    // Start the publish loop
    go sub.Run(ctx)

    // Receive notifications
    for notif := range sub.Notifications() {
        fmt.Printf("Value changed: %v\n", notif.Value.Value)
    }
}
```

## CLI Reference

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--endpoint` | `-e` | OPC UA server endpoint URL | `opc.tcp://localhost:4840` |
| `--timeout` | `-t` | Operation timeout in milliseconds | `5000` |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--security-policy` | `-s` | Security policy | `None` |
| `--security-mode` | `-m` | Security mode | `None` |
| `--cert` | | Path to client certificate (PEM) | |
| `--key` | | Path to client private key (PEM) | |

### Commands

#### Discovery Command

Discover OPC UA servers and endpoints.

```bash
# Discover endpoints
opcuacli discovery -e opc.tcp://localhost:4840
```

Displays:
- Server application information
- All available endpoints
- Security policies and modes for each endpoint
- Supported authentication methods
- Connection examples

#### Browse Command

Browse the OPC UA address space.

```bash
# Browse from root
opcuacli browse -e opc.tcp://localhost:4840

# Browse a specific node
opcuacli browse -e opc.tcp://localhost:4840 -n "i=85"

# Browse with direction
opcuacli browse -e opc.tcp://localhost:4840 -n "ns=2;s=MyNode" -d inverse
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--node` | `-n` | Node ID to browse from | `i=84` (Root) |
| `--direction` | `-d` | Browse direction: forward, inverse, both | `forward` |
| `--depth` | | Browse depth | `1` |

#### Read Command

Read attribute values from OPC UA nodes.

```bash
# Read a single node
opcuacli read -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Read multiple nodes
opcuacli read -e opc.tcp://localhost:4840 -n "i=2258" -n "i=2259"

# Read a specific attribute
opcuacli read -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -a DisplayName
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--node` | `-n` | Node ID(s) to read (can specify multiple) | *required* |
| `--attribute` | `-a` | Attribute to read | `Value` |

Supported attributes: `NodeId`, `NodeClass`, `BrowseName`, `DisplayName`, `Description`, `Value`, `DataType`, `ValueRank`, `ArrayDimensions`, `AccessLevel`

#### Write Command

Write values to OPC UA nodes.

```bash
# Write an integer (auto-detected)
opcuacli write -e opc.tcp://localhost:4840 -n "ns=2;i=1" --value 42

# Write a double
opcuacli write -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" --value 25.5 -T double

# Write a string
opcuacli write -e opc.tcp://localhost:4840 -n "i=1234" --value "Hello World" -T string
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--node` | `-n` | Node ID to write to | *required* |
| `--value` | | Value to write | *required* |
| `--type` | `-T` | Value type | `auto` |

Supported types: `auto`, `bool`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float`, `double`, `string`

#### Subscribe Command

Subscribe to data changes on OPC UA nodes.

```bash
# Subscribe to a single node
opcuacli subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=1"

# Subscribe to multiple nodes
opcuacli subscribe -e opc.tcp://localhost:4840 -n "i=2258" -n "i=2259"

# Subscribe with custom intervals
opcuacli subscribe -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -i 1000 --sample 250
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--node` | `-n` | Node ID(s) to subscribe to (can specify multiple) | *required* |
| `--interval` | `-i` | Publishing interval in milliseconds | `1000` |
| `--sample` | | Sampling interval in milliseconds | `250` |

Output format:
```
[HH:MM:SS.mmm] <NodeID> = <Value>
```

#### Gencert Command

Generate a self-signed X.509 certificate for OPC UA client authentication.

```bash
# Generate with defaults
opcuacli gencert

# Customize certificate
opcuacli gencert \
  --cert my-cert.pem \
  --key my-key.pem \
  --app-uri "urn:mycompany:myapp" \
  --org "My Company" \
  --dns "localhost,myhost.local" \
  --ip "127.0.0.1,192.168.1.100" \
  --days 730 \
  --key-size 4096
```

| Flag | Description | Default |
|------|-------------|---------|
| `--cert` | Output path for certificate | `client-cert.pem` |
| `--key` | Output path for private key | `client-key.pem` |
| `--app-uri` | OPC UA Application URI | `urn:opcua:client:app` |
| `--org` | Organization name | `OPC UA Client` |
| `--country` | Country code (2 letters) | `US` |
| `--locality` | Locality/City name | |
| `--dns` | Comma-separated DNS names | `localhost` |
| `--ip` | Comma-separated IP addresses | `127.0.0.1` |
| `--days` | Certificate validity in days | `365` |
| `--key-size` | RSA key size (2048 or 4096) | `2048` |

## Security

### Security Policies

| Policy | CLI Flag Value | Description |
|--------|----------------|-------------|
| None | `None` | No security (default) |
| Basic128Rsa15 | `Basic128Rsa15` | Legacy, not recommended |
| Basic256 | `Basic256` | Legacy, not recommended |
| Basic256Sha256 | `Basic256Sha256` | Recommended |
| Aes128-Sha256-RsaOaep | `Aes128Sha256RsaOaep` | Modern |
| Aes256-Sha256-RsaPss | `Aes256Sha256RsaPss` | Most secure |

### Security Modes

| Mode | CLI Flag Value | Description |
|------|----------------|-------------|
| None | `None` | No security |
| Sign | `Sign` | Messages are signed |
| SignAndEncrypt | `SignAndEncrypt` | Messages are signed and encrypted |

### Authentication Methods

| Method | Description |
|--------|-------------|
| Anonymous | No authentication (default) |
| Username/Password | Username and password credentials |
| Certificate | X.509 certificate authentication |

### Secure Connection Example

```bash
# 1. Generate a client certificate
opcuacli gencert --cert client-cert.pem --key client-key.pem

# 2. Discover available secure endpoints
opcuacli discovery -e opc.tcp://server:4840

# 3. Connect with security
opcuacli browse -e opc.tcp://server:4840 \
  -s Basic256Sha256 \
  -m SignAndEncrypt \
  --cert client-cert.pem \
  --key client-key.pem
```

## NodeID Format

NodeIDs can be specified in standard OPC UA notation:

| Format | Example | Description |
|--------|---------|-------------|
| Numeric | `i=1234` | Numeric ID in namespace 0 |
| Numeric with namespace | `ns=2;i=1234` | Numeric ID in namespace 2 |
| String | `s=MyNode` | String ID in namespace 0 |
| String with namespace | `ns=2;s=MyNode` | String ID in namespace 2 |
| GUID | `g=A1234567-...` | GUID ID |
| Opaque | `b=Base64...` | Opaque (ByteString) ID |

## Supported OPC UA Services

| Service | Description | Supported |
|---------|-------------|-----------|
| GetEndpoints | Retrieve available endpoints | Yes |
| CreateSession | Create a session | Yes |
| ActivateSession | Activate a session | Yes |
| CloseSession | Close a session | Yes |
| Browse | Browse address space | Yes |
| BrowseNext | Continue browsing | Yes |
| Read | Read attributes | Yes |
| Write | Write attributes | Yes |
| Call | Call methods | Yes |
| CreateSubscription | Create subscription | Yes |
| ModifySubscription | Modify subscription | Yes |
| DeleteSubscriptions | Delete subscriptions | Yes |
| CreateMonitoredItems | Create monitored items | Yes |
| ModifyMonitoredItems | Modify monitored items | Yes |
| DeleteMonitoredItems | Delete monitored items | Yes |
| Publish | Receive notifications | Yes |

## Project Structure

```
.
├── opcua/                    # OPC UA library (importable)
│   ├── client.go             # Main client implementation
│   ├── types.go              # Type definitions (NodeID, Variant, etc.)
│   ├── services.go           # Service request/response types
│   ├── protocol.go           # Protocol encoding/decoding
│   ├── security.go           # Security and cryptography
│   ├── options.go            # Client options
│   ├── errors.go             # Error types
│   ├── metrics.go            # Metrics collection
│   ├── pool.go               # Connection pooling
│   ├── server.go             # Server implementation
│   ├── cmd/
│   │   └── opcuacli/         # CLI application
│   │       ├── main.go
│   │       ├── root.go       # Root command and global flags
│   │       ├── browse.go     # Browse command
│   │       ├── read.go       # Read command
│   │       ├── write.go      # Write command
│   │       ├── subscribe.go  # Subscribe command
│   │       ├── discovery.go  # Discovery command
│   │       ├── gencert.go    # Certificate generation
│   │       └── common.go     # Shared utilities
│   └── internal/
│       └── transport/        # TCP transport layer
├── go.mod
├── go.sum
├── go.work                   # Go workspace for local development
└── README.md
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/edgeo/drivers.git
cd drivers/opcua

# Build the CLI
go build -o opcuacli ./opcua/cmd/opcuacli

# Run tests
go test ./opcua/...
```

## Tested Servers

The client has been tested against:

- **Eclipse Milo Demo Server** (`opc.tcp://milo.digitalpetri.com:62541/milo`)
  - All security policies (None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss)
  - All security modes (None, Sign, SignAndEncrypt)
  - Anonymous authentication

## License

MIT License

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
