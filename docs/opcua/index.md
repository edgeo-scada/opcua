# OPC UA Driver

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](./changelog)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/edgeo-scada/opcua/blob/main/LICENSE)

A complete Go implementation of the OPC UA protocol, with client, server, and connection pool.

## Installation

```bash
go get github.com/edgeo-scada/opcua@v1.0.0
```

To verify the installed version:

```go
import "github.com/edgeo-scada/opcua"

func main() {
    fmt.Printf("OPC UA driver version: %s\n", opcua.Version)
    // Output: OPC UA driver version: 1.0.0
}
```

## Features

- **OPC UA Client** with automatic reconnection
- **OPC UA Server** with multi-client support
- **Connection Pool** with health checks
- **Subscriptions** and monitored items
- **Built-in Metrics** (latency, counters, histograms)
- **Structured Logging** via `slog`

## Supported OPC UA Services

| Service | Description |
|---------|-------------|
| GetEndpoints | Discover available endpoints |
| CreateSession | Create a session |
| ActivateSession | Activate a session |
| CloseSession | Close a session |
| Browse | Navigate the address space |
| BrowseNext | Continue browsing |
| Read | Read node attributes |
| Write | Write node attributes |
| Call | Call methods |
| CreateSubscription | Create a subscription |
| CreateMonitoredItems | Create monitored items |
| DeleteSubscriptions | Delete subscriptions |
| Publish | Receive notifications |

## Quick Example

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Create a client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithAutoReconnect(true),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Connect and activate session
    ctx := context.Background()
    if err := client.ConnectAndActivateSession(ctx); err != nil {
        panic(err)
    }

    // Read a value
    results, err := client.Read(ctx, []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
    })
    if err != nil {
        panic(err)
    }
    fmt.Printf("Value: %v\n", results[0].Value)
}
```

## Package Structure

```
opcua/
├── client.go      # OPC UA Client
├── server.go      # OPC UA Server
├── pool.go        # Connection Pool
├── options.go     # Functional Configuration
├── types.go       # Types and Constants
├── errors.go      # Error Handling
├── metrics.go     # Metrics and Observability
├── protocol.go    # Protocol Encoding/Decoding
├── services.go    # OPC UA Services (requests/responses)
└── version.go     # Version Information
```

## Next Steps

- [Getting Started](./getting-started)
- [Client Documentation](./client)
- [Server Documentation](./server)
- [Connection Pool](./pool)
- [Configuration](./options)
- [Error Handling](./errors)
- [Metrics](./metrics)
- [Changelog](./changelog)
