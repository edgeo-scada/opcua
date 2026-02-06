# Getting Started

## Prerequisites

- Go 1.21 or higher

## Installation

```bash
go get github.com/edgeo-scada/opcua
```

## OPC UA Client

### Basic Connection

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Create the client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Connect and activate session
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := client.ConnectAndActivateSession(ctx); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Connected!")
}
```

### Navigating the Address Space

```go
// Browse from the Objects node (i=85)
refs, err := client.BrowseNode(ctx, opcua.NewNumericNodeID(0, 85), opcua.BrowseDirectionForward)
if err != nil {
    log.Fatal(err)
}

for _, ref := range refs {
    fmt.Printf("- %s (%s)\n", ref.DisplayName.Text, ref.NodeClass)
}
```

### Reading Values

```go
// Read a single value
value, err := client.ReadValue(ctx, opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Value: %v\n", value.Value)

// Read multiple values
results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
    {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},
})
if err != nil {
    log.Fatal(err)
}
for i, result := range results {
    fmt.Printf("Result %d: %v\n", i, result.Value)
}
```

### Writing Values

```go
// Write an integer value
err := client.WriteValue(ctx,
    opcua.NewNumericNodeID(2, 1),
    &opcua.Variant{Type: opcua.TypeInt32, Value: int32(42)},
)
if err != nil {
    log.Fatal(err)
}

// Write a double value
err = client.WriteValue(ctx,
    opcua.NewStringNodeID(2, "Temperature"),
    &opcua.Variant{Type: opcua.TypeDouble, Value: 25.5},
)
if err != nil {
    log.Fatal(err)
}
```

### Subscriptions

```go
// Create a subscription
sub, err := client.CreateSubscription(ctx,
    opcua.WithPublishingInterval(1000), // 1 second
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

// Receive notifications
for notif := range sub.Notifications() {
    fmt.Printf("Change: ClientHandle=%d, Value=%v\n",
        notif.ClientHandle, notif.Value.Value)
}
```

## OPC UA Server

### Basic Server

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Create the server
    server, err := opcua.NewServer(
        opcua.WithServerEndpoint("opc.tcp://localhost:4840"),
        opcua.WithServerName("My OPC UA Server"),
    )
    if err != nil {
        panic(err)
    }

    // Add custom nodes
    server.AddNode(opcua.NewNumericNodeID(2, 1), "Temperature", opcua.TypeDouble, 25.0)
    server.AddNode(opcua.NewNumericNodeID(2, 2), "Pressure", opcua.TypeDouble, 1013.25)

    // Graceful shutdown handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Println("Shutting down...")
        server.Close()
    }()

    // Start the server
    fmt.Println("OPC UA server on :4840")
    if err := server.ListenAndServe(ctx); err != nil {
        fmt.Printf("Error: %v\n", err)
    }
}
```

## Connection Pool

For high-performance applications:

```go
// Create a pool
pool, err := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
    opcua.WithPoolMaxIdleTime(5*time.Minute),
    opcua.WithPoolClientOptions(
        opcua.WithTimeout(10*time.Second),
    ),
)
if err != nil {
    log.Fatal(err)
}
defer pool.Close()

// Get a connection from the pool
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
})
// ...

// Return the connection to the pool
pool.Put(client)
```

Or with automatic return:

```go
pc, err := pool.GetPooled(ctx)
if err != nil {
    log.Fatal(err)
}
defer pc.Close() // Automatically returns to the pool

results, err := pc.Read(ctx, []opcua.ReadValueID{...})
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
| Opaque | `b=Base64...` | Opaque ID (ByteString) |

In Go code:

```go
// Numeric NodeID
nodeID1 := opcua.NewNumericNodeID(0, 85)      // i=85
nodeID2 := opcua.NewNumericNodeID(2, 1234)    // ns=2;i=1234

// String NodeID
nodeID3 := opcua.NewStringNodeID(2, "Temperature")  // ns=2;s=Temperature
```
