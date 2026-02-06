# OPC UA Server

The OPC UA server allows exposing data and services via the OPC UA protocol.

## Creating the Server

```go
server, err := opcua.NewServer(
    opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),
    opcua.WithServerName("My OPC UA Server"),
)
if err != nil {
    log.Fatal(err)
}
```

## Configuration Options

```go
server, err := opcua.NewServer(
    // Endpoint
    opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),

    // Identification
    opcua.WithServerName("Production Server"),
    opcua.WithServerURI("urn:example:server"),
    opcua.WithProductURI("urn:example:product"),

    // Security
    opcua.WithServerCertificate(cert, key),
    opcua.WithServerSecurityPolicies(
        opcua.SecurityPolicyNone,
        opcua.SecurityPolicyBasic256Sha256,
    ),

    // Connections
    opcua.WithMaxConnections(100),
    opcua.WithMaxSessionsPerConnection(10),

    // Logging
    opcua.WithServerLogger(slog.Default()),
)
```

## Starting the Server

### Simple Start

```go
if err := server.ListenAndServe(ctx); err != nil {
    log.Fatal(err)
}
```

### With Signal Handling

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

go func() {
    <-sigCh
    log.Println("Shutting down...")
    cancel()
}()

if err := server.ListenAndServe(ctx); err != nil && err != context.Canceled {
    log.Fatal(err)
}
```

## Address Space Management

### Adding Nodes

```go
// Add a numeric variable
server.AddNode(
    opcua.NewNumericNodeID(2, 1),
    "Temperature",
    opcua.TypeDouble,
    25.0,
)

// Add a string variable
server.AddNode(
    opcua.NewNumericNodeID(2, 2),
    "Status",
    opcua.TypeString,
    "Running",
)

// Add with options
server.AddNodeWithOptions(
    opcua.NewNumericNodeID(2, 3),
    &opcua.NodeOptions{
        BrowseName:   "Pressure",
        DisplayName:  "Pressure (bar)",
        Description:  "System pressure in bar",
        DataType:     opcua.TypeDouble,
        InitialValue: 1.0,
        AccessLevel:  opcua.AccessLevelReadWrite,
        Historizing:  true,
    },
)
```

### Adding Folders

```go
// Create a folder
server.AddFolder(
    opcua.NewNumericNodeID(2, 100),
    "Sensors",
    opcua.NewNumericNodeID(0, 85), // Parent: Objects folder
)

// Add variables in the folder
server.AddNodeToFolder(
    opcua.NewNumericNodeID(2, 101),
    "Temperature",
    opcua.TypeDouble,
    25.0,
    opcua.NewNumericNodeID(2, 100), // Parent: Sensors folder
)
```

### Adding Methods

```go
server.AddMethod(
    opcua.NewNumericNodeID(2, 200),        // Method ID
    opcua.NewNumericNodeID(0, 85),          // Parent (Objects)
    "Calculate",
    []opcua.Argument{
        {Name: "x", DataType: opcua.TypeDouble},
        {Name: "y", DataType: opcua.TypeDouble},
    },
    []opcua.Argument{
        {Name: "result", DataType: opcua.TypeDouble},
    },
    func(ctx context.Context, inputs []opcua.Variant) ([]opcua.Variant, error) {
        x := inputs[0].Value.(float64)
        y := inputs[1].Value.(float64)
        return []opcua.Variant{
            {Type: opcua.TypeDouble, Value: x + y},
        }, nil
    },
)
```

## Updating Values

### Simple Update

```go
server.SetValue(opcua.NewNumericNodeID(2, 1), 27.5)
```

### Update with Timestamp

```go
server.SetValueWithTimestamp(
    opcua.NewNumericNodeID(2, 1),
    27.5,
    time.Now(),
)
```

### Update with Status

```go
server.SetValueWithStatus(
    opcua.NewNumericNodeID(2, 1),
    27.5,
    opcua.StatusGood,
    time.Now(),
)
```

### Reading a Value

```go
value, err := server.GetValue(opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Value: %v\n", value)
```

## Subscription Management

### Custom Handler

```go
server.SetSubscriptionHandler(func(sub *opcua.ServerSubscription, event opcua.SubscriptionEvent) {
    switch event.Type {
    case opcua.SubscriptionCreated:
        log.Printf("Subscription created: %d", sub.ID)
    case opcua.SubscriptionDeleted:
        log.Printf("Subscription deleted: %d", sub.ID)
    case opcua.MonitoredItemCreated:
        log.Printf("MonitoredItem created: %d for node %s", event.ItemID, event.NodeID)
    }
})
```

## Authentication

### Custom Authentication

```go
server.SetAuthenticator(func(token opcua.UserIdentityToken) (bool, error) {
    switch t := token.(type) {
    case *opcua.AnonymousIdentityToken:
        return true, nil // Allow anonymous

    case *opcua.UserNameIdentityToken:
        // Verify credentials
        if t.UserName == "admin" && t.Password == "secret" {
            return true, nil
        }
        return false, nil

    case *opcua.X509IdentityToken:
        // Verify certificate
        return verifyCertificate(t.Certificate)

    default:
        return false, nil
    }
})
```

### Node-level Authorization

```go
server.SetAccessController(func(session *opcua.ServerSession, nodeID opcua.NodeID, op opcua.Operation) bool {
    // Check permissions
    if op == opcua.OperationWrite {
        return session.HasRole("operator")
    }
    return true
})
```

## Metrics

```go
metrics := server.Metrics()

fmt.Printf("Active sessions: %d\n", metrics.ActiveSessions)
fmt.Printf("Active subscriptions: %d\n", metrics.ActiveSubscriptions)
fmt.Printf("MonitoredItems: %d\n", metrics.MonitoredItems)
fmt.Printf("Total requests: %d\n", metrics.RequestsTotal)
```

## History

### Enable History

```go
server.AddNodeWithOptions(
    opcua.NewNumericNodeID(2, 1),
    &opcua.NodeOptions{
        BrowseName:   "Temperature",
        DataType:     opcua.TypeDouble,
        InitialValue: 25.0,
        Historizing:  true,
    },
)

// Configure history storage
server.SetHistoryStorage(myHistoryStore)
```

### Storage Interface

```go
type HistoryStorage interface {
    WriteValue(nodeID opcua.NodeID, value opcua.DataValue) error
    ReadRawValues(nodeID opcua.NodeID, start, end time.Time, maxValues int) ([]opcua.DataValue, error)
    ReadProcessedValues(nodeID opcua.NodeID, start, end time.Time, aggregate opcua.AggregateType, interval time.Duration) ([]opcua.DataValue, error)
}
```

## Complete Example

```go
package main

import (
    "context"
    "log"
    "math/rand"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Create the server
    server, err := opcua.NewServer(
        opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),
        opcua.WithServerName("Demo Server"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Add nodes
    server.AddNode(opcua.NewNumericNodeID(2, 1), "Temperature", opcua.TypeDouble, 25.0)
    server.AddNode(opcua.NewNumericNodeID(2, 2), "Pressure", opcua.TypeDouble, 1013.0)
    server.AddNode(opcua.NewNumericNodeID(2, 3), "Status", opcua.TypeString, "Running")

    // Simulate value changes
    go func() {
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()

        for range ticker.C {
            server.SetValue(opcua.NewNumericNodeID(2, 1), 20.0+rand.Float64()*10)
            server.SetValue(opcua.NewNumericNodeID(2, 2), 1000.0+rand.Float64()*50)
        }
    }()

    // Shutdown handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        log.Println("Shutting down...")
        cancel()
    }()

    // Start
    log.Println("OPC UA server started on :4840")
    if err := server.ListenAndServe(ctx); err != nil && err != context.Canceled {
        log.Fatal(err)
    }
}
```
