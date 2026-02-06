# OPC UA Client

The OPC UA client allows connecting to OPC UA servers and performing read, write, browse, and subscription operations.

## Creating the Client

```go
client, err := opcua.NewClient("localhost:4840",
    opcua.WithEndpoint("opc.tcp://localhost:4840"),
    opcua.WithTimeout(10*time.Second),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

## Configuration Options

See [Configuration](./options) for the complete list of options.

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
    opcua.WithSessionName("My Application"),
    opcua.WithSessionTimeout(time.Hour),

    // Authentication
    opcua.WithUserPassword("user", "password"),

    // Automatic reconnection
    opcua.WithAutoReconnect(true),
    opcua.WithReconnectBackoff(time.Second),
    opcua.WithMaxReconnectTime(30*time.Second),

    // Logging
    opcua.WithLogger(slog.Default()),
)
```

## Connection

### Simple Connection (secure channel only)

```go
if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}
```

### Connection with Session

```go
if err := client.ConnectAndActivateSession(ctx); err != nil {
    log.Fatal(err)
}
```

## Connection State

```go
// Check state
state := client.State()
fmt.Printf("State: %s\n", state)

// Check if connected
if client.IsConnected() {
    fmt.Println("Client connected")
}

// Check if session is active
if client.IsSessionActive() {
    fmt.Println("Session active")
}
```

Possible states:
- `StateDisconnected` - Not connected
- `StateConnecting` - Connecting
- `StateConnected` - TCP connected
- `StateSecureChannelOpen` - Secure channel open
- `StateSessionActive` - Session activated

## Browsing (Browse)

### Browse a Node

```go
refs, err := client.BrowseNode(ctx,
    opcua.NewNumericNodeID(0, 85),  // Objects folder
    opcua.BrowseDirectionForward,
)
if err != nil {
    log.Fatal(err)
}

for _, ref := range refs {
    fmt.Printf("- %s (NodeID: %s, Type: %s)\n",
        ref.DisplayName.Text,
        ref.NodeID,
        ref.NodeClass)
}
```

### Advanced Browsing

```go
results, err := client.Browse(ctx, []opcua.BrowseDescription{
    {
        NodeID:          opcua.NewNumericNodeID(0, 85),
        BrowseDirection: opcua.BrowseDirectionForward,
        IncludeSubtypes: true,
        NodeClassMask:   opcua.NodeClassVariable,
        ResultMask:      0x3F, // All fields
    },
})
if err != nil {
    log.Fatal(err)
}
```

Available directions:
- `BrowseDirectionForward` - Children
- `BrowseDirectionInverse` - Parents
- `BrowseDirectionBoth` - Both

## Reading (Read)

### Read a Value

```go
value, err := client.ReadValue(ctx, opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Value: %v (Type: %s)\n", value.Value.Value, value.Value.Type)
```

### Read Multiple Attributes

```go
results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeValue},
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeDisplayName},
    {NodeID: opcua.NewNumericNodeID(2, 2), AttributeID: opcua.AttributeValue},
})
if err != nil {
    log.Fatal(err)
}

for i, result := range results {
    if result.StatusCode.IsBad() {
        fmt.Printf("Error on read %d: %s\n", i, result.StatusCode)
    } else {
        fmt.Printf("Result %d: %v\n", i, result.Value)
    }
}
```

Available attributes:
- `AttributeNodeID` - Node's NodeID
- `AttributeNodeClass` - Node class
- `AttributeBrowseName` - Browse name
- `AttributeDisplayName` - Display name
- `AttributeDescription` - Description
- `AttributeValue` - Value (for variables)
- `AttributeDataType` - Data type
- `AttributeAccessLevel` - Access level

## Writing (Write)

### Write a Simple Value

```go
err := client.WriteValue(ctx,
    opcua.NewNumericNodeID(2, 1),
    &opcua.Variant{Type: opcua.TypeDouble, Value: 25.5},
)
if err != nil {
    log.Fatal(err)
}
```

### Write Multiple Values

```go
results, err := client.Write(ctx, []opcua.WriteValue{
    {
        NodeID:      opcua.NewNumericNodeID(2, 1),
        AttributeID: opcua.AttributeValue,
        Value:       opcua.DataValue{Value: &opcua.Variant{Type: opcua.TypeDouble, Value: 25.5}},
    },
    {
        NodeID:      opcua.NewNumericNodeID(2, 2),
        AttributeID: opcua.AttributeValue,
        Value:       opcua.DataValue{Value: &opcua.Variant{Type: opcua.TypeInt32, Value: int32(100)}},
    },
})
if err != nil {
    log.Fatal(err)
}

for i, status := range results {
    if status.IsBad() {
        fmt.Printf("Error on write %d: %s\n", i, status)
    }
}
```

Supported types:
- `TypeBoolean` - bool
- `TypeSByte`, `TypeByte` - int8, uint8
- `TypeInt16`, `TypeUInt16` - int16, uint16
- `TypeInt32`, `TypeUInt32` - int32, uint32
- `TypeInt64`, `TypeUInt64` - int64, uint64
- `TypeFloat`, `TypeDouble` - float32, float64
- `TypeString` - string
- `TypeDateTime` - time.Time
- `TypeByteString` - []byte

## Method Calls (Call)

### Call a Method

```go
outputs, err := client.CallMethod(ctx,
    opcua.NewNumericNodeID(2, 1),    // Object ID
    opcua.NewNumericNodeID(2, 100),  // Method ID
    opcua.Variant{Type: opcua.TypeInt32, Value: int32(10)},
    opcua.Variant{Type: opcua.TypeString, Value: "test"},
)
if err != nil {
    log.Fatal(err)
}

for i, output := range outputs {
    fmt.Printf("Output %d: %v\n", i, output.Value)
}
```

## Endpoint Discovery

```go
endpoints, err := client.GetEndpoints(ctx)
if err != nil {
    log.Fatal(err)
}

for _, ep := range endpoints {
    fmt.Printf("Endpoint: %s\n", ep.EndpointURL)
    fmt.Printf("  Security: %s / %s\n", ep.SecurityMode, ep.SecurityPolicyURI)
    fmt.Printf("  Auth: ")
    for _, token := range ep.UserIdentityTokens {
        fmt.Printf("%s ", token.TokenType)
    }
    fmt.Println()
}
```

## Metrics

```go
metrics := client.Metrics().Collect()
fmt.Printf("Total requests: %v\n", metrics["requests_total"])
fmt.Printf("Successful requests: %v\n", metrics["requests_success"])
fmt.Printf("Failed requests: %v\n", metrics["requests_errors"])
fmt.Printf("Reconnections: %v\n", metrics["reconnections"])
```

## Callbacks

```go
client, err := opcua.NewClient("localhost:4840",
    opcua.WithOnConnect(func() {
        fmt.Println("Connected!")
    }),
    opcua.WithOnDisconnect(func(err error) {
        fmt.Printf("Disconnected: %v\n", err)
    }),
    opcua.WithOnSessionActivated(func() {
        fmt.Println("Session activated!")
    }),
)
```
ect(func(err error) {
        fmt.Printf("Déconnecté: %v\n", err)
    }),
    opcua.WithOnSessionActivated(func() {
        fmt.Println("Session activée!")
    }),
)
```
