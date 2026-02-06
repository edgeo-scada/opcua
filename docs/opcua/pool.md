# Connection Pool

The connection pool allows efficient management of multiple connections to an OPC UA server for high-performance applications.

## Creating the Pool

```go
pool, err := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
    opcua.WithPoolMaxIdleTime(5*time.Minute),
)
if err != nil {
    log.Fatal(err)
}
defer pool.Close()
```

## Configuration Options

```go
pool, err := opcua.NewPool("localhost:4840",
    // Pool size
    opcua.WithPoolSize(20),

    // Maximum idle time before closing
    opcua.WithPoolMaxIdleTime(10*time.Minute),

    // Health check interval
    opcua.WithPoolHealthCheckInterval(30*time.Second),

    // Options passed to each client
    opcua.WithPoolClientOptions(
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithAutoReconnect(true),
        opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256),
        opcua.WithUserPassword("user", "password"),
    ),
)
```

## Manual Usage

### Getting a Connection

```go
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

// Use the client
results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeValue},
})

// Return to the pool
pool.Put(client)
```

### Error Handling

```go
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

results, err := client.Read(ctx, []opcua.ReadValueID{...})
if err != nil {
    // On error, mark as invalid
    pool.Remove(client)
    return err
}

pool.Put(client)
```

## Automatic Return Usage

The `GetPooled` method returns a wrapper that automatically returns the connection to the pool:

```go
pc, err := pool.GetPooled(ctx)
if err != nil {
    log.Fatal(err)
}
defer pc.Close() // Automatically returns to the pool

// Use like a normal client
results, err := pc.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeValue},
})
if err != nil {
    return err
}
```

## Metrics

```go
stats := pool.Stats()

fmt.Printf("Active connections: %d\n", stats.ActiveConnections)
fmt.Printf("Idle connections: %d\n", stats.IdleConnections)
fmt.Printf("Total connections: %d\n", stats.TotalConnections)
fmt.Printf("Pending waits: %d\n", stats.WaitCount)
fmt.Printf("Average wait time: %v\n", stats.AvgWaitTime)
```

## Health Checks

The pool automatically performs health checks on connections:

```go
pool, err := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
    opcua.WithPoolHealthCheckInterval(30*time.Second),
    opcua.WithPoolHealthCheckTimeout(5*time.Second),
)
```

Connections that fail health checks are automatically removed and replaced.

## Pool Behavior

### On-demand Creation

Connections are created on demand up to the maximum size:

```go
// Pool of 10 max connections
pool, _ := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
)

// Connections are created when needed
client1, _ := pool.Get(ctx)  // Creates connection 1
client2, _ := pool.Get(ctx)  // Creates connection 2
// ...
```

### Waiting When Pool is Full

If all connections are in use, `Get` waits for a connection to become available:

```go
// With timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

client, err := pool.Get(ctx)
if err == context.DeadlineExceeded {
    log.Println("Timeout: pool saturated")
}
```

### Closing Idle Connections

Inactive connections are closed after `MaxIdleTime`:

```go
pool, _ := opcua.NewPool("localhost:4840",
    opcua.WithPoolMaxIdleTime(5*time.Minute),
)

// After 5 minutes of inactivity, idle connections are closed
```

## Usage Patterns

### Worker Pool Pattern

```go
func processItems(pool *opcua.Pool, items []Item) error {
    var wg sync.WaitGroup
    errCh := make(chan error, len(items))

    for _, item := range items {
        wg.Add(1)
        go func(item Item) {
            defer wg.Done()

            pc, err := pool.GetPooled(ctx)
            if err != nil {
                errCh <- err
                return
            }
            defer pc.Close()

            if err := processItem(pc, item); err != nil {
                errCh <- err
            }
        }(item)
    }

    wg.Wait()
    close(errCh)

    for err := range errCh {
        if err != nil {
            return err
        }
    }
    return nil
}
```

### Rate Limiting Pattern

```go
func readWithRateLimit(pool *opcua.Pool, nodeIDs []opcua.NodeID, rps int) error {
    limiter := rate.NewLimiter(rate.Limit(rps), 1)

    for _, nodeID := range nodeIDs {
        if err := limiter.Wait(ctx); err != nil {
            return err
        }

        pc, err := pool.GetPooled(ctx)
        if err != nil {
            return err
        }

        _, err = pc.ReadValue(ctx, nodeID)
        pc.Close()

        if err != nil {
            return err
        }
    }
    return nil
}
```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Create the pool
    pool, err := opcua.NewPool("localhost:4840",
        opcua.WithPoolSize(10),
        opcua.WithPoolMaxIdleTime(5*time.Minute),
        opcua.WithPoolClientOptions(
            opcua.WithEndpoint("opc.tcp://localhost:4840"),
            opcua.WithTimeout(10*time.Second),
        ),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer pool.Close()

    // Simulate concurrent reads
    var wg sync.WaitGroup
    nodeIDs := []opcua.NodeID{
        opcua.NewNumericNodeID(2, 1),
        opcua.NewNumericNodeID(2, 2),
        opcua.NewNumericNodeID(2, 3),
    }

    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
            defer cancel()

            pc, err := pool.GetPooled(ctx)
            if err != nil {
                log.Printf("Worker %d: pool error: %v", id, err)
                return
            }
            defer pc.Close()

            for _, nodeID := range nodeIDs {
                value, err := pc.ReadValue(ctx, nodeID)
                if err != nil {
                    log.Printf("Worker %d: read error: %v", id, err)
                    continue
                }
                fmt.Printf("Worker %d: %v = %v\n", id, nodeID, value.Value)
            }
        }(i)
    }

    wg.Wait()

    // Display stats
    stats := pool.Stats()
    fmt.Printf("\nPool statistics:\n")
    fmt.Printf("  Active: %d\n", stats.ActiveConnections)
    fmt.Printf("  Idle: %d\n", stats.IdleConnections)
    fmt.Printf("  Total: %d\n", stats.TotalConnections)
}
```
