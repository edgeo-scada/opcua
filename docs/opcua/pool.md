# Pool de connexions

Le pool de connexions permet de gérer efficacement plusieurs connexions vers un serveur OPC UA pour les applications à haute performance.

## Création du pool

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

## Options de configuration

```go
pool, err := opcua.NewPool("localhost:4840",
    // Taille du pool
    opcua.WithPoolSize(20),

    // Durée d'inactivité maximale avant fermeture
    opcua.WithPoolMaxIdleTime(10*time.Minute),

    // Intervalle de vérification de santé
    opcua.WithPoolHealthCheckInterval(30*time.Second),

    // Options passées à chaque client
    opcua.WithPoolClientOptions(
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithAutoReconnect(true),
        opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256),
        opcua.WithUserPassword("user", "password"),
    ),
)
```

## Utilisation manuelle

### Obtenir une connexion

```go
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

// Utiliser le client
results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeValue},
})

// Remettre dans le pool
pool.Put(client)
```

### Gestion des erreurs

```go
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

results, err := client.Read(ctx, []opcua.ReadValueID{...})
if err != nil {
    // En cas d'erreur, marquer comme invalide
    pool.Remove(client)
    return err
}

pool.Put(client)
```

## Utilisation avec retour automatique

La méthode `GetPooled` retourne un wrapper qui remet automatiquement la connexion dans le pool:

```go
pc, err := pool.GetPooled(ctx)
if err != nil {
    log.Fatal(err)
}
defer pc.Close() // Remet automatiquement dans le pool

// Utiliser comme un client normal
results, err := pc.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(2, 1), AttributeID: opcua.AttributeValue},
})
if err != nil {
    return err
}
```

## Métriques

```go
stats := pool.Stats()

fmt.Printf("Connexions actives: %d\n", stats.ActiveConnections)
fmt.Printf("Connexions idle: %d\n", stats.IdleConnections)
fmt.Printf("Connexions totales: %d\n", stats.TotalConnections)
fmt.Printf("Attentes en cours: %d\n", stats.WaitCount)
fmt.Printf("Durée d'attente moyenne: %v\n", stats.AvgWaitTime)
```

## Health checks

Le pool effectue automatiquement des vérifications de santé sur les connexions:

```go
pool, err := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
    opcua.WithPoolHealthCheckInterval(30*time.Second),
    opcua.WithPoolHealthCheckTimeout(5*time.Second),
)
```

Les connexions qui échouent aux health checks sont automatiquement retirées et remplacées.

## Comportement du pool

### Création à la demande

Les connexions sont créées à la demande jusqu'à atteindre la taille maximale:

```go
// Pool de 10 connexions max
pool, _ := opcua.NewPool("localhost:4840",
    opcua.WithPoolSize(10),
)

// Les connexions sont créées quand nécessaire
client1, _ := pool.Get(ctx)  // Crée connexion 1
client2, _ := pool.Get(ctx)  // Crée connexion 2
// ...
```

### Attente si pool plein

Si toutes les connexions sont utilisées, `Get` attend qu'une connexion soit disponible:

```go
// Avec timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

client, err := pool.Get(ctx)
if err == context.DeadlineExceeded {
    log.Println("Timeout: pool saturé")
}
```

### Fermeture des connexions idle

Les connexions inactives sont fermées après `MaxIdleTime`:

```go
pool, _ := opcua.NewPool("localhost:4840",
    opcua.WithPoolMaxIdleTime(5*time.Minute),
)

// Après 5 minutes d'inactivité, les connexions idle sont fermées
```

## Patterns d'utilisation

### Pattern Worker Pool

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

### Pattern Rate Limiting

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

## Exemple complet

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
    // Créer le pool
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

    // Simuler des lectures concurrentes
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
                log.Printf("Worker %d: erreur pool: %v", id, err)
                return
            }
            defer pc.Close()

            for _, nodeID := range nodeIDs {
                value, err := pc.ReadValue(ctx, nodeID)
                if err != nil {
                    log.Printf("Worker %d: erreur lecture: %v", id, err)
                    continue
                }
                fmt.Printf("Worker %d: %v = %v\n", id, nodeID, value.Value)
            }
        }(i)
    }

    wg.Wait()

    // Afficher les stats
    stats := pool.Stats()
    fmt.Printf("\nStatistiques du pool:\n")
    fmt.Printf("  Actives: %d\n", stats.ActiveConnections)
    fmt.Printf("  Idle: %d\n", stats.IdleConnections)
    fmt.Printf("  Total: %d\n", stats.TotalConnections)
}
```
