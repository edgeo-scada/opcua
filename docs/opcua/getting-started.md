# Démarrage rapide

## Prérequis

- Go 1.21 ou supérieur

## Installation

```bash
go get github.com/edgeo/drivers/opcua
```

## Client OPC UA

### Connexion basique

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
    // Créer le client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Connexion et activation de session
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := client.ConnectAndActivateSession(ctx); err != nil {
        log.Fatal(err)
    }

    fmt.Println("Connecté!")
}
```

### Navigation dans l'espace d'adressage

```go
// Naviguer depuis le noeud Objects (i=85)
refs, err := client.BrowseNode(ctx, opcua.NewNumericNodeID(0, 85), opcua.BrowseDirectionForward)
if err != nil {
    log.Fatal(err)
}

for _, ref := range refs {
    fmt.Printf("- %s (%s)\n", ref.DisplayName.Text, ref.NodeClass)
}
```

### Lecture de valeurs

```go
// Lire une valeur unique
value, err := client.ReadValue(ctx, opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Valeur: %v\n", value.Value)

// Lire plusieurs valeurs
results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
    {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},
})
if err != nil {
    log.Fatal(err)
}
for i, result := range results {
    fmt.Printf("Résultat %d: %v\n", i, result.Value)
}
```

### Écriture de valeurs

```go
// Écrire une valeur entière
err := client.WriteValue(ctx,
    opcua.NewNumericNodeID(2, 1),
    &opcua.Variant{Type: opcua.TypeInt32, Value: int32(42)},
)
if err != nil {
    log.Fatal(err)
}

// Écrire une valeur double
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
// Créer un abonnement
sub, err := client.CreateSubscription(ctx,
    opcua.WithPublishingInterval(1000), // 1 seconde
)
if err != nil {
    log.Fatal(err)
}
defer sub.Delete(ctx)

// Créer des éléments surveillés
items, err := sub.CreateMonitoredItems(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},
})
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Surveillance de %d éléments\n", len(items))

// Recevoir les notifications
for notif := range sub.Notifications() {
    fmt.Printf("Changement: ClientHandle=%d, Valeur=%v\n",
        notif.ClientHandle, notif.Value.Value)
}
```

## Serveur OPC UA

### Serveur basique

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/edgeo/drivers/opcua"
)

func main() {
    // Créer le serveur
    server, err := opcua.NewServer(
        opcua.WithServerEndpoint("opc.tcp://localhost:4840"),
        opcua.WithServerName("Mon Serveur OPC UA"),
    )
    if err != nil {
        panic(err)
    }

    // Ajouter des noeuds personnalisés
    server.AddNode(opcua.NewNumericNodeID(2, 1), "Temperature", opcua.TypeDouble, 25.0)
    server.AddNode(opcua.NewNumericNodeID(2, 2), "Pressure", opcua.TypeDouble, 1013.25)

    // Gestion de l'arrêt gracieux
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Println("Arrêt...")
        server.Close()
    }()

    // Démarrer le serveur
    fmt.Println("Serveur OPC UA sur :4840")
    if err := server.ListenAndServe(ctx); err != nil {
        fmt.Printf("Erreur: %v\n", err)
    }
}
```

## Pool de connexions

Pour les applications à haute performance:

```go
// Créer un pool
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

// Utiliser une connexion du pool
client, err := pool.Get(ctx)
if err != nil {
    log.Fatal(err)
}

results, err := client.Read(ctx, []opcua.ReadValueID{
    {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
})
// ...

// Remettre la connexion dans le pool
pool.Put(client)
```

Ou avec retour automatique:

```go
pc, err := pool.GetPooled(ctx)
if err != nil {
    log.Fatal(err)
}
defer pc.Close() // Remet automatiquement dans le pool

results, err := pc.Read(ctx, []opcua.ReadValueID{...})
```

## Format des NodeID

Les NodeIDs peuvent être spécifiés en notation standard OPC UA:

| Format | Exemple | Description |
|--------|---------|-------------|
| Numérique | `i=1234` | ID numérique dans namespace 0 |
| Numérique avec namespace | `ns=2;i=1234` | ID numérique dans namespace 2 |
| Chaîne | `s=MyNode` | ID chaîne dans namespace 0 |
| Chaîne avec namespace | `ns=2;s=MyNode` | ID chaîne dans namespace 2 |
| GUID | `g=A1234567-...` | ID GUID |
| Opaque | `b=Base64...` | ID opaque (ByteString) |

Dans le code Go:

```go
// NodeID numérique
nodeID1 := opcua.NewNumericNodeID(0, 85)      // i=85
nodeID2 := opcua.NewNumericNodeID(2, 1234)    // ns=2;i=1234

// NodeID chaîne
nodeID3 := opcua.NewStringNodeID(2, "Temperature")  // ns=2;s=Temperature
```
