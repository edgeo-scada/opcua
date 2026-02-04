# Serveur OPC UA

Le serveur OPC UA permet d'exposer des données et des services via le protocole OPC UA.

## Création du serveur

```go
server, err := opcua.NewServer(
    opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),
    opcua.WithServerName("Mon Serveur OPC UA"),
)
if err != nil {
    log.Fatal(err)
}
```

## Options de configuration

```go
server, err := opcua.NewServer(
    // Endpoint
    opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),

    // Identification
    opcua.WithServerName("Serveur de Production"),
    opcua.WithServerURI("urn:example:server"),
    opcua.WithProductURI("urn:example:product"),

    // Sécurité
    opcua.WithServerCertificate(cert, key),
    opcua.WithServerSecurityPolicies(
        opcua.SecurityPolicyNone,
        opcua.SecurityPolicyBasic256Sha256,
    ),

    // Connexions
    opcua.WithMaxConnections(100),
    opcua.WithMaxSessionsPerConnection(10),

    // Logging
    opcua.WithServerLogger(slog.Default()),
)
```

## Démarrage du serveur

### Démarrage simple

```go
if err := server.ListenAndServe(ctx); err != nil {
    log.Fatal(err)
}
```

### Avec gestion du signal

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

go func() {
    <-sigCh
    log.Println("Arrêt en cours...")
    cancel()
}()

if err := server.ListenAndServe(ctx); err != nil && err != context.Canceled {
    log.Fatal(err)
}
```

## Gestion de l'espace d'adressage

### Ajouter des noeuds

```go
// Ajouter une variable numérique
server.AddNode(
    opcua.NewNumericNodeID(2, 1),
    "Temperature",
    opcua.TypeDouble,
    25.0,
)

// Ajouter une variable string
server.AddNode(
    opcua.NewNumericNodeID(2, 2),
    "Status",
    opcua.TypeString,
    "Running",
)

// Ajouter avec options
server.AddNodeWithOptions(
    opcua.NewNumericNodeID(2, 3),
    &opcua.NodeOptions{
        BrowseName:   "Pressure",
        DisplayName:  "Pression (bar)",
        Description:  "Pression du système en bar",
        DataType:     opcua.TypeDouble,
        InitialValue: 1.0,
        AccessLevel:  opcua.AccessLevelReadWrite,
        Historizing:  true,
    },
)
```

### Ajouter des dossiers

```go
// Créer un dossier
server.AddFolder(
    opcua.NewNumericNodeID(2, 100),
    "Sensors",
    opcua.NewNumericNodeID(0, 85), // Parent: Objects folder
)

// Ajouter des variables dans le dossier
server.AddNodeToFolder(
    opcua.NewNumericNodeID(2, 101),
    "Temperature",
    opcua.TypeDouble,
    25.0,
    opcua.NewNumericNodeID(2, 100), // Parent: Sensors folder
)
```

### Ajouter des méthodes

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

## Mise à jour des valeurs

### Mise à jour simple

```go
server.SetValue(opcua.NewNumericNodeID(2, 1), 27.5)
```

### Mise à jour avec timestamp

```go
server.SetValueWithTimestamp(
    opcua.NewNumericNodeID(2, 1),
    27.5,
    time.Now(),
)
```

### Mise à jour avec statut

```go
server.SetValueWithStatus(
    opcua.NewNumericNodeID(2, 1),
    27.5,
    opcua.StatusGood,
    time.Now(),
)
```

### Lecture de valeur

```go
value, err := server.GetValue(opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Valeur: %v\n", value)
```

## Gestion des subscriptions

### Handler personnalisé

```go
server.SetSubscriptionHandler(func(sub *opcua.ServerSubscription, event opcua.SubscriptionEvent) {
    switch event.Type {
    case opcua.SubscriptionCreated:
        log.Printf("Subscription créée: %d", sub.ID)
    case opcua.SubscriptionDeleted:
        log.Printf("Subscription supprimée: %d", sub.ID)
    case opcua.MonitoredItemCreated:
        log.Printf("MonitoredItem créé: %d pour noeud %s", event.ItemID, event.NodeID)
    }
})
```

## Authentification

### Authentification personnalisée

```go
server.SetAuthenticator(func(token opcua.UserIdentityToken) (bool, error) {
    switch t := token.(type) {
    case *opcua.AnonymousIdentityToken:
        return true, nil // Autoriser anonyme

    case *opcua.UserNameIdentityToken:
        // Vérifier les credentials
        if t.UserName == "admin" && t.Password == "secret" {
            return true, nil
        }
        return false, nil

    case *opcua.X509IdentityToken:
        // Vérifier le certificat
        return verifyCertificate(t.Certificate)

    default:
        return false, nil
    }
})
```

### Autorisation par noeud

```go
server.SetAccessController(func(session *opcua.ServerSession, nodeID opcua.NodeID, op opcua.Operation) bool {
    // Vérifier les permissions
    if op == opcua.OperationWrite {
        return session.HasRole("operator")
    }
    return true
})
```

## Métriques

```go
metrics := server.Metrics()

fmt.Printf("Sessions actives: %d\n", metrics.ActiveSessions)
fmt.Printf("Subscriptions actives: %d\n", metrics.ActiveSubscriptions)
fmt.Printf("MonitoredItems: %d\n", metrics.MonitoredItems)
fmt.Printf("Requêtes totales: %d\n", metrics.RequestsTotal)
```

## Historique

### Activer l'historique

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

// Configurer le stockage de l'historique
server.SetHistoryStorage(myHistoryStore)
```

### Interface de stockage

```go
type HistoryStorage interface {
    WriteValue(nodeID opcua.NodeID, value opcua.DataValue) error
    ReadRawValues(nodeID opcua.NodeID, start, end time.Time, maxValues int) ([]opcua.DataValue, error)
    ReadProcessedValues(nodeID opcua.NodeID, start, end time.Time, aggregate opcua.AggregateType, interval time.Duration) ([]opcua.DataValue, error)
}
```

## Exemple complet

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
    // Créer le serveur
    server, err := opcua.NewServer(
        opcua.WithServerEndpoint("opc.tcp://0.0.0.0:4840"),
        opcua.WithServerName("Demo Server"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Ajouter des noeuds
    server.AddNode(opcua.NewNumericNodeID(2, 1), "Temperature", opcua.TypeDouble, 25.0)
    server.AddNode(opcua.NewNumericNodeID(2, 2), "Pressure", opcua.TypeDouble, 1013.0)
    server.AddNode(opcua.NewNumericNodeID(2, 3), "Status", opcua.TypeString, "Running")

    // Simuler des changements de valeur
    go func() {
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()

        for range ticker.C {
            server.SetValue(opcua.NewNumericNodeID(2, 1), 20.0+rand.Float64()*10)
            server.SetValue(opcua.NewNumericNodeID(2, 2), 1000.0+rand.Float64()*50)
        }
    }()

    // Gestion de l'arrêt
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigCh
        log.Println("Arrêt...")
        cancel()
    }()

    // Démarrer
    log.Println("Serveur OPC UA démarré sur :4840")
    if err := server.ListenAndServe(ctx); err != nil && err != context.Canceled {
        log.Fatal(err)
    }
}
```
