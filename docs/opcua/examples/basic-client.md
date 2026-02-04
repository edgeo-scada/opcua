# Exemple: Client basique

Cet exemple montre comment créer un client OPC UA et effectuer des opérations de base.

## Code complet

```go
// examples/client/main.go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/edgeo-scada/opcua"
)

func main() {
    // Créer le client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithSessionName("Example Client"),
        opcua.WithAutoReconnect(true),
    )
    if err != nil {
        log.Fatalf("Erreur création client: %v", err)
    }
    defer client.Close()

    ctx := context.Background()

    // Connexion et activation de session
    log.Println("Connexion au serveur OPC UA...")
    if err := client.ConnectAndActivateSession(ctx); err != nil {
        log.Fatalf("Erreur connexion: %v", err)
    }
    log.Println("Connecté!")

    // 1. Navigation dans l'espace d'adressage
    log.Println("\n=== Navigation (Browse) ===")
    browseExample(ctx, client)

    // 2. Lecture de valeurs
    log.Println("\n=== Lecture (Read) ===")
    readExample(ctx, client)

    // 3. Écriture de valeurs
    log.Println("\n=== Écriture (Write) ===")
    writeExample(ctx, client)

    // 4. Subscription
    log.Println("\n=== Subscription ===")
    subscribeExample(ctx, client)

    // Afficher les métriques
    log.Println("\n=== Métriques ===")
    printMetrics(client)

    log.Println("\nTerminé!")
}

func browseExample(ctx context.Context, client *opcua.Client) {
    // Naviguer depuis le dossier Objects (i=85)
    refs, err := client.BrowseNode(ctx,
        opcua.NewNumericNodeID(0, 85),
        opcua.BrowseDirectionForward,
    )
    if err != nil {
        log.Printf("Erreur browse: %v", err)
        return
    }

    fmt.Printf("Noeuds trouvés dans Objects:\n")
    for _, ref := range refs {
        fmt.Printf("  - %s (NodeID: %s, Type: %s)\n",
            ref.DisplayName.Text,
            formatNodeID(ref.NodeID),
            ref.NodeClass)
    }
}

func readExample(ctx context.Context, client *opcua.Client) {
    // Lire plusieurs attributs
    nodesToRead := []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},      // ServerStatus
        {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue},      // CurrentTime
        {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeDisplayName}, // ServerStatus DisplayName
    }

    results, err := client.Read(ctx, nodesToRead)
    if err != nil {
        log.Printf("Erreur lecture: %v", err)
        return
    }

    for i, result := range results {
        if result.StatusCode.IsBad() {
            fmt.Printf("Lecture %d: Erreur %s\n", i, result.StatusCode)
        } else {
            fmt.Printf("Lecture %d: %v (Type: %s)\n", i,
                result.Value.Value,
                getTypeName(result.Value.Type))
        }
    }
}

func writeExample(ctx context.Context, client *opcua.Client) {
    // Note: Cette opération nécessite un serveur avec des noeuds écrivables
    nodeID := opcua.NewNumericNodeID(2, 1) // Exemple: ns=2;i=1

    err := client.WriteValue(ctx, nodeID, &opcua.Variant{
        Type:  opcua.TypeDouble,
        Value: 42.5,
    })
    if err != nil {
        log.Printf("Erreur écriture (attendue si noeud non disponible): %v", err)
        return
    }

    fmt.Println("Valeur écrite avec succès!")

    // Relire pour vérifier
    value, err := client.ReadValue(ctx, nodeID)
    if err != nil {
        log.Printf("Erreur relecture: %v", err)
        return
    }
    fmt.Printf("Nouvelle valeur: %v\n", value.Value.Value)
}

func subscribeExample(ctx context.Context, client *opcua.Client) {
    // Créer une subscription
    sub, err := client.CreateSubscription(ctx,
        opcua.WithPublishingInterval(1000),
    )
    if err != nil {
        log.Printf("Erreur création subscription: %v", err)
        return
    }
    defer sub.Delete(context.Background())

    fmt.Printf("Subscription créée (ID: %d, Interval: %.0fms)\n",
        sub.ID, sub.RevisedPublishingInterval)

    // Créer des monitored items
    items, err := sub.CreateMonitoredItems(ctx, []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue}, // CurrentTime
    })
    if err != nil {
        log.Printf("Erreur création monitored items: %v", err)
        return
    }

    fmt.Printf("Monitored items créés: %d\n", len(items))

    // Attendre quelques notifications
    fmt.Println("Attente des notifications (5 secondes)...")
    timeout := time.After(5 * time.Second)
    count := 0

    for {
        select {
        case notif := <-sub.Notifications():
            count++
            fmt.Printf("  Notification %d: %v\n", count, notif.Value.Value)
        case <-timeout:
            fmt.Printf("Notifications reçues: %d\n", count)
            return
        }
    }
}

func printMetrics(client *opcua.Client) {
    m := client.Metrics().Collect()
    fmt.Printf("Requêtes totales: %v\n", m["requests_total"])
    fmt.Printf("Requêtes réussies: %v\n", m["requests_success"])
    fmt.Printf("Requêtes erreurs: %v\n", m["requests_errors"])
}

func formatNodeID(n opcua.NodeID) string {
    switch n.Type {
    case opcua.NodeIDTypeNumeric:
        if n.Namespace == 0 {
            return fmt.Sprintf("i=%d", n.Numeric)
        }
        return fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Numeric)
    case opcua.NodeIDTypeString:
        if n.Namespace == 0 {
            return fmt.Sprintf("s=%s", n.String)
        }
        return fmt.Sprintf("ns=%d;s=%s", n.Namespace, n.String)
    default:
        return fmt.Sprintf("%v", n)
    }
}

func getTypeName(t opcua.TypeID) string {
    switch t {
    case opcua.TypeBoolean:
        return "Boolean"
    case opcua.TypeInt32:
        return "Int32"
    case opcua.TypeDouble:
        return "Double"
    case opcua.TypeString:
        return "String"
    case opcua.TypeDateTime:
        return "DateTime"
    default:
        return fmt.Sprintf("Type(%d)", t)
    }
}
```

## Exécution

```bash
# Compiler
go build -o client ./examples/client

# Exécuter (nécessite un serveur OPC UA sur localhost:4840)
./client
```

## Sortie attendue

```
Connexion au serveur OPC UA...
Connecté!

=== Navigation (Browse) ===
Noeuds trouvés dans Objects:
  - Server (NodeID: i=2253, Type: Object)
  - DeviceSet (NodeID: ns=2;i=1, Type: Object)

=== Lecture (Read) ===
Lecture 0: {State: Running, ...} (Type: ExtensionObject)
Lecture 1: 2024-02-01T10:30:00Z (Type: DateTime)
Lecture 2: ServerStatus (Type: LocalizedText)

=== Écriture (Write) ===
Valeur écrite avec succès!
Nouvelle valeur: 42.5

=== Subscription ===
Subscription créée (ID: 1, Interval: 1000ms)
Monitored items créés: 1
Attente des notifications (5 secondes)...
  Notification 1: 2024-02-01T10:30:01Z
  Notification 2: 2024-02-01T10:30:02Z
  Notification 3: 2024-02-01T10:30:03Z
  Notification 4: 2024-02-01T10:30:04Z
  Notification 5: 2024-02-01T10:30:05Z
Notifications reçues: 5

=== Métriques ===
Requêtes totales: 12
Requêtes réussies: 12
Requêtes erreurs: 0

Terminé!
```

## Points clés

1. **Toujours fermer le client** avec `defer client.Close()`
2. **Utiliser un context** pour les opérations avec timeout
3. **Vérifier les StatusCode** des résultats de lecture/écriture
4. **Nettoyer les subscriptions** avec `defer sub.Delete()`
