# Client OPC UA

Le client OPC UA permet de se connecter à des serveurs OPC UA et d'effectuer des opérations de lecture, écriture, navigation et souscription.

## Création du client

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

## Options de configuration

Voir [Configuration](./options) pour la liste complète des options.

```go
client, err := opcua.NewClient("localhost:4840",
    // Connexion
    opcua.WithEndpoint("opc.tcp://localhost:4840"),
    opcua.WithTimeout(10*time.Second),

    // Sécurité
    opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256),
    opcua.WithSecurityMode(opcua.MessageSecurityModeSignAndEncrypt),
    opcua.WithCertificate(cert, key),

    // Session
    opcua.WithSessionName("Mon Application"),
    opcua.WithSessionTimeout(time.Hour),

    // Authentification
    opcua.WithUserPassword("user", "password"),

    // Reconnexion automatique
    opcua.WithAutoReconnect(true),
    opcua.WithReconnectBackoff(time.Second),
    opcua.WithMaxReconnectTime(30*time.Second),

    // Logging
    opcua.WithLogger(slog.Default()),
)
```

## Connexion

### Connexion simple (secure channel uniquement)

```go
if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}
```

### Connexion avec session

```go
if err := client.ConnectAndActivateSession(ctx); err != nil {
    log.Fatal(err)
}
```

## État de connexion

```go
// Vérifier l'état
state := client.State()
fmt.Printf("État: %s\n", state)

// Vérifier si connecté
if client.IsConnected() {
    fmt.Println("Client connecté")
}

// Vérifier si session active
if client.IsSessionActive() {
    fmt.Println("Session active")
}
```

États possibles:
- `StateDisconnected` - Non connecté
- `StateConnecting` - Connexion en cours
- `StateConnected` - TCP connecté
- `StateSecureChannelOpen` - Secure channel ouvert
- `StateSessionActive` - Session activée

## Navigation (Browse)

### Naviguer un noeud

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

### Navigation avancée

```go
results, err := client.Browse(ctx, []opcua.BrowseDescription{
    {
        NodeID:          opcua.NewNumericNodeID(0, 85),
        BrowseDirection: opcua.BrowseDirectionForward,
        IncludeSubtypes: true,
        NodeClassMask:   opcua.NodeClassVariable,
        ResultMask:      0x3F, // Tous les champs
    },
})
if err != nil {
    log.Fatal(err)
}
```

Directions disponibles:
- `BrowseDirectionForward` - Enfants
- `BrowseDirectionInverse` - Parents
- `BrowseDirectionBoth` - Les deux

## Lecture (Read)

### Lire une valeur

```go
value, err := client.ReadValue(ctx, opcua.NewNumericNodeID(2, 1))
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Valeur: %v (Type: %s)\n", value.Value.Value, value.Value.Type)
```

### Lire plusieurs attributs

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
        fmt.Printf("Erreur sur lecture %d: %s\n", i, result.StatusCode)
    } else {
        fmt.Printf("Résultat %d: %v\n", i, result.Value)
    }
}
```

Attributs disponibles:
- `AttributeNodeID` - NodeID du noeud
- `AttributeNodeClass` - Classe du noeud
- `AttributeBrowseName` - Nom de navigation
- `AttributeDisplayName` - Nom d'affichage
- `AttributeDescription` - Description
- `AttributeValue` - Valeur (pour les variables)
- `AttributeDataType` - Type de données
- `AttributeAccessLevel` - Niveau d'accès

## Écriture (Write)

### Écrire une valeur simple

```go
err := client.WriteValue(ctx,
    opcua.NewNumericNodeID(2, 1),
    &opcua.Variant{Type: opcua.TypeDouble, Value: 25.5},
)
if err != nil {
    log.Fatal(err)
}
```

### Écrire plusieurs valeurs

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
        fmt.Printf("Erreur sur écriture %d: %s\n", i, status)
    }
}
```

Types supportés:
- `TypeBoolean` - bool
- `TypeSByte`, `TypeByte` - int8, uint8
- `TypeInt16`, `TypeUInt16` - int16, uint16
- `TypeInt32`, `TypeUInt32` - int32, uint32
- `TypeInt64`, `TypeUInt64` - int64, uint64
- `TypeFloat`, `TypeDouble` - float32, float64
- `TypeString` - string
- `TypeDateTime` - time.Time
- `TypeByteString` - []byte

## Appel de méthodes (Call)

### Appeler une méthode

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

## Découverte des endpoints

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

## Métriques

```go
metrics := client.Metrics().Collect()
fmt.Printf("Requêtes totales: %v\n", metrics["requests_total"])
fmt.Printf("Requêtes réussies: %v\n", metrics["requests_success"])
fmt.Printf("Requêtes en erreur: %v\n", metrics["requests_errors"])
fmt.Printf("Reconnexions: %v\n", metrics["reconnections"])
```

## Callbacks

```go
client, err := opcua.NewClient("localhost:4840",
    opcua.WithOnConnect(func() {
        fmt.Println("Connecté!")
    }),
    opcua.WithOnDisconnect(func(err error) {
        fmt.Printf("Déconnecté: %v\n", err)
    }),
    opcua.WithOnSessionActivated(func() {
        fmt.Println("Session activée!")
    }),
)
```
