# Gestion des erreurs

Le package OPC UA fournit une gestion complète des erreurs avec des types d'erreur spécifiques et des status codes OPC UA.

## Types d'erreur

### Erreurs de connexion

```go
var (
    // Connexion déjà fermée
    ErrConnectionClosed = errors.New("opcua: connection closed")

    // Non connecté
    ErrNotConnected = errors.New("opcua: not connected")

    // Nombre maximum de tentatives atteint
    ErrMaxRetriesExceeded = errors.New("opcua: max retries exceeded")

    // Réponse invalide
    ErrInvalidResponse = errors.New("opcua: invalid response")

    // Timeout
    ErrTimeout = errors.New("opcua: operation timeout")
)
```

### Erreurs OPC UA

Le type `OPCUAError` encapsule les erreurs du protocole OPC UA:

```go
type OPCUAError struct {
    Service    ServiceID
    StatusCode StatusCode
    Message    string
}

func (e *OPCUAError) Error() string {
    return fmt.Sprintf("opcua: %s failed with status %s: %s",
        e.Service, e.StatusCode, e.Message)
}
```

## Status Codes

### Vérification du status

```go
if result.StatusCode.IsBad() {
    // Erreur
}

if result.StatusCode.IsUncertain() {
    // Résultat incertain
}

if result.StatusCode.IsGood() {
    // Succès
}
```

### Status codes courants

| Code | Nom | Description |
|------|-----|-------------|
| 0x00000000 | Good | Succès |
| 0x80010000 | BadUnexpectedError | Erreur inattendue |
| 0x80020000 | BadInternalError | Erreur interne |
| 0x80030000 | BadOutOfMemory | Mémoire insuffisante |
| 0x80040000 | BadResourceUnavailable | Ressource non disponible |
| 0x80050000 | BadCommunicationError | Erreur de communication |
| 0x80060000 | BadEncodingError | Erreur d'encodage |
| 0x80070000 | BadDecodingError | Erreur de décodage |
| 0x80080000 | BadEncodingLimitsExceeded | Limites d'encodage dépassées |
| 0x80090000 | BadRequestTooLarge | Requête trop grande |
| 0x800A0000 | BadResponseTooLarge | Réponse trop grande |
| 0x800B0000 | BadUnknownResponse | Réponse inconnue |
| 0x80100000 | BadTimeout | Timeout |
| 0x80110000 | BadServiceUnsupported | Service non supporté |
| 0x80120000 | BadShutdown | Arrêt en cours |
| 0x80130000 | BadServerNotConnected | Serveur non connecté |
| 0x80140000 | BadServerHalted | Serveur arrêté |
| 0x80150000 | BadNothingToDo | Rien à faire |
| 0x80160000 | BadTooManyOperations | Trop d'opérations |

### Status codes de session

| Code | Nom | Description |
|------|-----|-------------|
| 0x80250000 | BadSessionIdInvalid | Session ID invalide |
| 0x80260000 | BadSessionClosed | Session fermée |
| 0x80270000 | BadSessionNotActivated | Session non activée |
| 0x80280000 | BadSubscriptionIdInvalid | Subscription ID invalide |

### Status codes de noeud

| Code | Nom | Description |
|------|-----|-------------|
| 0x80330000 | BadNodeIdInvalid | NodeID invalide |
| 0x80340000 | BadNodeIdUnknown | NodeID inconnu |
| 0x80350000 | BadAttributeIdInvalid | AttributeID invalide |
| 0x80360000 | BadIndexRangeInvalid | Index range invalide |
| 0x80370000 | BadIndexRangeNoData | Pas de données dans l'index range |
| 0x803C0000 | BadNotReadable | Non lisible |
| 0x803D0000 | BadNotWritable | Non écrivable |
| 0x803E0000 | BadOutOfRange | Hors limites |
| 0x803F0000 | BadNotSupported | Non supporté |

## Gestion des erreurs

### Pattern basique

```go
results, err := client.Read(ctx, nodesToRead)
if err != nil {
    // Erreur de communication ou de protocole
    log.Printf("Erreur de lecture: %v", err)
    return err
}

// Vérifier le status de chaque résultat
for i, result := range results {
    if result.StatusCode.IsBad() {
        log.Printf("Erreur sur noeud %d: %s", i, result.StatusCode)
    }
}
```

### Identification du type d'erreur

```go
results, err := client.Read(ctx, nodesToRead)
if err != nil {
    var opcuaErr *opcua.OPCUAError
    if errors.As(err, &opcuaErr) {
        // Erreur OPC UA spécifique
        fmt.Printf("Service: %s\n", opcuaErr.Service)
        fmt.Printf("Status: %s\n", opcuaErr.StatusCode)
        fmt.Printf("Message: %s\n", opcuaErr.Message)
    } else if errors.Is(err, opcua.ErrConnectionClosed) {
        // Connexion fermée
        return reconnect()
    } else if errors.Is(err, context.DeadlineExceeded) {
        // Timeout
        return retry()
    }
}
```

### Erreurs de reconnexion

```go
if err := client.Connect(ctx); err != nil {
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() {
        // Timeout réseau
        log.Println("Timeout de connexion")
    } else if errors.Is(err, syscall.ECONNREFUSED) {
        // Connexion refusée
        log.Println("Serveur non disponible")
    }
}
```

## Retry automatique

Le client supporte la reconnexion automatique:

```go
client, err := opcua.NewClient("localhost:4840",
    opcua.WithAutoReconnect(true),
    opcua.WithMaxRetries(5),
    opcua.WithReconnectBackoff(time.Second),
    opcua.WithMaxReconnectTime(30*time.Second),
)
```

## Logging des erreurs

```go
// Configuration du logger avec niveau
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

client, _ := opcua.NewClient("localhost:4840",
    opcua.WithLogger(logger),
)
```

Les erreurs sont automatiquement loggées avec leur contexte:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "ERROR",
  "msg": "read failed",
  "service": "Read",
  "status_code": "BadNodeIdUnknown",
  "node_id": "ns=2;i=999"
}
```

## Status codes personnalisés

```go
// Créer un status code
status := opcua.StatusCode(0x80330000) // BadNodeIdInvalid

// Vérifier les flags
fmt.Printf("Is Bad: %v\n", status.IsBad())
fmt.Printf("Is Uncertain: %v\n", status.IsUncertain())
fmt.Printf("Is Good: %v\n", status.IsGood())

// Obtenir le message
fmt.Printf("Message: %s\n", status.String())
```

## Exemple complet

```go
func readWithErrorHandling(client *opcua.Client, nodeID opcua.NodeID) (*opcua.DataValue, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    value, err := client.ReadValue(ctx, nodeID)
    if err != nil {
        // Classifier l'erreur
        var opcuaErr *opcua.OPCUAError
        if errors.As(err, &opcuaErr) {
            switch {
            case opcuaErr.StatusCode == opcua.BadNodeIdUnknown:
                return nil, fmt.Errorf("noeud %s non trouvé", nodeID)
            case opcuaErr.StatusCode == opcua.BadNotReadable:
                return nil, fmt.Errorf("noeud %s non lisible", nodeID)
            case opcuaErr.StatusCode == opcua.BadSessionIdInvalid:
                // Tenter une reconnexion
                if err := client.ConnectAndActivateSession(ctx); err != nil {
                    return nil, fmt.Errorf("reconnexion échouée: %w", err)
                }
                return readWithErrorHandling(client, nodeID) // Retry
            default:
                return nil, fmt.Errorf("erreur OPC UA: %w", err)
            }
        }

        if errors.Is(err, context.DeadlineExceeded) {
            return nil, fmt.Errorf("timeout lors de la lecture de %s", nodeID)
        }

        return nil, fmt.Errorf("erreur inattendue: %w", err)
    }

    // Vérifier le status de la valeur
    if value.StatusCode.IsBad() {
        return nil, fmt.Errorf("valeur invalide: %s", value.StatusCode)
    }

    if value.StatusCode.IsUncertain() {
        log.Printf("Attention: valeur incertaine pour %s: %s", nodeID, value.StatusCode)
    }

    return value, nil
}
```
