# Configuration

Le client et le serveur OPC UA utilisent le pattern des options fonctionnelles pour la configuration.

## Options du client

### Connexion

```go
// Endpoint du serveur
opcua.WithEndpoint("opc.tcp://localhost:4840")

// Timeout des opérations
opcua.WithTimeout(10 * time.Second)
```

### Sécurité

```go
// Politique de sécurité
opcua.WithSecurityPolicy(opcua.SecurityPolicyNone)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic128Rsa15)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyBasic256Sha256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyAes128Sha256)
opcua.WithSecurityPolicy(opcua.SecurityPolicyAes256Sha256)

// Mode de sécurité
opcua.WithSecurityMode(opcua.MessageSecurityModeNone)
opcua.WithSecurityMode(opcua.MessageSecurityModeSign)
opcua.WithSecurityMode(opcua.MessageSecurityModeSignAndEncrypt)

// Certificat client
opcua.WithCertificate(certPEM, keyPEM)

// Configuration TLS personnalisée
opcua.WithTLSConfig(&tls.Config{...})
```

### Session

```go
// Nom de la session
opcua.WithSessionName("Mon Application")

// Timeout de la session
opcua.WithSessionTimeout(time.Hour)
```

### Authentification

```go
// Authentification anonyme (par défaut)
opcua.WithAnonymousAuth()

// Authentification par nom d'utilisateur/mot de passe
opcua.WithUserPassword("user", "password")

// Authentification par certificat
opcua.WithCertificateAuth(userCert, userKey)
```

### Reconnexion automatique

```go
// Activer la reconnexion automatique
opcua.WithAutoReconnect(true)

// Délai initial entre les tentatives
opcua.WithReconnectBackoff(time.Second)

// Délai maximum entre les tentatives
opcua.WithMaxReconnectTime(30 * time.Second)

// Nombre maximum de tentatives
opcua.WithMaxRetries(5)
```

### Application

```go
// URI de l'application
opcua.WithApplicationURI("urn:my:app")

// URI du produit
opcua.WithProductURI("urn:my:product")

// Nom de l'application
opcua.WithApplicationName("Mon Application")
```

### Logging

```go
// Logger personnalisé
opcua.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
```

### Callbacks

```go
// Appelé lors de la connexion
opcua.WithOnConnect(func() {
    log.Println("Connecté")
})

// Appelé lors de la déconnexion
opcua.WithOnDisconnect(func(err error) {
    log.Printf("Déconnecté: %v", err)
})

// Appelé lors de l'activation de session
opcua.WithOnSessionActivated(func() {
    log.Println("Session activée")
})

// Appelé lors de la fermeture de session
opcua.WithOnSessionClosed(func(err error) {
    log.Printf("Session fermée: %v", err)
})
```

## Valeurs par défaut

| Option | Valeur par défaut |
|--------|-------------------|
| Timeout | 30 secondes |
| Security Policy | None |
| Security Mode | None |
| Session Name | "OPC UA Client Session" |
| Session Timeout | 1 heure |
| Auth Type | Anonymous |
| Auto Reconnect | false |
| Reconnect Backoff | 1 seconde |
| Max Reconnect Time | 30 secondes |
| Max Retries | 3 |
| Pool Size | 5 |

## Options de subscription

```go
// Intervalle de publication (ms)
opcua.WithPublishingInterval(1000)

// Nombre de cycles de vie
opcua.WithLifetimeCount(10)

// Nombre maximum de keep-alive
opcua.WithMaxKeepAliveCount(3)

// Nombre maximum de notifications par publication
opcua.WithMaxNotifications(100)

// Publication activée
opcua.WithPublishingEnabled(true)

// Priorité
opcua.WithPriority(0)
```

## Options des monitored items

```go
// Intervalle d'échantillonnage (ms)
opcua.WithSamplingInterval(250)

// Mode de surveillance
opcua.WithMonitoringMode(opcua.MonitoringModeReporting)

// Taille de la file
opcua.WithQueueSize(10)

// Supprimer les anciennes valeurs
opcua.WithDiscardOldest(true)
```

## Options du pool

```go
// Taille du pool
opcua.WithPoolSize(10)

// Durée maximum d'inactivité
opcua.WithPoolMaxIdleTime(5 * time.Minute)

// Options du client pour les connexions du pool
opcua.WithPoolClientOptions(
    opcua.WithTimeout(10 * time.Second),
    opcua.WithAutoReconnect(true),
)
```

## Exemple complet

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
    opcua.WithSessionName("Application de Production"),
    opcua.WithSessionTimeout(2*time.Hour),

    // Authentification
    opcua.WithUserPassword("operator", "secret"),

    // Reconnexion
    opcua.WithAutoReconnect(true),
    opcua.WithReconnectBackoff(2*time.Second),
    opcua.WithMaxReconnectTime(time.Minute),
    opcua.WithMaxRetries(10),

    // Application
    opcua.WithApplicationURI("urn:example:myapp"),
    opcua.WithProductURI("urn:example:product"),
    opcua.WithApplicationName("Mon Application de Production"),

    // Logging
    opcua.WithLogger(productionLogger),

    // Callbacks
    opcua.WithOnConnect(func() {
        metrics.ConnectionEstablished()
    }),
    opcua.WithOnDisconnect(func(err error) {
        metrics.ConnectionLost(err)
    }),
)
```
