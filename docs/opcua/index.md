---
slug: /
---

# OPC UA Driver

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](./changelog)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/edgeo/drivers/blob/main/LICENSE)

Une implementation Go complète du protocole OPC UA, avec client, serveur et pool de connexions.

## Installation

```bash
go get github.com/edgeo/drivers/opcua@v1.0.0
```

Pour vérifier la version installée:

```go
import "github.com/edgeo/drivers/opcua"

func main() {
    fmt.Printf("OPC UA driver version: %s\n", opcua.Version)
    // Output: OPC UA driver version: 1.0.0
}
```

## Fonctionnalités

- **Client OPC UA** avec reconnexion automatique
- **Serveur OPC UA** avec support multi-clients
- **Pool de connexions** avec health checks
- **Subscriptions** et monitored items
- **Métriques** intégrées (latence, compteurs, histogrammes)
- **Logging** structuré via `slog`

## Services OPC UA supportés

| Service | Description |
|---------|-------------|
| GetEndpoints | Découverte des endpoints disponibles |
| CreateSession | Création d'une session |
| ActivateSession | Activation d'une session |
| CloseSession | Fermeture d'une session |
| Browse | Navigation dans l'espace d'adressage |
| BrowseNext | Continuation de la navigation |
| Read | Lecture d'attributs de noeuds |
| Write | Écriture d'attributs de noeuds |
| Call | Appel de méthodes |
| CreateSubscription | Création d'un abonnement |
| CreateMonitoredItems | Création d'éléments surveillés |
| DeleteSubscriptions | Suppression d'abonnements |
| Publish | Réception des notifications |

## Exemple rapide

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/edgeo/drivers/opcua"
)

func main() {
    // Créer un client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
        opcua.WithTimeout(10*time.Second),
        opcua.WithAutoReconnect(true),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Connexion et activation de session
    ctx := context.Background()
    if err := client.ConnectAndActivateSession(ctx); err != nil {
        panic(err)
    }

    // Lire une valeur
    results, err := client.Read(ctx, []opcua.ReadValueID{
        {NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue},
    })
    if err != nil {
        panic(err)
    }
    fmt.Printf("Valeur: %v\n", results[0].Value)
}
```

## Structure du package

```
opcua/
├── client.go      # Client OPC UA
├── server.go      # Serveur OPC UA
├── pool.go        # Pool de connexions
├── options.go     # Configuration fonctionnelle
├── types.go       # Types et constantes
├── errors.go      # Gestion des erreurs
├── metrics.go     # Métriques et observabilité
├── protocol.go    # Encodage/décodage du protocole
├── services.go    # Services OPC UA (requêtes/réponses)
└── version.go     # Informations de version
```

## Prochaines étapes

- [Démarrage rapide](./getting-started)
- [Documentation Client](./client)
- [Documentation Serveur](./server)
- [Pool de connexions](./pool)
- [Configuration](./options)
- [Gestion des erreurs](./errors)
- [Métriques](./metrics)
- [Changelog](./changelog)
