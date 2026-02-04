# Exemple: Serveur basique

Cet exemple montre comment créer un serveur OPC UA simple avec des noeuds personnalisés.

## Code complet

```go
// examples/server/main.go
package main

import (
    "context"
    "fmt"
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
        opcua.WithServerName("Demo OPC UA Server"),
        opcua.WithServerURI("urn:edgeo:demo:server"),
    )
    if err != nil {
        log.Fatalf("Erreur création serveur: %v", err)
    }

    // Configurer l'espace d'adressage
    setupAddressSpace(server)

    // Démarrer la simulation de données
    go simulateData(server)

    // Gestion de l'arrêt gracieux
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigCh
        log.Printf("Signal reçu: %v, arrêt en cours...", sig)
        cancel()
    }()

    // Démarrer le serveur
    log.Println("Serveur OPC UA démarré sur opc.tcp://0.0.0.0:4840")
    log.Println("Appuyez sur Ctrl+C pour arrêter")

    if err := server.ListenAndServe(ctx); err != nil && err != context.Canceled {
        log.Fatalf("Erreur serveur: %v", err)
    }

    log.Println("Serveur arrêté")
}

func setupAddressSpace(server *opcua.Server) {
    // Créer un dossier pour nos données
    server.AddFolder(
        opcua.NewNumericNodeID(2, 1),  // NodeID: ns=2;i=1
        "Sensors",
        opcua.NewNumericNodeID(0, 85), // Parent: Objects folder
    )

    // Ajouter des variables de capteurs
    server.AddNodeToFolder(
        opcua.NewNumericNodeID(2, 10),
        "Temperature",
        opcua.TypeDouble,
        25.0,
        opcua.NewNumericNodeID(2, 1),
    )

    server.AddNodeToFolder(
        opcua.NewNumericNodeID(2, 11),
        "Humidity",
        opcua.TypeDouble,
        50.0,
        opcua.NewNumericNodeID(2, 1),
    )

    server.AddNodeToFolder(
        opcua.NewNumericNodeID(2, 12),
        "Pressure",
        opcua.TypeDouble,
        1013.25,
        opcua.NewNumericNodeID(2, 1),
    )

    // Créer un dossier pour les actionneurs
    server.AddFolder(
        opcua.NewNumericNodeID(2, 2),
        "Actuators",
        opcua.NewNumericNodeID(0, 85),
    )

    // Variables d'actionneurs (lecture/écriture)
    server.AddNodeWithOptions(
        opcua.NewNumericNodeID(2, 20),
        &opcua.NodeOptions{
            BrowseName:   "Valve1",
            DisplayName:  "Vanne 1",
            Description:  "Position de la vanne 1 (0-100%)",
            DataType:     opcua.TypeDouble,
            InitialValue: 0.0,
            AccessLevel:  opcua.AccessLevelReadWrite,
            ParentNodeID: opcua.NewNumericNodeID(2, 2),
        },
    )

    server.AddNodeWithOptions(
        opcua.NewNumericNodeID(2, 21),
        &opcua.NodeOptions{
            BrowseName:   "Pump1",
            DisplayName:  "Pompe 1",
            Description:  "État de la pompe 1",
            DataType:     opcua.TypeBoolean,
            InitialValue: false,
            AccessLevel:  opcua.AccessLevelReadWrite,
            ParentNodeID: opcua.NewNumericNodeID(2, 2),
        },
    )

    // Ajouter des variables de statut
    server.AddFolder(
        opcua.NewNumericNodeID(2, 3),
        "Status",
        opcua.NewNumericNodeID(0, 85),
    )

    server.AddNodeToFolder(
        opcua.NewNumericNodeID(2, 30),
        "SystemStatus",
        opcua.TypeString,
        "Running",
        opcua.NewNumericNodeID(2, 3),
    )

    server.AddNodeToFolder(
        opcua.NewNumericNodeID(2, 31),
        "AlarmCount",
        opcua.TypeInt32,
        int32(0),
        opcua.NewNumericNodeID(2, 3),
    )

    // Ajouter une méthode
    server.AddMethod(
        opcua.NewNumericNodeID(2, 100),
        opcua.NewNumericNodeID(0, 85),
        "ResetAlarms",
        nil, // Pas d'arguments d'entrée
        nil, // Pas d'arguments de sortie
        func(ctx context.Context, inputs []opcua.Variant) ([]opcua.Variant, error) {
            log.Println("Méthode ResetAlarms appelée")
            server.SetValue(opcua.NewNumericNodeID(2, 31), int32(0))
            return nil, nil
        },
    )

    server.AddMethod(
        opcua.NewNumericNodeID(2, 101),
        opcua.NewNumericNodeID(0, 85),
        "Calculate",
        []opcua.Argument{
            {Name: "a", DataType: opcua.TypeDouble},
            {Name: "b", DataType: opcua.TypeDouble},
            {Name: "operation", DataType: opcua.TypeString},
        },
        []opcua.Argument{
            {Name: "result", DataType: opcua.TypeDouble},
        },
        func(ctx context.Context, inputs []opcua.Variant) ([]opcua.Variant, error) {
            a := inputs[0].Value.(float64)
            b := inputs[1].Value.(float64)
            op := inputs[2].Value.(string)

            var result float64
            switch op {
            case "add":
                result = a + b
            case "sub":
                result = a - b
            case "mul":
                result = a * b
            case "div":
                if b == 0 {
                    return nil, fmt.Errorf("division par zéro")
                }
                result = a / b
            default:
                return nil, fmt.Errorf("opération inconnue: %s", op)
            }

            return []opcua.Variant{{Type: opcua.TypeDouble, Value: result}}, nil
        },
    )

    log.Println("Espace d'adressage configuré")
}

func simulateData(server *opcua.Server) {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()

    baseTemp := 25.0
    baseHumidity := 50.0
    basePressure := 1013.25

    for range ticker.C {
        // Simuler des variations de température
        temp := baseTemp + (rand.Float64()-0.5)*2
        server.SetValueWithTimestamp(
            opcua.NewNumericNodeID(2, 10),
            temp,
            time.Now(),
        )

        // Simuler des variations d'humidité
        humidity := baseHumidity + (rand.Float64()-0.5)*5
        server.SetValueWithTimestamp(
            opcua.NewNumericNodeID(2, 11),
            humidity,
            time.Now(),
        )

        // Simuler des variations de pression
        pressure := basePressure + (rand.Float64()-0.5)*10
        server.SetValueWithTimestamp(
            opcua.NewNumericNodeID(2, 12),
            pressure,
            time.Now(),
        )

        // Simuler occasionnellement une alarme
        if rand.Float64() < 0.05 {
            currentAlarms, _ := server.GetValue(opcua.NewNumericNodeID(2, 31))
            if count, ok := currentAlarms.(int32); ok {
                server.SetValue(opcua.NewNumericNodeID(2, 31), count+1)
            }
        }
    }
}
```

## Exécution

```bash
# Compiler
go build -o server ./examples/server

# Exécuter
./server
```

## Sortie

```
Espace d'adressage configuré
Serveur OPC UA démarré sur opc.tcp://0.0.0.0:4840
Appuyez sur Ctrl+C pour arrêter
```

## Structure de l'espace d'adressage

```
Root (i=84)
└── Objects (i=85)
    ├── Server (i=2253)
    │   └── ServerStatus, etc.
    ├── Sensors (ns=2;i=1)
    │   ├── Temperature (ns=2;i=10) - Double, ReadOnly
    │   ├── Humidity (ns=2;i=11) - Double, ReadOnly
    │   └── Pressure (ns=2;i=12) - Double, ReadOnly
    ├── Actuators (ns=2;i=2)
    │   ├── Valve1 (ns=2;i=20) - Double, ReadWrite
    │   └── Pump1 (ns=2;i=21) - Boolean, ReadWrite
    ├── Status (ns=2;i=3)
    │   ├── SystemStatus (ns=2;i=30) - String
    │   └── AlarmCount (ns=2;i=31) - Int32
    ├── ResetAlarms (ns=2;i=100) - Method
    └── Calculate (ns=2;i=101) - Method
```

## Test avec le CLI

```bash
# Naviguer
opcuacli browse -e opc.tcp://localhost:4840

# Lire la température
opcuacli read -e opc.tcp://localhost:4840 -n "ns=2;i=10"

# Écrire sur la vanne
opcuacli write -e opc.tcp://localhost:4840 -n "ns=2;i=20" -v 50.0 -T double

# Souscrire aux changements
opcuacli subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=10" -n "ns=2;i=11" -n "ns=2;i=12"

# Voir les infos du serveur
opcuacli info -e opc.tcp://localhost:4840
```

## Points clés

1. **Organiser les noeuds en dossiers** pour une meilleure navigation
2. **Définir clairement les droits d'accès** (ReadOnly vs ReadWrite)
3. **Mettre à jour les valeurs avec timestamp** pour les données de process
4. **Gérer l'arrêt gracieux** avec les signaux système
5. **Utiliser des méthodes** pour les actions qui nécessitent une logique côté serveur
