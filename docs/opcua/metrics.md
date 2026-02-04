# Métriques

Le package OPC UA fournit des métriques intégrées pour le monitoring et l'observabilité.

## Métriques disponibles

### Client

| Métrique | Type | Description |
|----------|------|-------------|
| `requests_total` | Counter | Nombre total de requêtes |
| `requests_success` | Counter | Nombre de requêtes réussies |
| `requests_errors` | Counter | Nombre de requêtes en erreur |
| `reconnections` | Counter | Nombre de reconnexions |
| `active_connections` | Gauge | Connexions actives |
| `active_sessions` | Gauge | Sessions actives |
| `active_subscriptions` | Gauge | Subscriptions actives |
| `monitored_items` | Gauge | Éléments surveillés |
| `latency` | Histogram | Latence des requêtes |

### Serveur

| Métrique | Type | Description |
|----------|------|-------------|
| `connections_total` | Counter | Connexions totales reçues |
| `active_connections` | Gauge | Connexions actives |
| `active_sessions` | Gauge | Sessions actives |
| `active_subscriptions` | Gauge | Subscriptions actives |
| `monitored_items` | Gauge | Éléments surveillés |
| `requests_total` | Counter | Requêtes totales traitées |
| `requests_by_service` | Counter | Requêtes par type de service |
| `publish_notifications` | Counter | Notifications publiées |
| `bytes_received` | Counter | Octets reçus |
| `bytes_sent` | Counter | Octets envoyés |

### Pool

| Métrique | Type | Description |
|----------|------|-------------|
| `pool_size` | Gauge | Taille configurée du pool |
| `active_connections` | Gauge | Connexions en cours d'utilisation |
| `idle_connections` | Gauge | Connexions en attente |
| `total_connections` | Gauge | Total des connexions |
| `wait_count` | Gauge | Requêtes en attente d'une connexion |
| `avg_wait_time` | Gauge | Temps d'attente moyen |

## Collecte des métriques

### Client

```go
client, _ := opcua.NewClient("localhost:4840")

// Obtenir les métriques
metrics := client.Metrics()

// Collecter toutes les métriques
all := metrics.Collect()
fmt.Printf("Requêtes totales: %v\n", all["requests_total"])
fmt.Printf("Requêtes réussies: %v\n", all["requests_success"])
fmt.Printf("Requêtes erreurs: %v\n", all["requests_errors"])
fmt.Printf("Reconnexions: %v\n", all["reconnections"])
fmt.Printf("Latence P50: %v\n", all["latency_p50"])
fmt.Printf("Latence P99: %v\n", all["latency_p99"])
```

### Serveur

```go
server, _ := opcua.NewServer(...)

stats := server.Metrics()
fmt.Printf("Sessions actives: %d\n", stats.ActiveSessions)
fmt.Printf("Subscriptions: %d\n", stats.ActiveSubscriptions)
fmt.Printf("Requêtes traitées: %d\n", stats.RequestsTotal)
```

### Pool

```go
pool, _ := opcua.NewPool("localhost:4840", ...)

stats := pool.Stats()
fmt.Printf("Connexions actives: %d\n", stats.ActiveConnections)
fmt.Printf("Connexions idle: %d\n", stats.IdleConnections)
fmt.Printf("Temps d'attente moyen: %v\n", stats.AvgWaitTime)
```

## Intégration Prometheus

### Exposition des métriques

```go
import (
    "net/http"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Créer les métriques Prometheus
var (
    opcuaRequestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "opcua_requests_total",
        Help: "Total number of OPC UA requests",
    })
    opcuaRequestsErrors = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "opcua_requests_errors",
        Help: "Total number of OPC UA request errors",
    })
    opcuaLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "opcua_request_duration_seconds",
        Help:    "OPC UA request duration in seconds",
        Buckets: prometheus.DefBuckets,
    })
)

func init() {
    prometheus.MustRegister(opcuaRequestsTotal)
    prometheus.MustRegister(opcuaRequestsErrors)
    prometheus.MustRegister(opcuaLatency)
}

// Collecter périodiquement
func collectMetrics(client *opcua.Client) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    var lastTotal, lastErrors uint64

    for range ticker.C {
        m := client.Metrics().Collect()

        currentTotal := m["requests_total"].(uint64)
        currentErrors := m["requests_errors"].(uint64)

        opcuaRequestsTotal.Add(float64(currentTotal - lastTotal))
        opcuaRequestsErrors.Add(float64(currentErrors - lastErrors))

        lastTotal = currentTotal
        lastErrors = currentErrors
    }
}

func main() {
    // Exposer les métriques
    http.Handle("/metrics", promhttp.Handler())
    go http.ListenAndServe(":9090", nil)

    // ...
}
```

### Collecteur personnalisé

```go
type OPCUACollector struct {
    client *opcua.Client
    requestsDesc *prometheus.Desc
    errorsDesc   *prometheus.Desc
}

func NewOPCUACollector(client *opcua.Client) *OPCUACollector {
    return &OPCUACollector{
        client: client,
        requestsDesc: prometheus.NewDesc(
            "opcua_requests_total",
            "Total OPC UA requests",
            nil, nil,
        ),
        errorsDesc: prometheus.NewDesc(
            "opcua_errors_total",
            "Total OPC UA errors",
            nil, nil,
        ),
    }
}

func (c *OPCUACollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.requestsDesc
    ch <- c.errorsDesc
}

func (c *OPCUACollector) Collect(ch chan<- prometheus.Metric) {
    m := c.client.Metrics().Collect()

    ch <- prometheus.MustNewConstMetric(
        c.requestsDesc,
        prometheus.CounterValue,
        float64(m["requests_total"].(uint64)),
    )
    ch <- prometheus.MustNewConstMetric(
        c.errorsDesc,
        prometheus.CounterValue,
        float64(m["requests_errors"].(uint64)),
    )
}
```

## Intégration OpenTelemetry

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("opcua")

func setupMetrics(client *opcua.Client) {
    requestsCounter, _ := meter.Int64Counter(
        "opcua.requests",
        metric.WithDescription("Total OPC UA requests"),
    )

    errorsCounter, _ := meter.Int64Counter(
        "opcua.errors",
        metric.WithDescription("Total OPC UA errors"),
    )

    latencyHistogram, _ := meter.Float64Histogram(
        "opcua.latency",
        metric.WithDescription("OPC UA request latency"),
        metric.WithUnit("ms"),
    )

    // Observer callback
    _, _ = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
        m := client.Metrics().Collect()
        // Observer les valeurs...
        return nil
    })
}
```

## Histogramme de latence

```go
metrics := client.Metrics()

// Accès aux percentiles
latency := metrics.Latency

fmt.Printf("Min: %v\n", latency.Min())
fmt.Printf("Max: %v\n", latency.Max())
fmt.Printf("Mean: %v\n", latency.Mean())
fmt.Printf("P50: %v\n", latency.Percentile(50))
fmt.Printf("P90: %v\n", latency.Percentile(90))
fmt.Printf("P95: %v\n", latency.Percentile(95))
fmt.Printf("P99: %v\n", latency.Percentile(99))
```

## Alertes basées sur les métriques

```go
func monitorHealth(client *opcua.Client) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        m := client.Metrics().Collect()

        // Alerter si trop d'erreurs
        errorRate := float64(m["requests_errors"].(uint64)) /
                     float64(m["requests_total"].(uint64))
        if errorRate > 0.05 {
            alerting.Send("OPC UA error rate high", errorRate)
        }

        // Alerter si latence élevée
        p99 := m["latency_p99"].(time.Duration)
        if p99 > 5*time.Second {
            alerting.Send("OPC UA latency high", p99)
        }

        // Alerter si pas de connexion
        if !client.IsConnected() {
            alerting.Send("OPC UA disconnected", nil)
        }
    }
}
```

## Exemple complet

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/edgeo-scada/opcua"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    // Créer le client
    client, err := opcua.NewClient("localhost:4840",
        opcua.WithEndpoint("opc.tcp://localhost:4840"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()
    if err := client.ConnectAndActivateSession(ctx); err != nil {
        log.Fatal(err)
    }

    // Exposer les métriques Prometheus
    http.Handle("/metrics", promhttp.Handler())
    go http.ListenAndServe(":9090", nil)

    // Afficher les métriques périodiquement
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        m := client.Metrics().Collect()

        fmt.Println("=== Métriques OPC UA ===")
        fmt.Printf("Requêtes totales: %v\n", m["requests_total"])
        fmt.Printf("Requêtes réussies: %v\n", m["requests_success"])
        fmt.Printf("Requêtes erreurs: %v\n", m["requests_errors"])
        fmt.Printf("Reconnexions: %v\n", m["reconnections"])
        fmt.Printf("Connexions actives: %v\n", m["active_connections"])
        fmt.Printf("Sessions actives: %v\n", m["active_sessions"])
        fmt.Printf("Subscriptions: %v\n", m["active_subscriptions"])
        fmt.Printf("Latence P50: %v\n", m["latency_p50"])
        fmt.Printf("Latence P99: %v\n", m["latency_p99"])
        fmt.Println()
    }
}
```
