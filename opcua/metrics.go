package opcua

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a simple atomic counter.
type Counter struct {
	value int64
}

// Add adds delta to the counter.
func (c *Counter) Add(delta int64) {
	atomic.AddInt64(&c.value, delta)
}

// Value returns the current counter value.
func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

// Reset resets the counter to zero.
func (c *Counter) Reset() {
	atomic.StoreInt64(&c.value, 0)
}

// LatencyHistogram tracks latency distribution.
type LatencyHistogram struct {
	mu      sync.Mutex
	buckets []int64   // count per bucket
	bounds  []float64 // upper bounds in ms
	sum     float64   // sum of all observations
	count   int64     // total count
	min     float64   // minimum observed value
	max     float64   // maximum observed value
}

// NewLatencyHistogram creates a new latency histogram with default buckets.
func NewLatencyHistogram() *LatencyHistogram {
	return &LatencyHistogram{
		buckets: make([]int64, 10),
		bounds:  []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000}, // ms
		min:     -1,
		max:     -1,
	}
}

// Observe records a latency observation.
func (h *LatencyHistogram) Observe(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0

	h.mu.Lock()
	defer h.mu.Unlock()

	h.sum += ms
	h.count++

	if h.min < 0 || ms < h.min {
		h.min = ms
	}
	if ms > h.max {
		h.max = ms
	}

	for i, bound := range h.bounds {
		if ms <= bound {
			h.buckets[i]++
			return
		}
	}
	// Greater than all bounds
	h.buckets[len(h.buckets)-1]++
}

// Stats returns histogram statistics.
func (h *LatencyHistogram) Stats() LatencyStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := LatencyStats{
		Count:   h.count,
		Sum:     h.sum,
		Buckets: make(map[string]int64),
	}

	if h.count > 0 {
		stats.Avg = h.sum / float64(h.count)
		stats.Min = h.min
		stats.Max = h.max
	}

	// Copy bucket counts
	labels := []string{"1ms", "5ms", "10ms", "25ms", "50ms", "100ms", "250ms", "500ms", "1s", "5s+"}
	for i, count := range h.buckets {
		if i < len(labels) {
			stats.Buckets[labels[i]] = count
		}
	}

	return stats
}

// Reset resets the histogram.
func (h *LatencyHistogram) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.buckets {
		h.buckets[i] = 0
	}
	h.sum = 0
	h.count = 0
	h.min = -1
	h.max = -1
}

// LatencyStats holds latency statistics.
type LatencyStats struct {
	Count   int64
	Sum     float64
	Avg     float64
	Min     float64
	Max     float64
	Buckets map[string]int64
}

// Metrics holds all client metrics.
type Metrics struct {
	RequestsTotal   Counter
	RequestsSuccess Counter
	RequestsErrors  Counter
	Reconnections   Counter
	ActiveConns     Counter
	ActiveSessions  Counter
	ActiveSubscriptions Counter
	MonitoredItems  Counter
	Latency         *LatencyHistogram

	// Per-service metrics
	serviceMetrics sync.Map // ServiceID -> *ServiceMetrics
}

// ServiceMetrics holds metrics for a specific service.
type ServiceMetrics struct {
	Requests Counter
	Errors   Counter
	Latency  *LatencyHistogram
}

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		Latency: NewLatencyHistogram(),
	}
}

// ForService returns metrics for a specific service.
func (m *Metrics) ForService(svc ServiceID) *ServiceMetrics {
	if val, ok := m.serviceMetrics.Load(svc); ok {
		return val.(*ServiceMetrics)
	}

	sm := &ServiceMetrics{
		Latency: NewLatencyHistogram(),
	}
	actual, _ := m.serviceMetrics.LoadOrStore(svc, sm)
	return actual.(*ServiceMetrics)
}

// Collect returns all metrics as a map (compatible with expvar/prometheus).
func (m *Metrics) Collect() map[string]interface{} {
	result := map[string]interface{}{
		"requests_total":       m.RequestsTotal.Value(),
		"requests_success":     m.RequestsSuccess.Value(),
		"requests_errors":      m.RequestsErrors.Value(),
		"reconnections":        m.Reconnections.Value(),
		"active_conns":         m.ActiveConns.Value(),
		"active_sessions":      m.ActiveSessions.Value(),
		"active_subscriptions": m.ActiveSubscriptions.Value(),
		"monitored_items":      m.MonitoredItems.Value(),
		"latency":              m.Latency.Stats(),
	}

	// Collect per-service metrics
	serviceStats := make(map[string]interface{})
	m.serviceMetrics.Range(func(key, value interface{}) bool {
		svc := key.(ServiceID)
		sm := value.(*ServiceMetrics)
		serviceStats[svc.String()] = map[string]interface{}{
			"requests": sm.Requests.Value(),
			"errors":   sm.Errors.Value(),
			"latency":  sm.Latency.Stats(),
		}
		return true
	})
	if len(serviceStats) > 0 {
		result["services"] = serviceStats
	}

	return result
}

// Reset resets all metrics.
func (m *Metrics) Reset() {
	m.RequestsTotal.Reset()
	m.RequestsSuccess.Reset()
	m.RequestsErrors.Reset()
	m.Reconnections.Reset()
	m.Latency.Reset()

	m.serviceMetrics.Range(func(key, value interface{}) bool {
		sm := value.(*ServiceMetrics)
		sm.Requests.Reset()
		sm.Errors.Reset()
		sm.Latency.Reset()
		return true
	})
}

// ServerMetrics holds server-side metrics.
type ServerMetrics struct {
	TotalRequests      Counter
	ActiveConnections  Counter
	ActiveSessions     Counter
	ActiveSubscriptions Counter
	Errors             Counter
	Latency            *LatencyHistogram

	// Per-service metrics
	serviceMetrics sync.Map
}

// NewServerMetrics creates a new ServerMetrics instance.
func NewServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		Latency: NewLatencyHistogram(),
	}
}

// ForService returns metrics for a specific service.
func (m *ServerMetrics) ForService(svc ServiceID) *ServiceMetrics {
	if val, ok := m.serviceMetrics.Load(svc); ok {
		return val.(*ServiceMetrics)
	}

	sm := &ServiceMetrics{
		Latency: NewLatencyHistogram(),
	}
	actual, _ := m.serviceMetrics.LoadOrStore(svc, sm)
	return actual.(*ServiceMetrics)
}

// Collect returns all server metrics as a map.
func (m *ServerMetrics) Collect() map[string]interface{} {
	result := map[string]interface{}{
		"total_requests":       m.TotalRequests.Value(),
		"active_connections":   m.ActiveConnections.Value(),
		"active_sessions":      m.ActiveSessions.Value(),
		"active_subscriptions": m.ActiveSubscriptions.Value(),
		"errors":               m.Errors.Value(),
		"latency":              m.Latency.Stats(),
	}

	serviceStats := make(map[string]interface{})
	m.serviceMetrics.Range(func(key, value interface{}) bool {
		svc := key.(ServiceID)
		sm := value.(*ServiceMetrics)
		serviceStats[svc.String()] = map[string]interface{}{
			"requests": sm.Requests.Value(),
			"errors":   sm.Errors.Value(),
			"latency":  sm.Latency.Stats(),
		}
		return true
	})
	if len(serviceStats) > 0 {
		result["services"] = serviceStats
	}

	return result
}

// PoolMetrics holds connection pool metrics.
type PoolMetrics struct {
	TotalConnections   Counter
	IdleConnections    Counter
	ActiveConnections  Counter
	ConnectionsCreated Counter
	ConnectionsClosed  Counter
	WaitCount          Counter
	WaitDuration       *LatencyHistogram
}

// NewPoolMetrics creates a new PoolMetrics instance.
func NewPoolMetrics() *PoolMetrics {
	return &PoolMetrics{
		WaitDuration: NewLatencyHistogram(),
	}
}

// Collect returns all pool metrics as a map.
func (m *PoolMetrics) Collect() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":   m.TotalConnections.Value(),
		"idle_connections":    m.IdleConnections.Value(),
		"active_connections":  m.ActiveConnections.Value(),
		"connections_created": m.ConnectionsCreated.Value(),
		"connections_closed":  m.ConnectionsClosed.Value(),
		"wait_count":          m.WaitCount.Value(),
		"wait_duration":       m.WaitDuration.Stats(),
	}
}

// SubscriptionMetrics holds subscription metrics.
type SubscriptionMetrics struct {
	NotificationsReceived Counter
	DataChangeNotifications Counter
	EventNotifications Counter
	PublishRequests Counter
	PublishResponses Counter
	RepublishRequests Counter
	Latency *LatencyHistogram
}

// NewSubscriptionMetrics creates a new SubscriptionMetrics instance.
func NewSubscriptionMetrics() *SubscriptionMetrics {
	return &SubscriptionMetrics{
		Latency: NewLatencyHistogram(),
	}
}

// Collect returns all subscription metrics as a map.
func (m *SubscriptionMetrics) Collect() map[string]interface{} {
	return map[string]interface{}{
		"notifications_received":    m.NotificationsReceived.Value(),
		"data_change_notifications": m.DataChangeNotifications.Value(),
		"event_notifications":       m.EventNotifications.Value(),
		"publish_requests":          m.PublishRequests.Value(),
		"publish_responses":         m.PublishResponses.Value(),
		"republish_requests":        m.RepublishRequests.Value(),
		"latency":                   m.Latency.Stats(),
	}
}
