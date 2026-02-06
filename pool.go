// Copyright 2025 Edgeo SCADA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opcua

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Pool manages a pool of OPC UA client connections.
type Pool struct {
	addr       string
	opts       *poolOptions
	clients    chan *Client
	mu         sync.Mutex
	closed     bool
	closeCh    chan struct{}
	metrics    *PoolMetrics
	logger     *slog.Logger
	clientOpts []Option
}

// NewPool creates a new connection pool.
func NewPool(addr string, opts ...PoolOption) (*Pool, error) {
	if addr == "" {
		return nil, errors.New("opcua: address cannot be empty")
	}

	options := defaultPoolOptions()
	for _, opt := range opts {
		opt(options)
	}

	p := &Pool{
		addr:       addr,
		opts:       options,
		clients:    make(chan *Client, options.size),
		closeCh:    make(chan struct{}),
		metrics:    NewPoolMetrics(),
		logger:     slog.Default(),
		clientOpts: options.clientOpts,
	}

	// Pre-create connections
	for i := 0; i < options.size; i++ {
		client, err := NewClient(addr, options.clientOpts...)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.clients <- client
		p.metrics.TotalConnections.Add(1)
		p.metrics.IdleConnections.Add(1)
		p.metrics.ConnectionsCreated.Add(1)
	}

	// Start health checker
	go p.healthChecker()

	return p, nil
}

// Get retrieves a client from the pool.
func (p *Pool) Get(ctx context.Context) (*PooledClient, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	p.mu.Unlock()

	start := time.Now()
	p.metrics.WaitCount.Add(1)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.closeCh:
		return nil, ErrPoolClosed
	case client := <-p.clients:
		p.metrics.WaitDuration.Observe(time.Since(start))
		p.metrics.IdleConnections.Add(-1)
		p.metrics.ActiveConnections.Add(1)

		// Connect if not connected
		if !client.IsSessionActive() {
			if err := client.ConnectAndActivateSession(ctx); err != nil {
				// Return client to pool and return error
				p.returnClient(client)
				return nil, err
			}
		}

		return &PooledClient{
			Client: client,
			pool:   p,
		}, nil
	}
}

// Put returns a client to the pool.
func (p *Pool) Put(client *Client) {
	p.returnClient(client)
}

func (p *Pool) returnClient(client *Client) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		client.Close()
		return
	}
	p.mu.Unlock()

	select {
	case p.clients <- client:
		p.metrics.IdleConnections.Add(1)
		p.metrics.ActiveConnections.Add(-1)
	default:
		// Pool is full, close the client
		client.Close()
		p.metrics.ConnectionsClosed.Add(1)
		p.metrics.TotalConnections.Add(-1)
	}
}

// Close closes the pool and all connections.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.closeCh)
	p.mu.Unlock()

	// Close all idle clients
	close(p.clients)
	for client := range p.clients {
		client.Close()
		p.metrics.ConnectionsClosed.Add(1)
		p.metrics.TotalConnections.Add(-1)
	}

	return nil
}

// Metrics returns the pool metrics.
func (p *Pool) Metrics() *PoolMetrics {
	return p.metrics
}

// Size returns the current pool size.
func (p *Pool) Size() int {
	return len(p.clients)
}

func (p *Pool) healthChecker() {
	ticker := time.NewTicker(p.opts.healthCheckFreq)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			p.checkHealth()
		}
	}
}

func (p *Pool) checkHealth() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	// Check each idle client
	toCheck := make([]*Client, 0)

	// Drain clients to check
	draining := true
	for draining {
		select {
		case client := <-p.clients:
			toCheck = append(toCheck, client)
		default:
			draining = false
		}
	}

	// Check and return healthy clients
	for _, client := range toCheck {
		if client.IsConnected() {
			select {
			case p.clients <- client:
			default:
				client.Close()
				p.metrics.ConnectionsClosed.Add(1)
				p.metrics.TotalConnections.Add(-1)
			}
		} else {
			// Create replacement
			newClient, err := NewClient(p.addr, p.clientOpts...)
			if err != nil {
				p.logger.Error("failed to create replacement client", slog.String("error", err.Error()))
				continue
			}
			select {
			case p.clients <- newClient:
				p.metrics.ConnectionsCreated.Add(1)
			default:
				newClient.Close()
			}
			p.metrics.ConnectionsClosed.Add(1)
		}
	}
}

// PooledClient wraps a Client with automatic return to pool.
type PooledClient struct {
	*Client
	pool     *Pool
	returned bool
	mu       sync.Mutex
}

// Close returns the client to the pool instead of closing it.
func (c *PooledClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.returned {
		return nil
	}
	c.returned = true
	c.pool.Put(c.Client)
	return nil
}

// Execute executes a function with the pooled client and automatically returns it.
func (p *Pool) Execute(ctx context.Context, fn func(*Client) error) error {
	client, err := p.Get(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	return fn(client.Client)
}

// Read reads values using a pooled connection.
func (p *Pool) Read(ctx context.Context, nodesToRead []ReadValueID) ([]DataValue, error) {
	var results []DataValue
	err := p.Execute(ctx, func(c *Client) error {
		var err error
		results, err = c.Read(ctx, nodesToRead)
		return err
	})
	return results, err
}

// Write writes values using a pooled connection.
func (p *Pool) Write(ctx context.Context, nodesToWrite []WriteValue) ([]StatusCode, error) {
	var results []StatusCode
	err := p.Execute(ctx, func(c *Client) error {
		var err error
		results, err = c.Write(ctx, nodesToWrite)
		return err
	})
	return results, err
}

// Browse browses nodes using a pooled connection.
func (p *Pool) Browse(ctx context.Context, nodesToBrowse []BrowseDescription) ([]BrowseResult, error) {
	var results []BrowseResult
	err := p.Execute(ctx, func(c *Client) error {
		var err error
		results, err = c.Browse(ctx, nodesToBrowse)
		return err
	})
	return results, err
}
