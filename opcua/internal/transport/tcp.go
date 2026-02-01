// Package transport provides TCP transport for OPC UA.
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TCPTransport handles OPC UA TCP communication.
type TCPTransport struct {
	addr    string
	timeout time.Duration
	conn    net.Conn
	mu      sync.Mutex
}

// NewTCPTransport creates a new TCP transport.
func NewTCPTransport(addr string, timeout time.Duration) *TCPTransport {
	return &TCPTransport{
		addr:    addr,
		timeout: timeout,
	}
}

// Connect establishes a TCP connection.
func (t *TCPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return nil
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	// Enable TCP keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	t.conn = conn
	return nil
}

// Close closes the TCP connection.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil
	return err
}

// SendRaw sends raw data and receives the response.
func (t *TCPTransport) SendRaw(ctx context.Context, data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil, errors.New("not connected")
	}

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.timeout)
	}
	t.conn.SetDeadline(deadline)

	// Send data
	_, err := t.conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	// Read response header (8 bytes)
	header := make([]byte, 8)
	_, err = io.ReadFull(t.conn, header)
	if err != nil {
		return nil, fmt.Errorf("read header failed: %w", err)
	}

	// Parse message size
	messageSize := binary.LittleEndian.Uint32(header[4:8])
	if messageSize < 8 {
		return nil, fmt.Errorf("invalid message size: %d", messageSize)
	}
	if messageSize > 16*1024*1024 { // 16 MB limit
		return nil, fmt.Errorf("message too large: %d", messageSize)
	}

	// Read rest of message
	response := make([]byte, messageSize)
	copy(response, header)
	_, err = io.ReadFull(t.conn, response[8:])
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	return response, nil
}

// Send sends an OPC UA PDU and receives the response.
func (t *TCPTransport) Send(ctx context.Context, pdu []byte) ([]byte, error) {
	return t.SendRaw(ctx, pdu)
}

// LocalAddr returns the local network address.
func (t *TCPTransport) LocalAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (t *TCPTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}
