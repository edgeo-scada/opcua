package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/edgeo/drivers/opcua"
)

// parseEndpoint extracts the host:port from an OPC UA endpoint URL.
func parseEndpoint(endpoint string) string {
	// Remove protocol prefix
	addr := endpoint
	if strings.HasPrefix(addr, "opc.tcp://") {
		addr = strings.TrimPrefix(addr, "opc.tcp://")
	}

	// Remove any path
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}

	// Add default port if missing
	if !strings.Contains(addr, ":") {
		addr += ":4840"
	}

	return addr
}

// parseNodeID parses a node ID string into a NodeID.
func parseNodeID(s string) (opcua.NodeID, error) {
	// Default namespace
	ns := uint16(0)
	identifier := s

	// Check for namespace prefix
	if strings.HasPrefix(s, "ns=") {
		parts := strings.SplitN(s, ";", 2)
		if len(parts) != 2 {
			return opcua.NodeID{}, fmt.Errorf("invalid node ID format: %s", s)
		}

		nsStr := strings.TrimPrefix(parts[0], "ns=")
		nsVal, err := strconv.ParseUint(nsStr, 10, 16)
		if err != nil {
			return opcua.NodeID{}, fmt.Errorf("invalid namespace: %s", nsStr)
		}
		ns = uint16(nsVal)
		identifier = parts[1]
	}

	// Parse identifier type
	if strings.HasPrefix(identifier, "i=") {
		idStr := strings.TrimPrefix(identifier, "i=")
		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			return opcua.NodeID{}, fmt.Errorf("invalid numeric ID: %s", idStr)
		}
		return opcua.NewNumericNodeID(ns, uint32(id)), nil
	}

	if strings.HasPrefix(identifier, "s=") {
		idStr := strings.TrimPrefix(identifier, "s=")
		return opcua.NewStringNodeID(ns, idStr), nil
	}

	if strings.HasPrefix(identifier, "g=") {
		// GUID format
		return opcua.NodeID{}, fmt.Errorf("GUID node IDs not yet supported")
	}

	if strings.HasPrefix(identifier, "b=") {
		// Opaque format
		return opcua.NodeID{}, fmt.Errorf("opaque node IDs not yet supported")
	}

	// Try to parse as numeric without prefix
	if id, err := strconv.ParseUint(identifier, 10, 32); err == nil {
		return opcua.NewNumericNodeID(ns, uint32(id)), nil
	}

	// Default to string
	return opcua.NewStringNodeID(ns, identifier), nil
}

// formatNodeID formats a NodeID as a string.
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
	case opcua.NodeIDTypeGUID:
		if n.Namespace == 0 {
			return fmt.Sprintf("g=%x", n.GUID)
		}
		return fmt.Sprintf("ns=%d;g=%x", n.Namespace, n.GUID)
	case opcua.NodeIDTypeOpaque:
		if n.Namespace == 0 {
			return fmt.Sprintf("b=%x", n.Opaque)
		}
		return fmt.Sprintf("ns=%d;b=%x", n.Namespace, n.Opaque)
	default:
		return fmt.Sprintf("<unknown type %d>", n.Type)
	}
}
