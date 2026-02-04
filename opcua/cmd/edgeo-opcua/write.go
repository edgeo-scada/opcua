package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/edgeo-scada/opcua"
	"github.com/spf13/cobra"
)

var writeCmd = &cobra.Command{
	Use:   "write",
	Short: "Write values to OPC UA nodes",
	Long: `Write values to OPC UA nodes.

Examples:
  edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;i=1" -v 42
  edgeo-opcua write -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -v 25.5 -T double
  edgeo-opcua write -e opc.tcp://localhost:4840 -n "i=1234" -v "Hello World" -T string`,
	RunE: runWrite,
}

var (
	writeNodeID string
	writeValue  string
	writeType   string
)

func init() {
	writeCmd.Flags().StringVarP(&writeNodeID, "node", "n", "", "Node ID to write to")
	writeCmd.Flags().StringVar(&writeValue, "value", "", "Value to write")
	writeCmd.Flags().StringVarP(&writeType, "type", "T", "auto", "Value type: auto, bool, int32, uint32, int64, uint64, float, double, string")
	writeCmd.MarkFlagRequired("node")
	writeCmd.MarkFlagRequired("value")
}

func runWrite(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	addr := parseEndpoint(endpoint)

	client, err := opcua.NewClient(addr,
		opcua.WithEndpoint(endpoint),
		opcua.WithTimeout(time.Duration(timeout)*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	if err := client.ConnectAndActivateSession(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Parse node ID
	nodeID, err := parseNodeID(writeNodeID)
	if err != nil {
		return fmt.Errorf("invalid node ID: %w", err)
	}

	// Parse value
	variant, err := parseValue(writeValue, writeType)
	if err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}

	// Write
	err = client.WriteValue(ctx, nodeID, variant)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	fmt.Printf("Successfully wrote value to %s\n", writeNodeID)
	fmt.Printf("  Value: %v\n", variant.Value)
	fmt.Printf("  Type: %s\n", getTypeName(variant.Type))

	return nil
}

func parseValue(value, typeName string) (*opcua.Variant, error) {
	typeName = strings.ToLower(typeName)

	// Auto-detect type if not specified
	if typeName == "auto" {
		typeName = detectType(value)
	}

	switch typeName {
	case "bool", "boolean":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeBoolean, Value: v}, nil

	case "int16":
		v, err := strconv.ParseInt(value, 10, 16)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeInt16, Value: int16(v)}, nil

	case "uint16":
		v, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeUInt16, Value: uint16(v)}, nil

	case "int32", "int":
		v, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeInt32, Value: int32(v)}, nil

	case "uint32", "uint":
		v, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeUInt32, Value: uint32(v)}, nil

	case "int64":
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeInt64, Value: v}, nil

	case "uint64":
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeUInt64, Value: v}, nil

	case "float", "float32":
		v, err := strconv.ParseFloat(value, 32)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeFloat, Value: float32(v)}, nil

	case "double", "float64":
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, err
		}
		return &opcua.Variant{Type: opcua.TypeDouble, Value: v}, nil

	case "string":
		return &opcua.Variant{Type: opcua.TypeString, Value: value}, nil

	default:
		return nil, fmt.Errorf("unknown type: %s", typeName)
	}
}

func detectType(value string) string {
	// Try boolean
	if value == "true" || value == "false" {
		return "bool"
	}

	// Try integer
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return "int64"
	}

	// Try float
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return "double"
	}

	// Default to string
	return "string"
}
