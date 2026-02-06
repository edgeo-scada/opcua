package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/edgeo-scada/opcua/opcua"
	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read values from OPC UA nodes",
	Long: `Read attribute values from OPC UA nodes.

Examples:
  edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;i=1"
  edgeo-opcua read -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -a Value
  edgeo-opcua read -e opc.tcp://localhost:4840 -n "i=2253" -n "i=2254"`,
	RunE: runRead,
}

var (
	readNodeIDs    []string
	readAttribute  string
)

func init() {
	readCmd.Flags().StringArrayVarP(&readNodeIDs, "node", "n", nil, "Node ID(s) to read (can specify multiple)")
	readCmd.Flags().StringVarP(&readAttribute, "attribute", "a", "Value", "Attribute to read: NodeId, NodeClass, BrowseName, DisplayName, Value, DataType, etc.")
	readCmd.MarkFlagRequired("node")
}

func runRead(cmd *cobra.Command, args []string) error {
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

	// Parse attribute ID
	attrID := parseAttributeID(readAttribute)

	// Build read requests
	nodesToRead := make([]opcua.ReadValueID, len(readNodeIDs))
	for i, nodeIDStr := range readNodeIDs {
		nodeID, err := parseNodeID(nodeIDStr)
		if err != nil {
			return fmt.Errorf("invalid node ID %q: %w", nodeIDStr, err)
		}
		nodesToRead[i] = opcua.ReadValueID{
			NodeID:      nodeID,
			AttributeID: attrID,
		}
	}

	// Read
	results, err := client.Read(ctx, nodesToRead)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	// Print results
	for i, result := range results {
		fmt.Printf("Node: %s\n", readNodeIDs[i])
		fmt.Printf("  Attribute: %s\n", readAttribute)

		if result.StatusCode.IsBad() {
			fmt.Printf("  Status: %s\n", result.StatusCode)
		} else {
			if result.Value != nil {
				fmt.Printf("  Value: %v\n", result.Value.Value)
				fmt.Printf("  Type: %s\n", getTypeName(result.Value.Type))
			} else {
				fmt.Printf("  Value: <null>\n")
			}
			if !result.SourceTimestamp.IsZero() {
				fmt.Printf("  SourceTimestamp: %s\n", result.SourceTimestamp.Format(time.RFC3339Nano))
			}
			if !result.ServerTimestamp.IsZero() {
				fmt.Printf("  ServerTimestamp: %s\n", result.ServerTimestamp.Format(time.RFC3339Nano))
			}
			fmt.Printf("  Status: %s\n", result.StatusCode)
		}
		fmt.Println()
	}

	return nil
}

func parseAttributeID(name string) opcua.AttributeID {
	switch strings.ToLower(name) {
	case "nodeid":
		return opcua.AttributeNodeID
	case "nodeclass":
		return opcua.AttributeNodeClass
	case "browsename":
		return opcua.AttributeBrowseName
	case "displayname":
		return opcua.AttributeDisplayName
	case "description":
		return opcua.AttributeDescription
	case "value":
		return opcua.AttributeValue
	case "datatype":
		return opcua.AttributeDataType
	case "valuerank":
		return opcua.AttributeValueRank
	case "arraydimensions":
		return opcua.AttributeArrayDimensions
	case "accesslevel":
		return opcua.AttributeAccessLevel
	default:
		return opcua.AttributeValue
	}
}

func getTypeName(t opcua.TypeID) string {
	switch t {
	case opcua.TypeNull:
		return "Null"
	case opcua.TypeBoolean:
		return "Boolean"
	case opcua.TypeSByte:
		return "SByte"
	case opcua.TypeByte:
		return "Byte"
	case opcua.TypeInt16:
		return "Int16"
	case opcua.TypeUInt16:
		return "UInt16"
	case opcua.TypeInt32:
		return "Int32"
	case opcua.TypeUInt32:
		return "UInt32"
	case opcua.TypeInt64:
		return "Int64"
	case opcua.TypeUInt64:
		return "UInt64"
	case opcua.TypeFloat:
		return "Float"
	case opcua.TypeDouble:
		return "Double"
	case opcua.TypeString:
		return "String"
	case opcua.TypeDateTime:
		return "DateTime"
	case opcua.TypeGUID:
		return "GUID"
	case opcua.TypeByteString:
		return "ByteString"
	case opcua.TypeNodeID:
		return "NodeId"
	case opcua.TypeStatusCode:
		return "StatusCode"
	case opcua.TypeQualifiedName:
		return "QualifiedName"
	case opcua.TypeLocalizedText:
		return "LocalizedText"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}
