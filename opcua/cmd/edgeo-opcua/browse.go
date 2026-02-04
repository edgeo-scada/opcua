package main

import (
	"context"
	"fmt"
	"time"

	"github.com/edgeo-scada/opcua"
	"github.com/spf13/cobra"
)

var browseCmd = &cobra.Command{
	Use:   "browse",
	Short: "Browse the OPC UA address space",
	Long: `Browse nodes in the OPC UA server address space.

Examples:
  edgeo-opcua browse -e opc.tcp://localhost:4840
  edgeo-opcua browse -e opc.tcp://localhost:4840 -n "i=85"
  edgeo-opcua browse -e opc.tcp://localhost:4840 -n "ns=2;s=MyNode" -d forward`,
	RunE: runBrowse,
}

var (
	browseNodeID    string
	browseDirection string
	browseDepth     int
)

func init() {
	browseCmd.Flags().StringVarP(&browseNodeID, "node", "n", "i=84", "Node ID to browse from (default: Root)")
	browseCmd.Flags().StringVarP(&browseDirection, "direction", "d", "forward", "Browse direction: forward, inverse, both")
	browseCmd.Flags().IntVarP(&browseDepth, "depth", "", 1, "Browse depth (1 = immediate children only)")
}

func runBrowse(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	// Parse endpoint
	addr := parseEndpoint(endpoint)

	// Create client
	client, err := opcua.NewClient(addr,
		opcua.WithEndpoint(endpoint),
		opcua.WithTimeout(time.Duration(timeout)*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	// Connect
	if err := client.ConnectAndActivateSession(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Parse node ID
	nodeID, err := parseNodeID(browseNodeID)
	if err != nil {
		return fmt.Errorf("invalid node ID: %w", err)
	}

	// Determine direction
	var direction opcua.BrowseDirection
	switch browseDirection {
	case "forward":
		direction = opcua.BrowseDirectionForward
	case "inverse":
		direction = opcua.BrowseDirectionInverse
	case "both":
		direction = opcua.BrowseDirectionBoth
	default:
		return fmt.Errorf("invalid direction: %s", browseDirection)
	}

	// Browse
	refs, err := client.BrowseNode(ctx, nodeID, direction)
	if err != nil {
		return fmt.Errorf("browse failed: %w", err)
	}

	// Print results
	fmt.Printf("Browsing from: %s\n", browseNodeID)
	fmt.Printf("Direction: %s\n", browseDirection)
	fmt.Printf("Found %d references:\n\n", len(refs))

	for i, ref := range refs {
		fmt.Printf("[%d] %s\n", i+1, ref.DisplayName.Text)
		fmt.Printf("    NodeID:    %s\n", formatNodeID(ref.NodeID))
		fmt.Printf("    NodeClass: %s\n", ref.NodeClass)
		fmt.Printf("    BrowseName: %s\n", ref.BrowseName.Name)
		if ref.TypeDefinition.Numeric != 0 {
			fmt.Printf("    TypeDef:   %s\n", formatNodeID(ref.TypeDefinition))
		}
		fmt.Println()
	}

	return nil
}
