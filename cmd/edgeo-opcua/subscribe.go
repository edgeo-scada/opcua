package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edgeo-scada/opcua/opcua"
	"github.com/spf13/cobra"
)

var subscribeCmd = &cobra.Command{
	Use:   "subscribe",
	Short: "Subscribe to data changes on OPC UA nodes",
	Long: `Subscribe to data changes on OPC UA nodes and print updates.

Examples:
  edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "ns=2;i=1"
  edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "ns=2;s=Temperature" -i 1000
  edgeo-opcua subscribe -e opc.tcp://localhost:4840 -n "i=2253" -n "i=2254" -s 250`,
	RunE: runSubscribe,
}

var (
	subscribeNodeIDs []string
	publishInterval  float64
	sampleInterval   float64
)

func init() {
	subscribeCmd.Flags().StringArrayVarP(&subscribeNodeIDs, "node", "n", nil, "Node ID(s) to subscribe to (can specify multiple)")
	subscribeCmd.Flags().Float64VarP(&publishInterval, "interval", "i", 1000, "Publishing interval in milliseconds")
	subscribeCmd.Flags().Float64Var(&sampleInterval, "sample", 250, "Sampling interval in milliseconds")
	subscribeCmd.MarkFlagRequired("node")
}

func runSubscribe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt, stopping...")
		cancel()
	}()

	addr := parseEndpoint(endpoint)

	client, err := opcua.NewClient(addr,
		opcua.WithEndpoint(endpoint),
		opcua.WithTimeout(time.Duration(timeout)*time.Millisecond),
		opcua.WithAutoReconnect(true),
	)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	if err := client.ConnectAndActivateSession(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Create subscription
	sub, err := client.CreateSubscription(ctx,
		opcua.WithPublishingInterval(publishInterval),
	)
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}
	defer sub.Delete(context.Background())

	fmt.Printf("Subscription created (ID: %d, Interval: %.0fms)\n", sub.ID, sub.RevisedPublishingInterval)

	// Create monitored items
	itemsToMonitor := make([]opcua.ReadValueID, len(subscribeNodeIDs))
	for i, nodeIDStr := range subscribeNodeIDs {
		nodeID, err := parseNodeID(nodeIDStr)
		if err != nil {
			return fmt.Errorf("invalid node ID %q: %w", nodeIDStr, err)
		}
		itemsToMonitor[i] = opcua.ReadValueID{
			NodeID:      nodeID,
			AttributeID: opcua.AttributeValue,
		}
	}

	items, err := sub.CreateMonitoredItems(ctx, itemsToMonitor,
		opcua.WithSamplingInterval(sampleInterval),
	)
	if err != nil {
		return fmt.Errorf("failed to create monitored items: %w", err)
	}

	fmt.Printf("Monitoring %d nodes:\n", len(items))
	for i, item := range items {
		if item != nil {
			fmt.Printf("  [%d] %s (ID: %d, Interval: %.0fms)\n",
				i+1, subscribeNodeIDs[i], item.ID, item.RevisedSamplingInterval)
		}
	}
	fmt.Println("\nWaiting for data changes (Ctrl+C to stop)...\n")

	// Start the publish loop in a goroutine
	go sub.Run(ctx)

	// Build client handle to node ID mapping
	handleToNode := make(map[uint32]string)
	for i, item := range items {
		if item != nil {
			handleToNode[item.ClientHandle] = subscribeNodeIDs[i]
		}
	}

	// Wait for notifications
	for {
		select {
		case <-ctx.Done():
			return nil
		case notif := <-sub.Notifications():
			ts := time.Now().Format("15:04:05.000")
			nodeID := handleToNode[notif.ClientHandle]
			if nodeID == "" {
				nodeID = fmt.Sprintf("handle=%d", notif.ClientHandle)
			}
			var value interface{}
			if notif.Value.Value != nil {
				value = notif.Value.Value.Value
			}
			fmt.Printf("[%s] %s = %v\n", ts, nodeID, value)
		}
	}
}
