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

// Example OPC UA client demonstrating basic operations.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/edgeo-scada/opcua"
)

func main() {
	// Create client
	client, err := opcua.NewClient("localhost:4840",
		opcua.WithEndpoint("opc.tcp://localhost:4840"),
		opcua.WithTimeout(10*time.Second),
		opcua.WithSessionName("Example Client"),
		opcua.WithAutoReconnect(true),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Connect and activate session
	log.Println("Connecting to OPC UA server...")
	if err := client.ConnectAndActivateSession(ctx); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	log.Println("Connected!")

	// Browse the Objects folder
	log.Println("\nBrowsing Objects folder (i=85)...")
	refs, err := client.BrowseNode(ctx, opcua.NewNumericNodeID(0, 85), opcua.BrowseDirectionForward)
	if err != nil {
		log.Fatalf("Browse failed: %v", err)
	}

	fmt.Printf("Found %d nodes:\n", len(refs))
	for _, ref := range refs {
		fmt.Printf("  - %s (%s)\n", ref.DisplayName.Text, ref.NodeClass)
	}

	// Read the Server node's ServerStatus
	log.Println("\nReading Server Status...")
	results, err := client.Read(ctx, []opcua.ReadValueID{
		{NodeID: opcua.NewNumericNodeID(0, 2256), AttributeID: opcua.AttributeValue}, // ServerStatus
	})
	if err != nil {
		log.Printf("Read failed: %v", err)
	} else if len(results) > 0 {
		fmt.Printf("Server Status: %v\n", results[0].Value)
	}

	// Create a subscription
	log.Println("\nCreating subscription...")
	sub, err := client.CreateSubscription(ctx,
		opcua.WithPublishingInterval(1000),
	)
	if err != nil {
		log.Printf("Create subscription failed: %v", err)
	} else {
		fmt.Printf("Subscription created: ID=%d, Interval=%.0fms\n",
			sub.ID, sub.RevisedPublishingInterval)

		// Create monitored items
		items, err := sub.CreateMonitoredItems(ctx, []opcua.ReadValueID{
			{NodeID: opcua.NewNumericNodeID(0, 2258), AttributeID: opcua.AttributeValue}, // CurrentTime
		})
		if err != nil {
			log.Printf("Create monitored items failed: %v", err)
		} else {
			fmt.Printf("Created %d monitored items\n", len(items))
		}

		// Wait for some notifications
		log.Println("Waiting for notifications...")
		timeout := time.After(5 * time.Second)
		for {
			select {
			case notif := <-sub.Notifications():
				fmt.Printf("Notification: ClientHandle=%d, Value=%v\n",
					notif.ClientHandle, notif.Value.Value)
			case <-timeout:
				log.Println("Timeout reached, cleaning up...")
				goto cleanup
			}
		}
	cleanup:
		sub.Delete(ctx)
	}

	// Print metrics
	log.Println("\nClient Metrics:")
	metrics := client.Metrics().Collect()
	fmt.Printf("  Requests Total: %v\n", metrics["requests_total"])
	fmt.Printf("  Requests Success: %v\n", metrics["requests_success"])
	fmt.Printf("  Requests Errors: %v\n", metrics["requests_errors"])

	log.Println("\nDone!")
}
