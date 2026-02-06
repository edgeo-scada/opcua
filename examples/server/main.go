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

// Example OPC UA server demonstrating basic operations.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edgeo-scada/opcua"
)

func main() {
	// Create handler
	handler := opcua.NewMemoryHandler()

	// Add some example nodes
	tempNodeID := opcua.NewNumericNodeID(2, 1)
	handler.AddNode(tempNodeID, opcua.NodeClassVariable, "Temperature", "Temperature Sensor")
	handler.SetValue(tempNodeID, &opcua.Variant{Type: opcua.TypeDouble, Value: 25.5})

	pressureNodeID := opcua.NewNumericNodeID(2, 2)
	handler.AddNode(pressureNodeID, opcua.NodeClassVariable, "Pressure", "Pressure Sensor")
	handler.SetValue(pressureNodeID, &opcua.Variant{Type: opcua.TypeDouble, Value: 101.325})

	statusNodeID := opcua.NewNumericNodeID(2, 3)
	handler.AddNode(statusNodeID, opcua.NodeClassVariable, "Status", "System Status")
	handler.SetValue(statusNodeID, &opcua.Variant{Type: opcua.TypeString, Value: "Running"})

	// Create server
	server, err := opcua.NewServer(":4840", handler,
		opcua.WithServerName("Example OPC UA Server"),
		opcua.WithServerApplicationName("Edgeo Example Server"),
		opcua.WithServerApplicationURI("urn:edgeo:example:server"),
		opcua.WithMaxConnections(100),
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server
	log.Println("Starting OPC UA server on :4840...")
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("Server started!")
	log.Println("Available nodes:")
	log.Println("  - ns=2;i=1 (Temperature)")
	log.Println("  - ns=2;i=2 (Pressure)")
	log.Println("  - ns=2;i=3 (Status)")

	// Update temperature periodically
	go func() {
		temp := 25.5
		for {
			time.Sleep(5 * time.Second)
			temp += (float64(time.Now().UnixNano()%10) - 5) * 0.1
			handler.SetValue(tempNodeID, &opcua.Variant{Type: opcua.TypeDouble, Value: temp})
			log.Printf("Temperature updated: %.2f", temp)
		}
	}()

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("\nShutting down...")
	server.Stop()

	// Print metrics
	log.Println("Server Metrics:")
	metrics := server.Metrics().Collect()
	log.Printf("  Total Requests: %v", metrics["total_requests"])
	log.Printf("  Active Connections: %v", metrics["active_connections"])
	log.Printf("  Active Sessions: %v", metrics["active_sessions"])

	log.Println("Done!")
}
