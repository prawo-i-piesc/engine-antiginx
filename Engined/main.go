// Package main provides the Engine-AntiGinx daemon (Engined) that listens for
// security scan tasks from a RabbitMQ message queue and executes them asynchronously.
//
// Engined acts as a background worker service that:
//   - Connects to RabbitMQ and consumes messages from "scan_queue"
//   - Parses incoming JSON task payloads containing target URLs
//   - Spawns the Engine-AntiGinx scanner for each task
//   - Handles graceful shutdown on interrupt signals (SIGINT)
//
// Architecture:
//
//	┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
//	│  Backend    │────▶│  RabbitMQ   │────▶│  Engined        │
//	│  (Producer) │     │  scan_queue │     │  (Consumer)     │
//	└─────────────┘     └─────────────┘     └────────┬────────┘
//	                                                 │
//	                                                 ▼
//	                                        ┌─────────────────┐
//	                                        │  Engine-AntiGinx│
//	                                        │  Scanner (App)  │
//	                                        └─────────────────┘
//
// Environment Variables:
//   - RABBITMQ_URL: Connection string for RabbitMQ (required)
//     Example: amqp://guest:guest@localhost:5672/
//
// Message Format (JSON):
//
//	{
//	    "id": "task-uuid-123",
//	    "target_url": "https://example.com"
//	}
//
// Error Handling:
//   - Invalid JSON messages are NACK'd without requeue
//   - Scanner execution errors are NACK'd without requeue
//   - Successful scans are ACK'd to remove from queue
//
// Graceful Shutdown:
//
// The daemon handles SIGINT (Ctrl+C) gracefully by:
//  1. Setting shutdown flag to prevent new task processing
//  2. Completing any in-progress task
//  3. Closing RabbitMQ connections
//  4. Exiting cleanly
package main

import (
	"Engine-AntiGinx/App/Errors"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"

	"github.com/joho/godotenv"
	"github.com/streadway/amqp"
)

// EngineTask represents a security scan task received from the message queue.
// It contains the necessary information to execute a security assessment
// against a target URL.
//
// Fields:
//   - Id: Unique identifier for the task, used for tracking and reporting
//   - Target: The URL to scan (e.g., "https://example.com")
//
// JSON Example:
//
//	{
//	    "id": "550e8400-e29b-41d4-a716-446655440000",
//	    "target_url": "https://example.com"
//	}
type EngineTask struct {
	Id     string `json:"id"`
	Target string `json:"target_url"`
}

// main is the entry point for the Engine-AntiGinx daemon.
// It establishes a connection to RabbitMQ, sets up message consumption,
// and enters an infinite loop to process incoming scan tasks.
//
// The daemon performs the following steps:
//  1. Set up interrupt signal handling for graceful shutdown
//  2. Read RABBITMQ_URL from environment variables
//  3. Establish connection to RabbitMQ
//  4. Create a channel and start consuming from "scan_queue"
//  5. Process each message by spawning the scanner subprocess
//  6. ACK/NACK messages based on processing success
//  7. Handle graceful shutdown on SIGINT
//
// The main loop uses a select statement to handle:
//   - Incoming messages from RabbitMQ
//   - Interrupt signals for shutdown
//
// Environment Requirements:
//   - RABBITMQ_URL must be set
//   - RabbitMQ server must be accessible
//   - "scan_queue" must exist in RabbitMQ
func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Cannot read .env file")
	}
	fmt.Println("Engine Daemon starting....")

	// Channel that notifies if any interruption occurred
	closeChannel := make(chan os.Signal, 1)
	signal.Notify(closeChannel, os.Interrupt)

	// Entering infinite loop for listening to rabbitMQ
	isShuttingDown := false

	//	RabbitMQ connection
	rabbitmqURL := os.Getenv("RABBITMQ_URL")
	if rabbitmqURL == "" {
		fmt.Println("Error: RABBITMQ_URL environment variable is not set")
		return
	}
	conn, err := amqp.Dial(rabbitmqURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	errMidConn := conn.NotifyClose(make(chan *amqp.Error))
	defer conn.Close()

	taskChannel, err := conn.Channel()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer taskChannel.Close()

	msgs, err := taskChannel.Consume("scan_queue", "", false, false, false, false, nil)
	if err != nil {
		fmt.Println(err)
		isShuttingDown = true
	}
OUTER:
	for {
		if isShuttingDown {
			break
		}
		select {

		case closeMidConn := <-errMidConn:
			fmt.Printf("Connection to RabbitMQ crashed. %s. Engine Daemon is going down... \n", closeMidConn)
			isShuttingDown = true
			closeChannel = nil
			errMidConn = nil
			os.Exit(1)

		case s := <-closeChannel:
			fmt.Println("Engine Daemon is going down...")
			fmt.Println(fmt.Sprintf("Received a signal %x", s))
			isShuttingDown = true
			closeChannel = nil
			errMidConn = nil
			continue OUTER

		case msg := <-msgs:
			var task EngineTask
			err := json.Unmarshal(msg.Body, &task)
			if err != nil {
				fmt.Printf("Task parsing error %s\n", err)
				msg.Nack(false, false)
				continue
			}
			fmt.Printf("Consumer received a task with id: %s\n", task.Id)
			fmt.Printf("Target url %s\n", task.Target)

			var stderrBuff bytes.Buffer
			cmd := exec.Command("/engine-antiginx/App", "test", "--target", task.Target, "--antiBotDetection", "--tests", "https", "hsts", "serv-h-a", "xframe", "cookie-sec", "csp", "--taskId", task.Id)
			cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuff)
			cmdErr := cmd.Run()
			if cmdErr != nil {
				errBytes := stderrBuff.Bytes()
				var errJSON Errors.Error
				if jsonErr := json.Unmarshal(errBytes, &errJSON); jsonErr != nil {
					fmt.Printf("General error from Engine: %v\n", jsonErr)
					if errJSON.IsRetryable {
						fmt.Println("Error is retryable. Requeuing")
						msg.Nack(false, true)
					} else {
						fmt.Println("Error is fatal. Discarding")
						msg.Nack(false, false)
					}
				} else {
					fmt.Printf("Fatal error %v\n", stderrBuff)
					msg.Nack(false, false)
				}
				continue
			} else {
				fmt.Printf("Scan performed successfully: %s\n", task.Id)
				msg.Ack(false)
			}

		}
	}
}
