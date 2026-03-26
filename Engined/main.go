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
	"Engine-AntiGinx/App/parser/config/types"
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

	rabbitConf, err := configureRabbitConnection(rabbitmqURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	conn := rabbitConf.ConnCh
	taskChannel := rabbitConf.TaskCh
	errMidConn := rabbitConf.ErrMidConnCh
	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Printf("Warning: Failed closing connection %s\n", err.Error())
		}
	}()
	defer func() {
		err := taskChannel.Close()
		if err != nil {
			fmt.Printf("Warning: Failed closing connection with task channel %s\n", err.Error())
		}
	}()

	msgs, err := taskChannel.Consume("scan_queue", "", false, false, false, false, nil)
	if err != nil {
		fmt.Println(err)
		isShuttingDown = true
	}
	consumeSafe(msgs, &isShuttingDown, errMidConn, closeChannel)
}

func consumeSafe(msgs <-chan amqp.Delivery, isShuttingDown *bool, errMidConn chan *amqp.Error, closeChannel chan os.Signal) {
OUTER:
	for !*isShuttingDown {
		select {

		case closeMidConn := <-errMidConn:
			fmt.Printf("Connection to RabbitMQ crashed. %s. Engine Daemon is going down... \n", closeMidConn)
			*isShuttingDown = true
			closeChannel = nil
			errMidConn = nil
			os.Exit(1)

		case s := <-closeChannel:
			fmt.Println("Engine Daemon is going down...")
			fmt.Printf("Received a signal %x", s)
			*isShuttingDown = true
			closeChannel = nil
			errMidConn = nil
			continue OUTER

		case msg := <-msgs:
			var task types.TestJson
			err := json.Unmarshal(msg.Body, &task)
			if err != nil {
				fmt.Printf("Task parsing error %s\n", err)
				err := msg.Nack(false, false)
				if err != nil {
					fmt.Printf("Warning: Failed to nack task %s\n", err.Error())
				}
				continue
			}

			taskId := findParam(task.Parameters, "--taskId")
			if taskId < 0 {
				fmt.Printf("Invalid task structure, cannot find taskId param.\n")
				nackErr := msg.Nack(false, false)
				if nackErr != nil {
					fmt.Printf("Warning: Failed to nack task %s\n", err.Error())
				}
			}
			parameter := task.Parameters[taskId]
			fmt.Printf("Consumer received a task with id: %s\n", parameter)
			fmt.Printf("Target url %s\n", task.Target)

			var stderrBuff bytes.Buffer
			cmdErr := runScan(msg.Body, &stderrBuff)

			if cmdErr != nil {
				handleScanError(&stderrBuff, msg)
				continue
			} else {
				fmt.Printf("Scan performed successfully: %s\n", parameter)

				err := msg.Ack(false)
				if err != nil {
					fmt.Printf("Warning: Failed to ack task %s\n", err.Error())
				}
			}
		}
	}
}
func findParam(params []*types.CommandParameter, paramToFind string) int {
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if paramToFind == currPtr.Name {
			return i
		}
	}
	return -1
}
func configureRabbitConnection(queueUrl string) (*RabbitConfig, error) {
	conn, err := amqp.Dial(queueUrl)
	if err != nil {
		return nil, err
	}
	errMidConn := conn.NotifyClose(make(chan *amqp.Error))
	taskChannel, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	return &RabbitConfig{
		ConnCh:       conn,
		TaskCh:       taskChannel,
		ErrMidConnCh: errMidConn,
	}, nil
}
func runScan(messageBody []byte, stderrBuff *bytes.Buffer) error {
	cmd := exec.Command("/engine-antiginx/App", "rawjson")
	cmd.Stdin = bytes.NewReader(messageBody)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrBuff)
	return cmd.Run()
}
func handleScanError(stderrBuff *bytes.Buffer, msg amqp.Delivery) {
	var errJSON Errors.Error
	errBytes := stderrBuff.Bytes()
	if jsonErr := json.Unmarshal(errBytes, &errJSON); jsonErr == nil {
		fmt.Printf("General error from Engine: %v\n", errJSON)
		if errJSON.IsRetryable {
			fmt.Println("Error is retryable. Requeuing")
			nackErr := msg.Nack(false, true)
			if nackErr != nil {
				fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
			}
		} else {
			fmt.Println("Error is fatal. Discarding")
			nackErr := msg.Nack(false, false)
			if nackErr != nil {
				fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
			}
		}
	} else {
		fmt.Printf("Fatal error: %s\n", stderrBuff.String())
		nackErr := msg.Nack(false, false)
		if nackErr != nil {
			fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
		}
	}
}
