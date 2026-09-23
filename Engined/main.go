// Package main runs the Engine-AntiGinx RabbitMQ consumer.
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

// EngineTask is an unused id/target_url payload type; the consumer decodes types.TestJson.
type EngineTask struct {
	Id     string `json:"id"`
	Target string `json:"target_url"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Cannot read .env file")
	}
	fmt.Println("Engine Daemon starting....")

	closeChannel := make(chan os.Signal, 1)
	signal.Notify(closeChannel, os.Interrupt)

	isShuttingDown := false

	rabbitmqURL := os.Getenv("RABBITMQ_URL")
	if rabbitmqURL == "" {
		fmt.Println("Error: RABBITMQ_URL environment variable is not set")
		return
	}

	engineCall, isSet := os.LookupEnv("ENGINE_ANTIGINX_CALL")

	if !isSet || engineCall == "" {
		fmt.Printf("Error: ENGINE_ANTIGINX_CALL environment variable is not set")
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
	consumeSafe(msgs, &isShuttingDown, errMidConn, closeChannel, engineCall)
}

func consumeSafe(msgs <-chan amqp.Delivery, isShuttingDown *bool,
	errMidConn chan *amqp.Error, closeChannel chan os.Signal, engineCall string) {
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
				nackErr := msg.Ack(false)
				if nackErr != nil {
					fmt.Printf("Warning: Failed to nack task %s\n", err.Error())
				}
				continue
			}
			idParam := task.Parameters[taskId]

			ackCounter := getRetryCount(msg)
			fmt.Printf("Ack counter %d \n", ackCounter)
			if ackCounter > int64(3) {
				fmt.Printf("Too many requeing for task with id: %s\n", idParam)
				nackErr := msg.Ack(false)
				if nackErr != nil {
					fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
				}
				continue
			}

			fmt.Printf("Consumer received a task with id: %s\n", idParam)
			fmt.Printf("Target url %s\n", task.Target)

			var stderrBuff bytes.Buffer
			cmdErr := runScan(msg.Body, &stderrBuff, engineCall)

			if cmdErr != nil {
				handleScanError(&stderrBuff, msg, *idParam)
				continue
			} else {
				fmt.Printf("Scan performed successfully: %s\n", idParam)

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
func runScan(messageBody []byte, stderrBuff *bytes.Buffer, engineCall string) error {
	cmd := exec.Command(engineCall, "rawjson")
	cmd.Stdin = bytes.NewReader(messageBody)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrBuff)
	return cmd.Run()
}
func handleScanError(stderrBuff *bytes.Buffer, msg amqp.Delivery, idParam types.CommandParameter) {
	var errJSON Errors.Error
	errBytes := stderrBuff.Bytes()
	if jsonErr := json.Unmarshal(errBytes, &errJSON); jsonErr == nil {
		fmt.Printf("General error from Engine: %v\n", errJSON)
		currRetries := getRetryCount(msg)
		if errJSON.IsRetryable {
			fmt.Printf("Error is retryable. Requeuing task with id: %s | Current retries: %d\n", idParam, currRetries)
			nackErr := msg.Nack(false, false)
			if nackErr != nil {
				fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
			}
		} else {
			fmt.Printf("Error is fatal. Discarding task with id %s", idParam)
			nackErr := msg.Ack(false)
			if nackErr != nil {
				fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
			}
		}
	} else {
		fmt.Printf("Fatal error: %s\n", stderrBuff)
		nackErr := msg.Ack(false)
		if nackErr != nil {
			fmt.Printf("Warning: Failed to nack task %s\n", nackErr.Error())
		}
	}
}

func getRetryCount(msg amqp.Delivery) int64 {
	if xDeath, ok := msg.Headers["x-death"].([]interface{}); ok {
		if len(xDeath) > 0 {
			if deathInfo, ok := xDeath[0].(amqp.Table); ok {
				if count, ok := deathInfo["count"].(int64); ok {
					return count
				}
			}
		}
	}
	return 0
}
