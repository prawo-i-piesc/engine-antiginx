package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/streadway/amqp"
)

type EngineTask struct {
	Id     string `json:"id"`
	Target string `json:"target_url"`
}

func main() {
	fmt.Println("Engine Daemon starting....")

	// Channel that notifies if any interruption occurred
	closeChannel := make(chan os.Signal, 1)
	signal.Notify(closeChannel, os.Interrupt)

	// Entering infinite loop for listening to rabbitMQ
	isShuttingDown := false

	//	RabbitMQ connection
	conn, err := amqp.Dial("amqp://guest:guest@192.168.0.54:5672/")
	if err != nil {
		fmt.Println(err)
		return
	}
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

		case s := <-closeChannel:
			fmt.Println("Engine Daemon is going down...")
			fmt.Println(fmt.Sprintf("Received a signal %x", s))
			isShuttingDown = true
			closeChannel = nil
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
			cmd := exec.Command("go", "run", "main.go", "test", "--target", task.Target, "--tests", "https", "hsts", "serv-h-a", "--taskId", task.Id)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmdErr := cmd.Run()
			if cmdErr != nil {
				// Error handling logic will be implemented here
				fmt.Printf("Error during processing %s\n", cmdErr)
				msg.Nack(false, false)
				continue
			}
			msg.Ack(false)

		}

	}
}
