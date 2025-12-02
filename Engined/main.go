package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
)

func main() {
	fmt.Println("Engine Daemon starting....")

	// Channel that notifies if any interruption occurred
	closeChannel := make(chan os.Signal, 1)
	signal.Notify(closeChannel, os.Interrupt)

	// Entering infinite loop for listening to rabbitMQ

	isShuttingDown := false
	started := false

OUTTER:
	for {

		if isShuttingDown {
			break
		}

		select {

		case s, ok := <-closeChannel:

			if ok {
				fmt.Println("Engine Daemon is going down...")
				fmt.Println(fmt.Sprintf("Received a signal %x", s))
				isShuttingDown = true
				closeChannel = nil
				continue OUTTER
			}

		default:
			//	Keep running code below until receive kill signal

			if !started {
				fmt.Println("Engine Daemon starter successfully")
				started = true
			}

			//	Full logic of rabbitMQ handling
			t := time.Now()
			fmt.Println(fmt.Sprintf("Engine Daemon is running... %s", t.Format(time.RFC822)))
			time.Sleep(time.Second * 5)
		}

	}

}
