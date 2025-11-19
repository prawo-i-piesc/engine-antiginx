package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

type backendReporter struct {
	resultChannel <-chan Tests.TestResult
	backendURL    string
}

func InitializeBackendReporter(channel chan Tests.TestResult, backendURL string) *backendReporter {
	return &backendReporter{channel, backendURL}
}

func (b *backendReporter) StartListening() <-chan bool {
	done := make(chan bool)
	go func() {
		for result := range b.resultChannel {
			b.sendToBackend(result)
		}
		fmt.Println("Reporter finished processing.")
		done <- true
	}()
	return done
}

func (b *backendReporter) sendToBackend(result Tests.TestResult) {
	fmt.Printf("Result of the test %v", result)
}
