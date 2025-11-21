package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

// backendReporter handles the consumption of test results and forwards them to an external service.
// It acts as a consumer in the producer-consumer pattern, processing results asynchronously.
type backendReporter struct {
	resultChannel <-chan Tests.TestResult
	backendURL    string
}

// InitializeBackendReporter creates and configures a new instance of backendReporter.
//
// Parameters:
//   - channel: The source channel where test results will be published.
//   - backendURL: The endpoint URL where results should be sent.
func InitializeBackendReporter(channel chan Tests.TestResult, backendURL string) *backendReporter {
	return &backendReporter{channel, backendURL}
}

// StartListening begins the background process of consuming test results from the channel.
//
// It spawns a non-blocking goroutine that iterates over the resultChannel until it is closed.
// Once the input channel is closed and all pending items are processed, it sends a value
// to the returned 'done' channel to signal completion.
//
// Usage example:
//
//	done := reporter.StartListening()
//	// ... run tests ...
//	close(resultsChannel) // Signal reporter to stop
//	<-done                // Wait for reporter to finish cleanup
func (b *backendReporter) StartListening() <-chan bool {
	done := make(chan bool)
	go func() {

		// The loop terminates automatically when b.resultChannel is closed by the sender.
		for result := range b.resultChannel {
			b.sendToBackend(result)
		}

		// Signal that the reporter has finished processing all messages.
		done <- true
	}()
	return done
}

// sendToBackend handles the logic of formatting and transmitting a single test result
// to the configured backendURL.
//
// Currently, it prints the result to stdout (placeholder implementation).
func (b *backendReporter) sendToBackend(result Tests.TestResult) {
	//TODO: Implement actual HTTP request logic here
	fmt.Printf("Result of the test %v", result)
}
