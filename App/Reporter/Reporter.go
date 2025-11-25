// Package Reporter provides the core interface for test result reporting implementations.
// This file defines the Reporter interface that must be implemented by all reporter types,
// enabling polymorphic handling of different reporting strategies (CLI, HTTP backend, etc.).
package Reporter

// Reporter is the interface that defines the contract for all test result reporting implementations.
// It provides a unified abstraction for consuming test results from a channel and processing them
// according to the specific reporter's strategy.
//
// The interface enables the application to work with different reporting backends without
// coupling the test execution logic to specific output mechanisms. This allows for:
//   - Flexible output destinations (console, HTTP backend, file, etc.)
//   - Easy addition of new reporter types
//   - Testability through mock implementations
//   - Runtime selection of reporting strategy
//
// Current implementations:
//   - cliReporter: Outputs formatted results to stdout (console)
//   - backendReporter: Sends results to external HTTP backend with retry logic
//
// Expected behavior:
//   - StartListening() should spawn a goroutine for asynchronous processing
//   - The reporter should consume all results from its input channel
//   - Processing should continue until the input channel is closed
//   - The returned channel should signal completion and provide error/failure count
//   - Implementations should handle graceful shutdown without data loss
//
// Example usage:
//
//	// Create reporter based on configuration
//	var reporter Reporter
//	if backendURL != "" {
//	    reporter = InitializeBackendReporter(resultChan, backendURL)
//	} else {
//	    reporter = InitializeCliReporter(resultChan)
//	}
//
//	// Start processing
//	doneChan := reporter.StartListening()
//
//	// Send results to reporter...
//	for _, result := range testResults {
//	    resultChan <- result
//	}
//	close(resultChan)
//
//	// Wait for completion
//	failureCount := <-doneChan
//	if failureCount > 0 {
//	    log.Printf("Warning: %d results failed to process", failureCount)
//	}
type Reporter interface {
	// StartListening initiates asynchronous processing of test results from the reporter's
	// input channel. This method must be non-blocking and should spawn a goroutine for
	// background processing.
	//
	// The method returns a receive-only channel that signals when all processing is complete.
	// The integer value sent on this channel represents the count of failed operations:
	//   - 0: All results processed successfully (or no failures possible, as in CLI reporter)
	//   - >0: Number of results that failed to process (e.g., failed HTTP uploads)
	//
	// Implementations must:
	//   - Process all results until the input channel is closed
	//   - Handle errors gracefully with appropriate retry logic if applicable
	//   - Ensure no data loss during shutdown
	//   - Send exactly one value to the returned channel before closing it
	//
	// Returns:
	//   - <-chan int: Completion signal channel with failure count
	StartListening() <-chan int
}
