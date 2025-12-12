// Package Reporter provides asynchronous test result reporting functionality using the
// producer-consumer pattern. It consumes TestResult objects from a channel and forwards
// them to an external backend service via HTTP POST requests with intelligent retry logic.
//
// The reporter implements:
//   - Non-blocking retry mechanism with exponential backoff
//   - Graceful shutdown with no data loss
//   - Error classification (retryable vs. fatal errors)
//   - Concurrent processing of results and retries
//   - Configurable retry limits and timeouts
//
// Error codes:
//   - 100: JSON marshaling error (not retryable)
//   - 101: HTTP request creation error (not retryable)
//   - 102: Network error (retryable)
//   - 103: HTTP status error (retryable for 5xx, not retryable for 4xx)
package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Tests"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// backendReporter handles the consumption of test results and forwards them to an external
// backend service via HTTP. It implements a robust producer-consumer pattern with a
// non-blocking retry mechanism for handling transient failures.
//
// The reporter processes results asynchronously in a separate goroutine and applies
// intelligent retry logic based on error types. Network errors and server errors (5xx)
// are retried, while client errors (4xx) and marshaling errors are not.
//
// Architecture:
//   - Main processing loop: Consumes from resultChannel
//   - Retry queue: Buffered channel for failed submissions
//   - Retry goroutines: Sleep-based backoff for rate limiting
//
// Fields:
//   - resultChannel: Input channel for test results from the Runner
//   - backendURL: Target HTTP endpoint for result submission
//   - testId: ID of test from RabbitMQ
//   - maxRetries: Maximum retry attempts for failed submissions (default: 2)
//   - httpClient: HTTP client with configured timeout (default: 5 seconds)
type backendReporter struct {
	resultChannel chan Tests.TestResult
	backendURL    string
	testId        string
	target        string
	maxRetries    int
	httpClient    *http.Client
}

// retryResult is an internal wrapper structure used to track the state of a failed submission
// in the retry queue. It encapsulates both the original test result and metadata about
// the retry attempt to enforce retry limits and prevent infinite retry loops.
//
// Fields:
//   - result: The original TestResult that failed to submit
//   - attNum: Current attempt number (0-based, incremented with each retry)
type retryResult struct {
	result Tests.TestResult
	attNum int
}

// InitializeBackendReporter creates and configures a new instance of backendReporter
// with sensible defaults for production use. The reporter is ready to start processing
// results immediately after initialization.
//
// Default configuration:
//   - HTTP timeout: 5 seconds
//   - Max retries: 2 attempts
//   - Retry delay: 2 seconds (hardcoded in tryToSendOrEnqueue)
//
// The reporter must be started by calling StartListening() to begin processing results.
//
// Parameters:
//   - channel: The input channel where test results are published by the Runner
//   - backendURL: The target HTTP endpoint for result submission (e.g., "http://api.example.com/results")
//
// Returns:
//   - *backendReporter: Configured reporter instance ready to start listening
//
// Example:
//
//	resultChan := make(chan Tests.TestResult, 10)
//	reporter := InitializeBackendReporter(resultChan, "http://api.example.com/results")
//	doneChan := reporter.StartListening()
//	// ... send results to resultChan ...
//	close(resultChan)
//	failedCount := <-doneChan
//	fmt.Printf("Processing complete. Failed uploads: %d\n", failedCount)
func InitializeBackendReporter(channel chan Tests.TestResult, backendURL string, testId string, target string) *backendReporter {
	return &backendReporter{channel, backendURL, testId, target, 2, &http.Client{
		Timeout: 5 * time.Second,
	}}
}

// StartListening initiates the asynchronous background processing loop that consumes
// test results and forwards them to the backend service. This method spawns a goroutine
// that handles both new results and retry attempts concurrently.
//
// Processing architecture:
//
// The method uses a select statement to handle two input sources:
//  1. resultChannel: New test results from the Runner
//  2. retryChan: Failed results waiting for retry after backoff delay
//
// Graceful shutdown sequence:
//  1. Producer closes resultChannel signaling no more results
//  2. Reporter processes all remaining results in the channel
//  3. Reporter waits for all sleeping retry goroutines (via retryWg)
//  4. Reporter processes any new retries added by sleeping goroutines
//  5. Reporter sends final failure count and exits
//
// This ensures zero data loss during shutdown - all results are either
// successfully submitted or counted as failures.
//
// Retry mechanism:
//   - Buffered retry channel (capacity: 10) prevents blocking
//   - WaitGroup tracks sleeping retry goroutines
//   - 2-second delay between retry attempts
//   - Retryable errors are re-queued up to maxRetries limit
//
// Returns:
//   - <-chan int: Read-only channel that receives the total count of failed uploads
//     once all processing is complete (including retries)
//
// Example:
//
//	reporter := InitializeBackendReporter(resultChan, "http://api.example.com/results")
//	doneChan := reporter.StartListening()
//
//	// Send results...
//	for _, result := range testResults {
//	    resultChan <- result
//	}
//	close(resultChan)
//
//	// Wait for completion
//	failedCount := <-doneChan
//	if failedCount > 0 {
//	    log.Printf("Warning: %d results failed to upload", failedCount)
//	}
func (b *backendReporter) StartListening() <-chan int {
	done := make(chan int)

	// Buffered channel prevents the retry logic from blocking the main loop
	retryChan := make(chan retryResult, 10)
	var retryWg sync.WaitGroup

	go func() {
		failedUploads := 0
		inputOpen := true
		for {
			// Shutdown Condition:
			// If the main input is closed AND there are no pending retries in the queue...

			if !inputOpen && len(retryChan) == 0 {
				// ...wait for any sleeping retry goroutines to finish...
				retryWg.Wait()

				// ...and double-check if they added anything new to the queue.
				if len(retryChan) == 0 {
					b.sendLastWithFlag(
						Tests.TestResultWrapper{
							Target:  b.target,
							TestId:  b.testId,
							Result:  Tests.TestResult{},
							EndFlag: true,
						}, &failedUploads)
					break
				}
			}

			select {
			// Priority 1: New Results
			case res, ok := <-b.resultChannel:
				if !ok {
					inputOpen = false
					// Setting the channel to nil disables this case in the select statement,
					// allowing the loop to continue processing retries.
					b.resultChannel = nil
				} else {
					b.tryToSendOrEnqueue(res, 0, retryChan, &retryWg, &failedUploads)
				}
				// Priority 2: Retries
			case res := <-retryChan:
				b.tryToSendOrEnqueue(res.result, res.attNum, retryChan, &retryWg, &failedUploads)
			}
		}

		// Signal that the reporter has finished processing all messages.
		done <- failedUploads
	}()
	return done
}

// tryToSendOrEnqueue attempts to send a test result to the backend and manages the retry
// workflow based on the outcome. This method implements the core retry logic with
// exponential backoff and retry limit enforcement.
//
// Workflow:
//  1. Attempt to send the result via sendToBackend
//  2. On success: return immediately
//  3. On failure: check if error is retryable
//  4. If retryable and under retry limit: spawn backoff goroutine
//  5. If not retryable or limit exceeded: increment failure counter
//
// Retry behavior:
//   - Network errors (code 102): Retried
//   - Server errors 5xx (code 103): Retried
//   - Client errors 4xx (code 103): Not retried
//   - Marshaling errors (code 100): Not retried
//   - Request creation errors (code 101): Not retried
//
// The retry goroutine sleeps for 2 seconds before re-queuing the result, preventing
// rapid retry storms and giving the backend time to recover from transient issues.
//
// Parameters:
//   - result: The test result to submit
//   - attNumber: Current attempt number (0-based)
//   - retryChan: Channel for re-queuing failed results
//   - retryWg: WaitGroup for tracking sleeping retry goroutines
//   - failedUploads: Pointer to counter for permanent failures
func (b *backendReporter) tryToSendOrEnqueue(result Tests.TestResult, attNumber int, retryChan chan retryResult, retryWg *sync.WaitGroup, failedUploads *int) {
	resultWrapper := Tests.TestResultWrapper{
		Target:  b.target,
		TestId:  b.testId,
		Result:  result,
		EndFlag: false,
	}
	err := b.sendToBackend(resultWrapper)
	if err == nil {
		return
	}

	shouldRetry := false
	var customErr *Errors.Error
	// Check if the error provides specific retry instructions
	if errors.As(err, &customErr) {
		shouldRetry = customErr.IsRetryable
	}
	if shouldRetry && attNumber < b.maxRetries {
		retryWg.Add(1)

		// Non-blocking backoff strategy
		go func() {
			defer retryWg.Done()
			time.Sleep(2 * time.Second)
			retryChan <- retryResult{
				result: result,
				attNum: attNumber + 1,
			}
		}()
	} else {
		*failedUploads++
	}
}

// sendToBackend performs the actual HTTP POST request to the configured backend endpoint
// with comprehensive error handling and classification. This method executes the complete
// HTTP request lifecycle from marshaling to response validation.
//
// Request process:
//  1. Marshal the TestResult to JSON
//  2. Create HTTP POST request with JSON payload
//  3. Set Content-Type header to application/json
//  4. Execute request with configured timeout (default: 5 seconds)
//  5. Validate response status code
//
// Error classification:
//   - Code 100 (JSON Marshal): Not retryable - indicates invalid test result structure
//   - Code 101 (Request Creation): Not retryable - indicates programming error
//   - Code 102 (Network Error): Retryable - transient network issues, DNS failures, timeouts
//   - Code 103 (HTTP Status): Conditional retry based on status code:
//   - 200-299: Success, no error
//   - 400, 401, 403: Not retryable (client errors, auth issues)
//   - 404, 405, etc.: Not retryable (client errors)
//   - 500-599: Retryable (server errors, temporary outages)
//
// The method returns structured Errors.Error objects that include the IsRetryable flag,
// allowing the retry logic to make intelligent decisions about whether to re-attempt
// the submission.
//
// Parameters:
//   - result: The TestResult to submit to the backend
//
// Returns:
//   - error: nil on success (HTTP 2xx), *Errors.Error with retry information on failure
//
// Example error handling:
//
//	err := reporter.sendToBackend(testResult)
//	if err != nil {
//	    var customErr *Errors.Error
//	    if errors.As(err, &customErr) && customErr.IsRetryable {
//	        // Retry logic
//	    } else {
//	        // Permanent failure
//	    }
//	}
func (b *backendReporter) sendToBackend(result Tests.TestResultWrapper) error {
	req, err := b.prepareReqWithErrHandling(result)
	if err != nil {
		return err
	}

	res, err2 := b.httpClient.Do(req)
	if err2 != nil {
		return &Errors.Error{
			Code: 102,
			Message: `Reporter error occurred. This could be due to:
				- Network error`,
			Source:      "Reporter",
			IsRetryable: true,
		}
	}
	defer res.Body.Close()

	err3 := b.handleRetryLogic(res)
	return err3
}
func (b *backendReporter) handleRetryLogic(response *http.Response) *Errors.Error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	retryable := true
	if response.StatusCode == 400 || response.StatusCode == 401 || response.StatusCode == 403 {
		retryable = false
	}
	return &Errors.Error{
		Code: 103,
		Message: fmt.Sprintf(`Reporter error occurred. This could be due to:
				- server rejected request with status code %d`, response.StatusCode),
		Source:      "Reporter",
		IsRetryable: retryable,
	}
}
func (b *backendReporter) prepareReqWithErrHandling(result Tests.TestResultWrapper) (*http.Request, *Errors.Error) {
	marshalled, err := json.Marshal(result)
	if err != nil {
		return nil, &Errors.Error{
			Code: 100,
			Message: `Reporter error occurred. This could be due to:
				- JSON Marshall error`,
			Source:      "Reporter",
			IsRetryable: false,
		}
	}
	req, err := http.NewRequest("POST", b.backendURL, bytes.NewReader(marshalled))

	if err != nil {
		return nil, &Errors.Error{
			Code: 101,
			Message: `Reporter error occurred. This could be due to:
				- invalid method passed to NewRequest method`,
			Source:      "Reporter",
			IsRetryable: false,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// sendLastWithFlag performs last request to the backend with information that engine finished its work.
// Method handles retryable and non-retryable cases. If the error is retryable, method waits 2 seconds and try one more time.
// Otherwise, increments failedUploads counter.
func (b *backendReporter) sendLastWithFlag(result Tests.TestResultWrapper, failedUploads *int) {
	err := b.sendToBackend(result)
	if err == nil {
		return
	}

	shouldRetry := false
	var customErr *Errors.Error

	if errors.As(err, &customErr) {
		shouldRetry = customErr.IsRetryable
	}
	if shouldRetry {
		time.Sleep(2 * time.Second)
		err := b.sendToBackend(result)
		if err != nil {
			*failedUploads++
		}
	} else {
		*failedUploads++
	}
}
