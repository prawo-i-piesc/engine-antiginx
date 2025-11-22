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

// backendReporter handles the consumption of test results and forwards them to an external service via HTTP.
//
// It implements a robust producer-consumer pattern with a non-blocking retry mechanism.
// Results are processed asynchronously, and failed requests are re-queued based on
// specific error policies (e.g., network timeouts are retried, 400 Bad Request is not).
type backendReporter struct {
	resultChannel chan Tests.TestResult
	backendURL    string
	maxRetries    int
	httpClient    *http.Client
}

// retryResult is an internal wrapper used to track the state of a failed submission.
// It holds the original test result and the current attempt count to enforce maxRetries limits.
type retryResult struct {
	result Tests.TestResult
	attNum int
}

// InitializeBackendReporter creates and configures a new instance of backendReporter.
//
// It sets up a default HTTP client with a 5-second timeout and a default retry limit (2).
//
// Parameters:
//   - channel: The source channel where the Runner publishes test results.
//   - backendURL: The target API endpoint (e.g., "http://api.example.com/report").
func InitializeBackendReporter(channel chan Tests.TestResult, backendURL string) *backendReporter {
	return &backendReporter{channel, backendURL, 2, &http.Client{
		Timeout: 5 * time.Second,
	}}
}

// StartListening initiates the background processing loop.
//
// It spawns a single goroutine that listens on two channels simultaneously using a select statement:
//  1. The main resultChannel (new incoming tests).
//  2. An internal retry channel (failed tests waiting for re-submission).
//
// Graceful Shutdown:
// The method ensures no data is lost during shutdown. It waits for the input channel
// to close AND for all pending retries (sleeping goroutines) to finish before
// sending the final failure count to the returned channel.
//
// Returns:
//   - A read-only channel that receives the total count of failed uploads
//     once all processing is complete.
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

// tryToSendOrEnqueue attempts to send a result and manages the retry workflow.
//
// If the transmission fails and the error is flagged as Retryable, it spawns
// a goroutine that sleeps for 2 seconds before pushing the result back to the retry channel.
// If the max retries are exceeded or the error is fatal, it increments the failedUploads counter.
func (b *backendReporter) tryToSendOrEnqueue(result Tests.TestResult, attNumber int, retryChan chan retryResult, retryWg *sync.WaitGroup, failedUploads *int) {
	err := b.sendToBackend(result)
	if err == nil {
		return
	}

	shouldRetry := true
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

// sendToBackend performs the actual HTTP POST request to the configured endpoint.
//
// It handles:
//  1. JSON Marshaling of the test result.
//  2. Creation of the HTTP request.
//  3. Execution of the request via the HTTP client.
//  4. Error classification (Network error vs. HTTP 4xx/5xx).
//
// Returns:
//   - nil if the request was successful (HTTP 2xx).
//   - An *Errors.Error indicating the cause of failure and whether it is retryable.
func (b *backendReporter) sendToBackend(result Tests.TestResult) error {
	marshalled, err := json.Marshal(result)
	if err != nil {
		return &Errors.Error{
			Code: 100,
			Message: `Reporter error occurred. This could be due to:
				- JSON Marshall error`,
			Source:      "Reporter",
			IsRetryable: false,
		}
	}
	req, err := http.NewRequest("POST", b.backendURL, bytes.NewReader(marshalled))
	if err != nil {
		return &Errors.Error{
			Code: 101,
			Message: `Reporter error occurred. This could be due to:
				- invalid method passed to NewRequest method`,
			Source:      "Reporter",
			IsRetryable: false,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := b.httpClient.Do(req)
	if err != nil {
		return &Errors.Error{
			Code: 102,
			Message: `Reporter error occurred. This could be due to:
				- Network error`,
			Source:      "Reporter",
			IsRetryable: true,
		}
	}
	defer res.Body.Close()

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}

	retryable := true
	if res.StatusCode == 400 || res.StatusCode == 401 || res.StatusCode == 403 {
		retryable = false
	}
	return &Errors.Error{
		Code: 103,
		Message: fmt.Sprintf(`Reporter error occurred. This could be due to:
				- server rejected request with status code %d`, res.StatusCode),
		Source:      "Reporter",
		IsRetryable: retryable,
	}
}
