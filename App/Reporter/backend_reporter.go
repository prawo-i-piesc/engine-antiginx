// Package Reporter provides result consumers.
package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// backendReporter sends results to an HTTP endpoint.
type backendReporter struct {
	resultChannel chan strategy.ResultWrapper
	backendURL    string
	testId        string
	target        string
	maxRetries    int
	retryDelay    int
	httpClient    *http.Client
}

// retryResult tracks a pending retry attempt.
type retryResult struct {
	result strategy.ResultWrapper
	attNum int
}

// InitializeBackendReporter configures HTTP reporting and retry timing.
func InitializeBackendReporter(channel chan strategy.ResultWrapper, backendURL string, testId string, target string, clientTimeOut int, retryDelay int) *backendReporter {
	return &backendReporter{channel, backendURL, testId, target, 2, retryDelay, &http.Client{
		Timeout: time.Duration(clientTimeOut) * time.Second,
	}}
}

// StartListening consumes results and waits for pending retries.
// TODO rozróżnić kiedy jeden z wyników na kanale ma jakieś reqInfo
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
					if failedUploads == 0 {
						b.sendLastWithFlag(
							types.TestResultWrapper{
								Target:  b.target,
								TestId:  b.testId,
								Result:  SiteTests.TestResult{},
								EndFlag: true,
							}, &failedUploads)
					}
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
				} else if pres, info := res.GetReqInfo(); pres {
					b.sendLastWithFlag(
						types.TestResultWrapper{
							Target:      b.target,
							TestId:      b.testId,
							Result:      SiteTests.TestResult{},
							EndFlag:     false,
							ResultType:  types.Message,
							ProcessInfo: *info,
						}, &failedUploads)
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

// tryToSendOrEnqueue retries transient failures up to maxRetries.
func (b *backendReporter) tryToSendOrEnqueue(result strategy.ResultWrapper, attNumber int, retryChan chan retryResult, retryWg *sync.WaitGroup, failedUploads *int) {
	ok, val := result.GetTestResult()
	if !ok {
		*failedUploads++
		return
	}
	resultWrapper := types.TestResultWrapper{
		Target:     b.target,
		TestId:     b.testId,
		Result:     *val,
		EndFlag:    false,
		ResultType: types.Success,
		ProcessInfo: strategy.RequestInfo{
			Message: "Test completed successfully",
			Code:    0,
		},
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
			time.Sleep(time.Duration(b.retryDelay) * time.Second)
			retryChan <- retryResult{
				result: result,
				attNum: attNumber + 1,
			}
		}()
	} else {
		*failedUploads++
	}
}

// sendToBackend POSTs a JSON result and classifies failures.
func (b *backendReporter) sendToBackend(result types.TestResultWrapper) error {
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
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("BACKEND REPORTER\nwarning: failed to close response body: %s", err.Error())
		}
	}()

	err3 := b.handleRetryLogic(res)

	if err3 != nil {
		return err3
	}
	return nil
}
func (b *backendReporter) handleRetryLogic(response *http.Response) *Errors.Error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	retryable := response.StatusCode < 400 || response.StatusCode >= 500
	return &Errors.Error{
		Code: 103,
		Message: fmt.Sprintf(`Reporter error occurred. This could be due to:
				- server rejected request with status code %d`, response.StatusCode),
		Source:      "Reporter",
		IsRetryable: retryable,
	}
}
func (b *backendReporter) prepareReqWithErrHandling(result types.TestResultWrapper) (*http.Request, *Errors.Error) {
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

// sendLastWithFlag sends a message or completion marker with one possible retry.
func (b *backendReporter) sendLastWithFlag(result types.TestResultWrapper, failedUploads *int) {
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
		time.Sleep(time.Duration(b.retryDelay) * time.Second)
		err := b.sendToBackend(result)
		if err != nil {
			*failedUploads++
		}
	} else {
		*failedUploads++
	}
}
