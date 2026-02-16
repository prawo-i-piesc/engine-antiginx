package strategyImpl

import (
	error "Engine-AntiGinx/App/Errors"
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/Registry"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// headerTestStrategy implements the strategy.TestStrategy interface.
// It is responsible for orchestrating header-based security assessments
// by fetching target content and executing a suite of sub-tests concurrently.
type headerTestStrategy struct{}

// InitializeHeaderStrategy returns a pointer to a new headerTestStrategy.
// It acts as the constructor for the header-based testing logic.
func InitializeHeaderStrategy() *headerTestStrategy {
	return &headerTestStrategy{}
}

// Execute performs the strategy logic by fetching the target website's content
// and spawning asynchronous sub-tests for each provided argument.
//
// Concurrency Model:
//   - It utilizes a sync.WaitGroup to track the lifecycle of spawned goroutines.
//   - Results are streamed back to the orchestrator via the provided result channel.
//
// Logic Flow:
//  1. Formats the target URL using the targetFormatter helper.
//  2. Fetches the raw website content (respecting the antiBotFlag).
//  3. Iterates through ctx.Args to identify specific sub-tests in the Registry.
//  4. Launches each valid sub-test in its own goroutine.
//
// Panic Behavior:
//
//	If an argument corresponds to a test ID that does not exist in the Registry,
//	the function panics with an error.Error (code 100), which is caught by the
//	global ErrorHandler.
func (h *headerTestStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	// Using target formatter to properly build target URL
	targetFormatter := helpers.InitializeTargetFormatter()
	target := targetFormatter.Format(ctx.Target, ctx.Args)
	result := loadWebsiteContent(*target, antiBotFlag)

	for _, val := range ctx.Args {
		t, ok := Registry.GetTest(val)
		if !ok {
			panic(error.Error{
				Code:        100,
				Message:     fmt.Sprintf("Parsing error occurred. This could be due to:\n- test with Id %s does not exists", val),
				Source:      "Header Test Strategy",
				IsRetryable: false,
			})
		}

		// Increment WaitGroup before launching the goroutine to ensure
		// the orchestrator waits for this specific sub-test.
		wg.Add(1)

		// Launch the test asynchronously.
		go performTest(t, wg, channel, result)

	}
}

// GetName returns the command-line flag identifier associated with this strategy.
// This name is used by the Registry to map the "--tests" parameter to this implementation.
func (h *headerTestStrategy) GetName() string {
	return "--tests"
}

// GetPreferredReporterType returns the default ReporterType that should be used when
// running this strategy in the absence of any environment-based override.
//
// Centralized configuration (for example, environment variables such as BACK_URL)
// may override this preference at runtime to route results to a different reporter,
// but individual strategies should declare their preferred type to keep behavior
// consistent as more reporter types are introduced.
func (h *headerTestStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}

// loadWebsiteContent fetches the target website content via HTTP GET request and returns
// the response for sharing across all test executions. This function performs a single
// HTTP request to avoid redundant network calls for each test.
//
// The function creates an HTTP client with custom headers to identify the scanner and
// executes a GET request against the target URL. The returned response object is then
// shared among all concurrent test goroutines.
//
// HTTP configuration:
//   - User-Agent: "AntiGinx-TestClient/1.0" (identifies the scanner)
//   - Method: GET
//   - Timeout: Configured in HttpClient wrapper (default: 30 seconds)
//
// The function may panic with httpError if:
//   - Request creation fails (code 100)
//   - Network error occurs (code 101)
//   - Non-200 status code returned (code 102)
//   - Response body reading fails (code 200)
//   - Bot protection detected (code 300)
//
// Parameters:
//   - target: The fully qualified URL to request (e.g., "https://example.com")
//
// Returns:
//   - *http.Response: Raw HTTP response object to be shared across all tests
//
// Example:
//
//	response := loadWebsiteContent("https://example.com", true)
//	// Response contains headers, body, status code, etc.
//	// This single response is analyzed by all tests
func loadWebsiteContent(target string, useAntiBotDetection bool) *http.Response {
	opts := []HttpClient.WrapperOption{
		HttpClient.WithHeaders(map[string]string{
			"User-Agent": "AntiGinx-TestClient/1.0",
		}),
	}
	if useAntiBotDetection {
		opts = append(opts, HttpClient.WithAntiBotDetection())
	}
	httpClient := HttpClient.CreateHttpWrapper(opts...)
	var content *http.Response
	var lastErr HttpClient.HttpError

	for i := 0; i < 2; i++ {
		panicTriggerred := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicTriggerred = true
					switch val := r.(type) {
					case HttpClient.HttpError:
						if !val.IsRetryable {
							panic(val)
						}
						lastErr = val
					default:
						panic(r)
					}
				}
			}()
			content = httpClient.Get(target)
		}()
		if !panicTriggerred {
			return content
		}
		if i < 1 {
			time.Sleep(time.Second * 2)
		}
	}
	panic(lastErr)
}

// performTest executes a single security test in a separate goroutine and publishes
// the result to the shared results channel. This function is designed to be called
// as a goroutine and implements the worker pattern for concurrent test execution.
//
// Workflow:
//  1. Wrap HTTP response in ResponseTestParams structure
//  2. Execute the test's Run method with the parameters
//  3. Send the TestResult to the results channel
//  4. Signal completion via WaitGroup (deferred)
//
// The function uses defer wg.Done() to ensure the WaitGroup is always decremented,
// even if the test panics or encounters an error. This guarantees proper synchronization
// and prevents deadlocks in the orchestration logic.
//
// Concurrency considerations:
//   - Thread-safe: Multiple goroutines can call this function concurrently
//   - Shared response: All tests receive the same HTTP response object (read-only)
//   - Channel communication: Results are sent to buffered channel (non-blocking)
//   - Synchronization: WaitGroup ensures proper cleanup
//
// Parameters:
//   - test: Pointer to the ResponseTest to execute
//   - wg: WaitGroup for synchronizing test completion
//   - results: Send-only channel for publishing test results
//   - response: Shared HTTP response object to analyze
//
// Example usage (called by Orchestrate):
//
//	wg.Add(1)
//	go performTest(httpsTest, &wg, resultChannel, httpResponse)
//	// Test runs concurrently, result sent to channel, WaitGroup decremented
func performTest(test *Tests.ResponseTest, wg *sync.WaitGroup, results chan<- strategy.ResultWrapper, response *http.Response) {
	defer wg.Done()
	testParams := Tests.ResponseTestParams{Response: response}
	testResult := test.Run(testParams)
	wrapped := strategy.WrapStrategyResult(&testResult, nil)
	results <- wrapped
}
