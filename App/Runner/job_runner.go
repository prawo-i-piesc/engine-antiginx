// Package Runner provides the central orchestration logic for the Engine-AntiGinx scanner.
// It coordinates all major components including parameter parsing, HTTP client configuration,
// test registry access, concurrent test execution, and result reporting.
//
// The Runner acts as the main controller that:
//   - Parses command-line parameters to determine which tests to run
//   - Loads target website content once and shares it across all tests
//   - Spawns concurrent goroutines for parallel test execution
//   - Manages result reporting through the Reporter interface
//   - Handles graceful shutdown and synchronization
//
// Architecture:
//   - Fan-out pattern: One HTTP response shared among multiple test workers
//   - Producer-consumer: Tests produce results, reporter consumes them
//   - Synchronization: WaitGroup for test completion, channel for reporter completion
//
// Error codes:
//   - 100: No tests specified for execution (missing --tests parameter)
//   - 201: Invalid test ID (test does not exist in Registry)
package Runner

import (
	error "Engine-AntiGinx/App/Errors"
	HttpClient "Engine-AntiGinx/App/HTTP"
	parameterparser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Registry"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Tests"
	"fmt"
	"net/http"
	"os"

	//"os"
	"sync"
)

// jobRunner is the central orchestrator responsible for coordinating the entire test execution
// lifecycle. It connects all major components of the application and manages their interactions.
//
// The runner implements the following workflow:
//  1. Parameter parsing: Extracts test IDs and target URL from command-line arguments
//  2. Reporter initialization: Selects CLI or backend reporter based on configuration
//  3. Content loading: Fetches target website content once for efficiency
//  4. Concurrent execution: Spawns goroutines for parallel test execution
//  5. Result collection: Gathers test results via channel
//  6. Graceful shutdown: Waits for all tests and reporting to complete
//
// The runner uses a fan-out concurrency pattern where a single HTTP response is shared
// among multiple test worker goroutines, enabling efficient parallel processing without
// redundant HTTP requests.
type jobRunner struct{}

// CreateJobRunner initializes and returns a new instance of jobRunner ready to orchestrate
// test execution. This factory function provides the entry point for creating the main
// application controller.
//
// The returned runner is stateless and can be used to orchestrate multiple test execution
// sessions if needed, though typically only one instance is created per application run.
//
// Returns:
//   - *jobRunner: A new runner instance ready to call Orchestrate()
//
// Example:
//
//	runner := CreateJobRunner()
//	runner.Orchestrate(parsedParameters)
func CreateJobRunner() *jobRunner {
	return &jobRunner{}
}

// Orchestrate is the main execution method that coordinates all components to perform
// security testing. It parses parameters, configures components, executes tests concurrently,
// and manages result reporting with graceful shutdown.
//
// Execution workflow:
//
//  1. Parameter extraction:
//     - Extract target URL from first parameter
//     - Find "--tests" parameter and extract test IDs
//     - Validate that tests are specified
//
//  2. Target formatting:
//     - Format target URL using TargetFormatter
//     - Ensure proper URL structure for HTTP requests
//
//  3. Reporter selection:
//     - Check BACK_URL environment variable
//     - Initialize BackendReporter if BACK_URL is set
//     - Initialize CliReporter otherwise (fallback for local use)
//
//  4. Content loading:
//     - Fetch target website content once via HTTP GET
//     - Share response across all tests for efficiency
//     - Use custom User-Agent headers
//
//  5. Concurrent test execution:
//     - Create buffered result channel (capacity: 100)
//     - Start reporter goroutine
//     - Spawn goroutine for each test using WaitGroup
//     - Each test receives shared HTTP response
//
//  6. Graceful shutdown:
//     - Wait for all test goroutines to complete (wg.Wait)
//     - Close result channel to signal reporter
//     - Wait for reporter to finish processing (<-doneChannel)
//     - Report any failed uploads to console
//
// Concurrency architecture:
//   - Fan-out pattern: Single HTTP response → Multiple test workers
//   - Producer-consumer: Test workers → Result channel → Reporter
//   - Synchronization: WaitGroup for tests, channel for reporter
//   - Buffered channel prevents test blocking if reporter is slow
//
// Environment variables:
//   - BACK_URL: If set, results are sent to this HTTP endpoint
//
// Parameters:
//   - params: Parsed command-line parameters including target and test IDs
//
// Panics:
//   - error.Error with code 100: No tests specified (missing --tests parameter)
//   - error.Error with code 201: Invalid test ID (test not found in Registry)
//
// Example:
//
//	runner := CreateJobRunner()
//	params := parser.Parse(os.Args)
//	// params contains: [
//	//   {Name: "--target", Arguments: ["example.com"]},
//	//   {Name: "--tests", Arguments: ["https", "hsts"]},
//	// ]
//	runner.Orchestrate(params)
//	// Output: Test results printed to console or sent to backend
func (j *jobRunner) Orchestrate(params []*parameterparser.CommandParameter) {

	var testsToExecute []string
	target := &params[0].Arguments[0]

	// Skip the first parameter and look for "--tests"
	testParam := findParam(params, "--tests")
	if testParam == -1 {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				- tests keyword not present in params`,
		})
	}
	testsToExecute = params[testParam].Arguments

	// Validate that we actually have tests to run.
	if testsToExecute == nil {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				-  Not found any tests to execute`,
			Source: "Runner",
		})
	}

	// Using target formatter to properly build target URL
	targetFormatter := InitializeTargetFormatter()
	target = targetFormatter.Format(*target, testsToExecute)

	// Preload content required for the tests.
	// Check if anti-bot detection is enabled
	antiBotParam := findParam(params, "--antiBotDetection")
	useAntiBotDetection := antiBotParam != -1
	result := loadWebsiteContent(*target, useAntiBotDetection)
	var wg sync.WaitGroup

	// Create a buffered channel to prevent blocking test execution if the reporter is slow.
	channel := make(chan Tests.TestResult, 100)

	// Determine which reporter to use based on environment configuration.
	var reporter Reporter.Reporter
	if v, exists := os.LookupEnv("BACK_URL"); exists {
		taskIdParam := findParam(params, "--taskId")
		if taskIdParam == -1 {
			panic(error.Error{
				Code: 101,
				Message: `Runner error occurred. This could be due to:
					- Misconfiguration of testId param`,
			})
		}
		reporter = Reporter.InitializeBackendReporter(channel, v, params[taskIdParam].Arguments[0], *target)
	} else {
		reporter = Reporter.InitializeCliReporter(channel)
	}

	// Start the reporter in a separate goroutine.
	// doneChannel will receive a signal (count of failed uploads) when reporting is finished.
	doneChannel := reporter.StartListening()

	// Iterate over the test IDs and spawn a goroutine for each
	for _, val := range testsToExecute {
		t, ok := Registry.GetTest(val)
		if !ok {
			panic(error.Error{
				Code:    201,
				Message: fmt.Sprintf("Parsing error occurred. This could be due to:\n- test with Id %s does not exists", val),
				Source:  "Runner",
			})
		}
		wg.Add(1)

		// Launch the test asynchronously.
		go performTest(t, &wg, channel, result)
	}

	// Wait for all test goroutines to finish producing results.
	wg.Wait()
	close(channel)

	// Block until the reporter processes all remaining items and shuts down.
	failedUploads := <-doneChannel
	if failedUploads > 0 {
		fmt.Printf("Engine failed to send %d requests", failedUploads)
	}
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
	if useAntiBotDetection {
		// Create HTTP client with anti-bot detection enabled
		httpClient := HttpClient.CreateHttpWrapper(
			HttpClient.WithAntiBotDetection(),
			HttpClient.WithHeaders(map[string]string{
				"User-Agent": "AntiGinx-TestClient/1.0",
			}),
		)
		return httpClient.Get(target)
	} else {
		// Create standard HTTP client
		httpClient := HttpClient.CreateHttpWrapper(HttpClient.WithHeaders(map[string]string{
			"User-Agent": "AntiGinx-TestClient/1.0",
		}))
		return httpClient.Get(target)
	}
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
func performTest(test *Tests.ResponseTest, wg *sync.WaitGroup, results chan<- Tests.TestResult, response *http.Response) {
	defer wg.Done()
	testParams := Tests.ResponseTestParams{Response: response}
	testResult := test.Run(testParams)
	results <- testResult
}

func findParam(params []*parameterparser.CommandParameter, paramToFind string) int {
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if paramToFind == currPtr.Name {
			return i
		}
	}
	return -1
}
