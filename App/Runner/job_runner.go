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
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution"
	"fmt"
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
// execution workflow:
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
func (j *jobRunner) Orchestrate(execPlan *execution.Plan) {
	target := execPlan.Target
	contexts := execPlan.Contexts
	flag := execPlan.AntiBotFlag

	// Validate that we actually have tests to run.
	strategies := execPlan.Strategies
	if len(strategies) == 0 {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				-  Not found any tests to execute`,
			Source:      "Runner",
			IsRetryable: false,
		})
	}

	// Create a buffered channel to prevent blocking test execution if the reporter is slow.
	var wg sync.WaitGroup
	channel := make(chan Tests.TestResult, 100)

	// Determine which reporter to use based on environment configuration.
	var reporter Reporter.Reporter
	if v, exists := os.LookupEnv("BACK_URL"); exists {
		taskIdParam := execPlan.TaskId
		if taskIdParam == "" {
			panic(error.Error{
				Code: 101,
				Message: `Runner error occurred. This could be due to:
					- Misconfiguration of testId param`,
				Source:      "Runner",
				IsRetryable: false,
			})
		}
		reporter = Reporter.InitializeBackendReporter(channel, v, taskIdParam, target)
	} else {
		reporter = Reporter.InitializeCliReporter(channel)
	}

	// Start the reporter in a separate goroutine.
	// doneChannel will receive a signal (count of failed uploads) when reporting is finished.
	doneChannel := reporter.StartListening()

	for _, val := range strategies {
		val.Execute(contexts[val.GetName()], channel, &wg, flag)
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
