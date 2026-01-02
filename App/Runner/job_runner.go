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
//	runner.Orchestrate(execPlan)
func CreateJobRunner() *jobRunner {
	return &jobRunner{}
}

// Orchestrate is the main execution method that coordinates all components to perform
// security testing. It validates the execution plan, configures the reporting infrastructure,
// executes strategies, and manages a graceful shutdown of the concurrency pipeline.
//
// Execution Workflow:
//
//  1. Plan Validation and Extraction:
//     - Validates that the execution plan contains at least one strategy.
//     - Extracts global flags (AntiBotFlag) and target information.
//
//  2. Concurrency Infrastructure Setup:
//     - Initializes a buffered result channel (capacity: 100) to decouple test execution from reporting.
//     - Initializes a sync.WaitGroup to track the lifecycle of asynchronous strategies.
//
//  3. Reporter Selection and Initialization:
//     - Checks for the "BACK_URL" environment variable.
//     - If BACK_URL exists, validates TaskId and initializes the BackendReporter.
//     - Otherwise, falls back to the CliReporter for local terminal output.
//
//  4. Reporting Pipeline Activation:
//     - Starts the reporter's listener goroutine.
//     - Obtains a doneChannel to synchronize the final shutdown sequence.
//
//  5. Concurrent Strategy Execution (Fan-out):
//     - Iterates through the ordered list of strategies in the Plan.
//     - Triggers the Execute method for each strategy, passing the specific context,
//     result channel, and synchronization primitives.
//
//  6. Graceful Shutdown:
//     - Blocks until all strategy-level goroutines signal completion (wg.Wait).
//     - Closes the result channel to signal the reporter that no more data is coming.
//     - Blocks until the reporter processes remaining results and closes the doneChannel.
//     - Reports any failed uploads (e.g., network issues during backend reporting) to Stderr.
//
// Concurrency Architecture:
//   - Producer-Consumer: Test strategies (producers) feed results into a shared buffered channel.
//   - Fan-out: A single execution plan triggers multiple independent strategy executions.
//   - Synchronization: Uses a combination of WaitGroups for worker tracking and channels for state signaling.
//
// Environment Variables:
//   - BACK_URL: If set, the orchestrator switches from CLI output to remote API reporting.
//
// Parameters:
//   - execPlan: A pre-formatted execution plan containing the target, taskId, and strategies.
//
// Panics:
//   - error.Error (Code 100): No tests found in the execution plan.
//   - error.Error (Code 101): BACK_URL is set, but TaskId is missing or empty.
//
// Example:
//
//	runner := CreateJobRunner()
//	plan := &execution.Plan{
//	    Target: "example.com",
//	    Strategies: []strategy.TestStrategy{headerStrat},
//	    TaskId: "uuid-123",
//	}
//	runner.Orchestrate(plan)
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
