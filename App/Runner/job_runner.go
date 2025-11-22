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
	"sync"
)

// jobRunner is responsible for orchestrating the execution of tests based on provided command parameters.
// It manages the lifecycle of test execution including setup, concurrent execution, and reporting.
type jobRunner struct{}

// CreateJobRunner initializes and returns a new instance of jobRunner.
func CreateJobRunner() *jobRunner {
	return &jobRunner{}
}

// Orchestrate parses the command line parameters to identify tests and executes them concurrently.
//
// It performs the following high-level operations:
//  1. Parses command parameters to identify the list of tests to execute (looks for "--tests").
//  2. Initializes the appropriate reporter:
//     - If the "BACK_URL" environment variable is set, it uses the BackendReporter.
//     - Otherwise, it falls back to the CliReporter.
//  3. Preloads necessary website content.
//  4. Spawns concurrent goroutines for each test case.
//  5. Waits for all tests and the reporting process to finish before returning
//
// Orchestrate will panic if:
//   - No "--tests" flag is found in params.
//   - A test ID provided in arguments does not exist in the Registry.
func (j *jobRunner) Orchestrate(params []*parameterparser.CommandParameter) {

	testWebsite := "http://startrinity.com/HttpTester/HttpRestApiClientTester.aspx"
	var testsToExecute []string

	// Skip the first parameter and look for "--tests"
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if currPtr != nil && currPtr.Name == "--tests" {
			testsToExecute = currPtr.Arguments
		}
	}

	// Validate that we actually have tests to run.
	if testsToExecute == nil {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				-  Not found any tests to execute`,
			Source: "Runner",
		})
	}

	// Preload content required for the tests.
	result := loadWebsiteContent(testWebsite)
	var wg sync.WaitGroup

	// Create a buffered channel to prevent blocking test execution if the reporter is slow.
	channel := make(chan Tests.TestResult, 100)

	// Determine which reporter to use based on environment configuration.
	var reporter Reporter.Reporter
	if v, exists := os.LookupEnv("BACK_URL"); exists {
		reporter = Reporter.InitializeBackendReporter(channel, v)
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

// loadWebsiteContent sends an HTTP GET request to the target URL using a custom User-Agent.
// It returns the raw *http.Response which is shared across tests.
func loadWebsiteContent(target string) *http.Response {
	httpClient := HttpClient.CreateHttpWrapper(HttpClient.WithHeaders(map[string]string{
		"User-Agent": "CustomAgent/1.0",
	}))
	return httpClient.Get(target, HttpClient.WithHeaders(map[string]string{
		"User-Agent": "AntiGinx-TestClient/1.0",
	}))
}

// performTest executes a single ResponseTest logic against the provided http.Response.
// It signals the WaitGroup upon completion and sends the result to the results channel.
func performTest(test *Tests.ResponseTest, wg *sync.WaitGroup, results chan<- Tests.TestResult, response *http.Response) {
	defer wg.Done()
	testParams := Tests.ResponseTestParams{Response: response}
	testResult := test.Run(testParams)
	results <- testResult
}
