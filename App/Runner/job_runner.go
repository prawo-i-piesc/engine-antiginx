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
// It performs the following steps:
//  1. Scans params for the "--tests" flag.
//  2. Fetches content from the target website.
//  3. Initializes the reporter backend.
//  4. Spawns a goroutine for each test found in the Registry.
//  5. Waits for all tests to complete and the reporter to finish.
//
// Orchestrate will panic if:
//   - No "--tests" flag is found in params.
//   - A test ID provided in arguments does not exist in the Registry.
func (j *jobRunner) Orchestrate(params []*parameterparser.CommandParameter) {

	// NOTE: Hardcoded URL moved to a variable for clarity, will be changed to parameter from user input later.
	testWebsite := "http://startrinity.com/HttpTester/HttpRestApiClientTester.aspx"
	var testsToExecute *[]string

	// Skip the first parameter (usually the program name) and look for "--tests"
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if currPtr != nil && currPtr.Name == "--tests" {
			testsToExecute = &currPtr.Arguments
		}
	}
	if testsToExecute == nil {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				-  Not found any tests to execute`,
			Source: "Runner",
		})
	}
	result := loadWebsiteContent(testWebsite)
	var wg sync.WaitGroup
	channel := make(chan Tests.TestResult)

	reporter := Reporter.InitializeBackendReporter(channel, "BACK_URL")
	doneChannel := reporter.StartListening()
	for _, val := range *testsToExecute {
		t, ok := Registry.GetTest(val)
		if !ok {
			panic(error.Error{
				Code:    201,
				Message: fmt.Sprintf("Parsing error occurred. This could be due to:\n- test with Id %s does not exists", val),
				Source:  "Runner",
			})
		}
		wg.Add(1)
		go performTest(t, &wg, channel, result)
	}

	wg.Wait()
	close(channel)
	<-doneChannel
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
