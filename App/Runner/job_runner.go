package Runner

import (
	parameterparser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/Registry"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Tests"
	"fmt"
	"net/http"
	"sync"
)

type jobRunner struct{}

func createJobRunner() *jobRunner {
	return &jobRunner{}
}

func (j *jobRunner) Orchestrate(params []*parameterparser.CommandParameter, response *http.Response) {
	var testsToExecute *[]string
	for i := 1; i < len(params); i++ {
		if params[i].Name == "--tests" {
			testsToExecute = &params[i].Arguments
		}
	}
	if testsToExecute == nil {
		panic(fmt.Sprint("No tests to make"))
	}

	var wg sync.WaitGroup
	channel := make(chan Tests.TestResult)

	reporter := Reporter.InitializeBackendReporter(channel, "BACK_URL")
	doneChannel := reporter.StartListening()
	for _, val := range *testsToExecute {
		t, ok := Registry.GetTest(val)
		if !ok {
			panic(fmt.Sprintf("Test with id %s does not exists", val))
		}
		wg.Add(1)
		go performTest(t, &wg, channel, response)
	}

	wg.Wait()
	close(channel)
	<-doneChannel
}
func performTest(test *Tests.ResponseTest, wg *sync.WaitGroup, results chan<- Tests.TestResult, response *http.Response) {
	defer wg.Done()
	testParams := Tests.ResponseTestParams{Response: response}
	testResult := test.Run(testParams)
	results <- testResult
}
