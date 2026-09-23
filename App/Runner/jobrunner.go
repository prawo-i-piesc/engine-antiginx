// Package Runner orchestrates an execution plan and its reporter.
package Runner

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
	//"os"
	"sync"
)

// jobRunner coordinates strategy execution and reporting.
type jobRunner struct{}

// CreateJobRunner creates a runner.
func CreateJobRunner() *jobRunner {
	return &jobRunner{}
}

// Orchestrate runs the plan and waits for reporting to finish.
func (j *jobRunner) Orchestrate(execPlan *execution.Plan, repResolver Reporter.Resolver) {
	target := execPlan.Target
	contexts := execPlan.Contexts
	flag := execPlan.AntiBotFlag
	isHelp := execPlan.IsHelp

	// Validate that we actually have tests to run.
	strategies := execPlan.Strategies
	if !isHelp && len(strategies) == 0 {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
				-  Not found any tests to execute`,
			Source:      "Runner",
			IsRetryable: false,
		})
	}
	if !isHelp && len(contexts) == 0 {
		panic(error.Error{
			Code: 100,
			Message: `Runner error occurred. This could be due to:
					- Not found any tests to execute`,
			Source:      "Runner",
			IsRetryable: false,
		})
	}

	// Create a buffered channel to prevent blocking test execution if the reporter is slow.
	var wg sync.WaitGroup
	channel := make(chan strategy.ResultWrapper, 100)

	// Determine which reporter to use based on environment configuration.
	reporter := repResolver.Resolve(channel, execPlan.TaskId, target,
		5, 2, strategies)

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
