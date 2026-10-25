// Package Runner orchestrates an execution plan and its reporter.
package Runner

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"log/slog"
	"sync"
)

// jobRunner coordinates strategy execution and reporting.
type jobRunner struct{}

// CreateJobRunner creates a runner.
func CreateJobRunner() *jobRunner {
	return &jobRunner{}
}

// Orchestrate runs the plan and waits for reporting to finish.
func (j *jobRunner) Orchestrate(execPlan *execution.Plan, repResolver Reporter.Resolver, logChannel chan types.LogEvent, metricsChannel chan Metrics.MetricsEvent) {
	target := execPlan.Target
	contexts := execPlan.Contexts
	flag := execPlan.AntiBotFlag
	isHelp := execPlan.IsHelp

	slog.Info("Starting execution plan orchestration")
	slog.Debug("Validating execution plan strategies and contexts")

	// Validate that we actually have tests to run.
	strategies := execPlan.Strategies
	if !isHelp && len(strategies) == 0 {
		panic(Errors.Error{
			Code:        100,
			Message:     `Runner error occurred. This could be due to: -  Not found any tests to execute`,
			Source:      "Runner",
			IsRetryable: false,
		})
	}
	if !isHelp && len(contexts) == 0 {
		panic(Errors.Error{
			Code:        100,
			Message:     `Runner error occurred. This could be due to: - Not found any tests to execute`,
			Source:      "Runner",
			IsRetryable: false,
		})
	}

	// Create a buffered channel to prevent blocking test execution if the reporter is slow.
	var wg sync.WaitGroup
	channel := make(chan strategy.ResultWrapper, 100)

	// Determine which reporter to use based on environment configuration.
	reporter := repResolver.Resolve(channel, execPlan.TaskId, target, strategies, logChannel, metricsChannel)

	// Start the reporter in a separate goroutine.
	// doneChannel will receive a signal (count of failed uploads) when reporting is finished.
	doneChannel := reporter.StartListening()

	for _, val := range strategies {
		slog.Debug("Dispatching strategy", slog.String("strategy", val.GetName()))
		val.Execute(contexts[val.GetName()], channel, &wg, flag)
	}

	slog.Debug("Waiting for test goroutines to finish")
	// Wait for all test goroutines to finish producing results.
	wg.Wait()
	close(channel)

	slog.Info("All strategies completed, waiting for reporter to flush and shutdown")
	// Block until the reporter processes all remaining items and shuts down.
	failedUploads := <-doneChannel

	if failedUploads > 0 {
		Metrics.IncTotalScans("incomplete")
		slog.Warn("Engine failed to send requests", slog.Int("failedUploads", failedUploads))
	} else {
		Metrics.IncTotalScans("complete")
		slog.Info("Orchestration completed successfully")
	}
	close(logChannel)
}
