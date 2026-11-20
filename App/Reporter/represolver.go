package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/execution/strategy"
	"log/slog"
	"os"
)

type ConcreteResolver struct{}

// NewResolver creates a reporter resolver.
func NewResolver() *ConcreteResolver {
	return &ConcreteResolver{}
}

// Resolve chooses help, backend or CLI reporting from strategies and environment.
func (r *ConcreteResolver) Resolve(ch chan strategy.ResultWrapper, taskId string,
	target string, strategies []strategy.TestStrategy, logChan chan types.LogEvent, metricsChan chan Metrics.MetricsEvent) Reporter {
	prefReporter := r.checkStrategies(strategies)

	if prefReporter == strategy.HelpReporter {
		return NewHelpReporter(ch)
	}
	if _, exists := os.LookupEnv("PIPE_COMMUNICATION"); exists {
		return InitializePipeReporter(ch, target, taskId, logChan, metricsChan)
	}
	//if v, exists := os.LookupEnv("BACK_URL"); exists {
	// return InitializeBackendReporter(ch, v, taskId, target, clientTimeOut, retryDelay)
	//}

	return InitializeCliReporter(ch)
}

// checkStrategies panics if the strategies disagree on reporter type.
func (r *ConcreteResolver) checkStrategies(strategies []strategy.TestStrategy) strategy.ReporterType {
	stratLen := len(strategies)
	if stratLen == 0 {
		slog.Error("Reporter ConcreteResolver error: internal error - no strategies provided")
		panic(Errors.Error{
			Code: 100,
			Message: `Reporter ConcreteResolver error occurred. This could be due to:
- internal error`,
			Source:      "Reporter ConcreteResolver",
			IsRetryable: false,
		})
	}
	preferredReporter := strategies[0].GetPreferredReporterType()

	for i := 1; i < stratLen; i++ {
		actualReporter := strategies[i].GetPreferredReporterType()
		if preferredReporter != actualReporter {
			slog.Error("Reporter ConcreteResolver error: misconfiguration of engine task - mixed reporter types")
			panic(Errors.Error{
				Code: 101,
				Message: `Reporter ConcreteResolver error occurred. This could be due to:
							- misconfiguration of engine task`,
				Source:      "Reporter ConcreteResolver",
				IsRetryable: false,
			})
		}
	}
	return preferredReporter
}
