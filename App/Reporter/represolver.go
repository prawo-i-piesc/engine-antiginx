package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
)

type ConcreteResolver struct{}

// NewResolver initializes and returns a new instance of the ConcreteResolver struct.
//
// Returns:
//   - *ConcreteResolver: A pointer to the newly created resolver instance
func NewResolver() *ConcreteResolver {
	return &ConcreteResolver{}
}

// Resolve determines and initializes the appropriate Reporter implementation based on
// the provided strategies and environment configuration.
//
// The resolution logic follows this priority order:
// 1. If strategies prefer a HelpReporter, it returns a new HelpReporter.
// 2. If the "BACK_URL" environment variable is set, it returns an initialized BackendReporter.
// 3. Otherwise, it defaults to returning an InitializeCliReporter.
//
// Parameters:
//   - ch: The channel used for transmitting strategy result wrappers
//   - taskId: The unique identifier for the current task
//   - target: The target endpoint or system being tested
//   - clientTimeOut: The timeout duration for the client in seconds (or ms, depending on impl)
//   - retryDelay: The delay duration between retries
//   - strategies: A slice of test strategies to be validated and used for reporting decisions
//
// Returns:
//   - Reporter: An interface satisfying the Reporter contract (Help, Backend, or CLI)
func (r *ConcreteResolver) Resolve(ch chan strategy.ResultWrapper, taskId string,
	target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter {
	prefReporter := r.checkStrategies(strategies)

	if prefReporter == strategy.HelpReporter {
		return NewHelpReporter(ch)
	}
	if v, exists := os.LookupEnv("BACK_URL"); exists {
		return InitializeBackendReporter(ch, v, taskId, target, clientTimeOut, retryDelay)
	}

	return InitializeCliReporter(ch)
}

// checkStrategies validates that all provided strategies share the same preferred reporter type.
//
// This helper method iterates through the provided strategies to ensure consistency.
// It will panic if the strategy list is empty or if there is a conflict in the
// preferred reporter type between different strategies.
//
// Parameters:
//   - strategies: The list of strategies to validate
//
// Returns:
//   - strategy.ReporterType: The unified reporter type preferred by the strategies
func (r *ConcreteResolver) checkStrategies(strategies []strategy.TestStrategy) strategy.ReporterType {
	stratLen := len(strategies)
	if stratLen == 0 {
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
		if preferredReporter != strategies[i].GetPreferredReporterType() {
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
