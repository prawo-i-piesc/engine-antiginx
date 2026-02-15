package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
)

type ConcreteResolver struct{}

func NewResolver() *ConcreteResolver {
	return &ConcreteResolver{}
}

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
