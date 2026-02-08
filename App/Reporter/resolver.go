package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
)

type Resolver struct{}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) Resolve(ch chan Tests.TestResult, taskId string,
	target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter {
	prefReporter := r.checkStrategies(strategies)

	if prefReporter == strategy.HelpReporter {
		//	help reporter will be returned
	}
	if v, exists := os.LookupEnv("BACK_URL"); exists {
		return InitializeBackendReporter(ch, v, taskId, target, clientTimeOut, retryDelay)
	}

	return InitializeCliReporter(ch)
}

func (r *Resolver) checkStrategies(strategies []strategy.TestStrategy) strategy.ReporterType {
	stratLen := len(strategies)
	if stratLen == 0 {
		panic(Errors.Error{
			Code: 100,
			Message: `Reporter Resolver error occurred. This could be due to:
							- internal error`,
			Source:      "Reporter Resolver",
			IsRetryable: false,
		})
	}
	preferredReporter := strategies[0].GetPreferredReporterType()

	for i := 1; i < stratLen; i++ {
		if preferredReporter != strategies[i].GetPreferredReporterType() {
			panic(Errors.Error{
				Code: 101,
				Message: `Reporter Resolver error occurred. This could be due to:
							- misconfiguration of engine task`,
				Source:      "Reporter Resolver",
				IsRetryable: false,
			})
		}
	}
	return preferredReporter
}
