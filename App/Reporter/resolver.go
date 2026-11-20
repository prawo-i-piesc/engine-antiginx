package Reporter

import (
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/execution/strategy"
)

// Resolver selects a reporter for an execution plan.
type Resolver interface {

	// Resolve constructs the selected reporter.
	Resolve(ch chan strategy.ResultWrapper, taskId string,
		target string, strategies []strategy.TestStrategy, logChan chan types.LogEvent, metricsChan chan Metrics.MetricsEvent) Reporter
}
