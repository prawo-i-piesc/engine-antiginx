package Reporter

import (
	"Engine-AntiGinx/App/execution/strategy"
)

// Resolver selects a reporter for an execution plan.
type Resolver interface {

// Resolve constructs the selected reporter.
	Resolve(ch chan strategy.ResultWrapper, taskId string,
		target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter
}
