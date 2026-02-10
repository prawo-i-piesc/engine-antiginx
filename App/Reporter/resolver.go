package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
)

type Resolver interface {
	Resolve(ch chan Tests.TestResult, taskId string,
		target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter
}
