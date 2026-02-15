package Reporter

import (
	"Engine-AntiGinx/App/execution/strategy"
)

type Resolver interface {
	Resolve(ch chan strategy.ResultWrapper, taskId string,
		target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter
}
