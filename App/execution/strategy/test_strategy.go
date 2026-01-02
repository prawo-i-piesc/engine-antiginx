package strategy

import (
	"Engine-AntiGinx/App/Tests"
	"sync"
)

type TestStrategy interface {
	Execute(ctx TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool)
	GetName() string
}

type TestContext struct {
	Target string
	Args   []string
}
