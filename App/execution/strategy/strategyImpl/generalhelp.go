package strategyImpl

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
)

type generalHelpStrategy struct{}

func NewGeneralHelpStrategy() *generalHelpStrategy {
	return &generalHelpStrategy{}
}

func (s *generalHelpStrategy) Execute(ctx strategy.TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()

	}()
}

func (s *generalHelpStrategy) GetName() string {
	return ""
}
