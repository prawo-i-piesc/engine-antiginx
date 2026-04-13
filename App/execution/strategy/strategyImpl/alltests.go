package strategyImpl

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/Registry"
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
)

type allTestsStrategy struct{}

func InitializeAllTestsStrategy() *allTestsStrategy {
	return &allTestsStrategy{}
}

func (a *allTestsStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	targetFormatter := helpers.InitializeTargetFormatter()
	target := targetFormatter.Format(ctx.Target, ctx.Args)
	result := loadWebsiteContent(*target, antiBotFlag)

	for _, val := range Registry.GetAllTests() {
		wg.Add(1)
		go performTest(val, wg, channel, result)
	}
}

func (a *allTestsStrategy) GetName() string {
	return "--all"
}

func (a *allTestsStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
