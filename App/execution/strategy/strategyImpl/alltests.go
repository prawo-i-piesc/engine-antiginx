package strategyImpl

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/http"
	"sync"
)

type allTestsStrategy struct {
	loadWebsiteContent func(target string, useAntiBotDetection bool) *http.Response
	getAllTests        func() []*Tests.ResponseTest
}

func InitializeAllTestsStrategy(loadWebsiteContent func(target string, useAntiBotDetection bool) *http.Response,
	getAllTests func() []*Tests.ResponseTest) *allTestsStrategy {
	return &allTestsStrategy{
		loadWebsiteContent: loadWebsiteContent,
		getAllTests:        getAllTests,
	}
}

func (a *allTestsStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	targetFormatter := helpers.InitializeTargetFormatter()
	target := targetFormatter.Format(ctx.Target, ctx.Args)
	result := a.loadWebsiteContent(*target, antiBotFlag)

	for _, val := range a.getAllTests() {
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
