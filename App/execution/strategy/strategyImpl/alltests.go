package strategyImpl

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/http"
	"sync"
)

type allTestsStrategy struct {
	loadWebsiteContent func(target string, useAntiBotDetection bool) *http.Response
	getAllTests        func() []*Tests.ResponseTest
	format             func(target string, params []string) *string
}

func InitializeAllTestsStrategy(loadWebsiteContent func(target string, useAntiBotDetection bool) *http.Response,
	getAllTests func() []*Tests.ResponseTest,
	format func(target string, params []string) *string) *allTestsStrategy {
	return &allTestsStrategy{
		loadWebsiteContent: loadWebsiteContent,
		getAllTests:        getAllTests,
		format:             format,
	}
}

func (a *allTestsStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	target := a.format(ctx.Target, ctx.Args)
	result, reqInfo := a.loadWebsiteContent(*target, antiBotFlag)

	if reqInfo.Code != 0 {
		channel <- strategy.WrapStrategyResult(nil, nil, reqInfo)
		return
	}

	for _, val := range a.getAllTests() {
		wg.Add(1)
		go strategy.PerformTest(val, wg, channel, result)
	}
}

func (a *allTestsStrategy) GetName() string {
	return "--all"
}

func (a *allTestsStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
