package strategyImpl

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/url"
	"sync"
)

type allTestsStrategy struct {
	loadWebsiteContent strategy.ContentLoader
	getAllTests        func() []Tests.Test
	format             func(target string, params []string) *string
	canonicalize       func(target string) *url.URL
}

func InitializeAllTestsStrategy(loadWebsiteContent strategy.ContentLoader,
	getAllTests func() []Tests.Test,
	format func(target string, params []string) *string,
	canonicalize func(target string) *url.URL) *allTestsStrategy {
	return &allTestsStrategy{
		loadWebsiteContent: loadWebsiteContent,
		getAllTests:        getAllTests,
		format:             format,
		canonicalize:       canonicalize,
	}
}

func (a *allTestsStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	strategy.RunPhases(strategy.PhaseRun{
		Tests:           a.getAllTests(),
		ResponseTarget:  *a.format(ctx.Target, ctx.Args),
		CanonicalTarget: a.canonicalize(ctx.Target),
		LoadContent:     a.loadWebsiteContent,
		AntiBotFlag:     antiBotFlag,
	}, channel, wg)
}

func (a *allTestsStrategy) GetName() string {
	return "--all"
}

func (a *allTestsStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
