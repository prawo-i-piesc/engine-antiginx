package strategyImpl

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
	"net/url"
	"sync"
)

type headerTestStrategy struct {
	loadWebsiteContent strategy.ContentLoader
	getTest            func(testId string) (SiteTests.Test, bool)
	format             func(target string, params []string) *string
	canonicalize       func(target string) *url.URL
}

// InitializeHeaderStrategy returns a pointer to a new headerTestStrategy.
func InitializeHeaderStrategy(loadWebsiteContent strategy.ContentLoader,
	getTest func(testId string) (SiteTests.Test, bool),
	format func(target string, params []string) *string,
	canonicalize func(target string) *url.URL) *headerTestStrategy {
	return &headerTestStrategy{
		loadWebsiteContent: loadWebsiteContent,
		getTest:            getTest,
		format:             format,
		canonicalize:       canonicalize,
	}
}

// Execute performs the strategy logic by fetching the target website's content and spawning asynchronous sub-tests for each provided argument.
func (h *headerTestStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	selected := make([]SiteTests.Test, 0, len(ctx.Args))
	for _, val := range ctx.Args {
		t, ok := h.getTest(val)
		if !ok {
			panic(error.Error{
				Code:        100,
				Message:     fmt.Sprintf("Parsing error occurred. This could be due to:\n- test with Id %s does not exists", val),
				Source:      "Header Test Strategy",
				IsRetryable: false,
			})
		}
		selected = append(selected, t)
	}

	strategy.RunPhases(strategy.PhaseRun{
		Tests:           selected,
		ResponseTarget:  *h.format(ctx.Target, ctx.Args),
		CanonicalTarget: h.canonicalize(ctx.Target),
		LoadContent:     h.loadWebsiteContent,
		AntiBotFlag:     antiBotFlag,
	}, channel, wg)
}

func (h *headerTestStrategy) GetName() string {
	return "--tests"
}

// GetPreferredReporterType returns the default ReporterType that should be used when running this strategy in the absence of any environment-based override.
func (h *headerTestStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
