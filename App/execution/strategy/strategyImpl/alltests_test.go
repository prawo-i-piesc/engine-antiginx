package strategyImpl

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllTestsStrategy_Methods(t *testing.T) {
	formatMock := func(target string, params []string) *string {
		res := "formatted"
		return &res
	}
	canonicalizeMock := func(target string) *url.URL {
		return &url.URL{Host: "test"}
	}
	getAllTestsMock := func() []SiteTests.Test {
		return []SiteTests.Test{}
	}
	loaderMock := func(target string, useAntiBotDetection bool) (*http.Response, *strategy.RequestInfo) {
		return nil, nil
	}

	strat := InitializeAllTestsStrategy(loaderMock, getAllTestsMock, formatMock, canonicalizeMock)

	assert.Equal(t, "--all", strat.GetName())
	assert.Equal(t, strategy.CLIReporter, strat.GetPreferredReporterType())

	ch := make(chan strategy.ResultWrapper, 1)
	wg := &sync.WaitGroup{}
	ctx := strategy.TestContext{Target: "test.com", Args: []string{}}
	
	assert.NotPanics(t, func() {
		strat.Execute(ctx, ch, wg, false)
		wg.Wait()
		close(ch)
	})
}
