package strategyImpl

import (
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneralHelpStrategy_Methods(t *testing.T) {
	strat := NewGeneralHelpStrategy()

	assert.Equal(t, "", strat.GetName())
	assert.Equal(t, strategy.HelpReporter, strat.GetPreferredReporterType())

	ch := make(chan strategy.ResultWrapper, 1)
	wg := &sync.WaitGroup{}

	strat.Execute(strategy.TestContext{}, ch, wg, false)
	wg.Wait()
	close(ch)

	res, ok := <-ch
	assert.True(t, ok)
	exists, helpData := res.GetHelpMessage()
	assert.True(t, exists)
	assert.NotNil(t, helpData)
}

func TestHeaderTestHelp_Methods(t *testing.T) {
	strat := NewHeaderTestHelp()

	assert.Equal(t, "--tests", strat.GetName())
	assert.Equal(t, strategy.HelpReporter, strat.GetPreferredReporterType())

	ch := make(chan strategy.ResultWrapper, 1)
	wg := &sync.WaitGroup{}

	strat.Execute(strategy.TestContext{}, ch, wg, false)
	wg.Wait()
	close(ch)

	res, ok := <-ch
	assert.True(t, ok)
	exists, helpData := res.GetHelpMessage()
	assert.True(t, exists)
	assert.NotNil(t, helpData)
}
