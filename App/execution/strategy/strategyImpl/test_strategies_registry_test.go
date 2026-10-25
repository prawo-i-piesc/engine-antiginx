package strategyImpl

import (
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockDuplicateStrategy struct {
	name string
}

func (m mockDuplicateStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
}
func (m mockDuplicateStrategy) GetName() string {
	return m.name
}
func (m mockDuplicateStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}

func TestRegistry_GetStrategy(t *testing.T) {
	s, ok := GetStrategy("--tests")
	assert.True(t, ok)
	assert.NotNil(t, s)

	sAll, okAll := GetStrategy("--all")
	assert.True(t, okAll)
	assert.NotNil(t, sAll)

	_, okNone := GetStrategy("non-existent")
	assert.False(t, okNone)
}

func TestRegistry_GetHelpStrategy(t *testing.T) {
	hGen, okHGen := GetHelpStrategy("")
	assert.True(t, okHGen)
	assert.NotNil(t, hGen)

	hTests, okHTests := GetHelpStrategy("--tests")
	assert.True(t, okHTests)
	assert.NotNil(t, hTests)

	_, okHNone := GetHelpStrategy("non-existent")
	assert.False(t, okHNone)
}

func TestRegistry_PanicsOnDuplicate(t *testing.T) {
	assert.Panics(t, func() {
		registerStrategy(mockDuplicateStrategy{name: "--tests"})
	})

	assert.Panics(t, func() {
		registerHelpStrategy(mockDuplicateStrategy{name: ""})
	})
}
