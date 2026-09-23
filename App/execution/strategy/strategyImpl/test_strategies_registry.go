package strategyImpl

import (
	error "Engine-AntiGinx/App/Errors"
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/Registry"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
)

var strategies = make(map[string]strategy.TestStrategy)
var helpStrategies = make(map[string]strategy.TestStrategy)

func init() {
	// Scan strategies initialization
	formatter := helpers.InitializeTargetFormatter()
	registerStrategy(InitializeHeaderStrategy(strategy.LoadWebsiteContent, Registry.GetTest, formatter.Format, formatter.CanonicalURL))
	registerStrategy(InitializeAllTestsStrategy(strategy.LoadWebsiteContent, Registry.GetAllTests, formatter.Format, formatter.CanonicalURL))

	// Help strategies initialization
	registerHelpStrategy(NewGeneralHelpStrategy())
	registerHelpStrategy(NewHeaderTestHelp())

}

func registerStrategy(strategy strategy.TestStrategy) {
	if _, exists := strategies[strategy.GetName()]; exists {
		panic(error.Error{
			Code:        100,
			Message:     fmt.Sprintf("Strategies registry error occurred. This could be due to:\n- test with Id %s already exists", strategy.GetName()),
			Source:      "Strategies Registry",
			IsRetryable: false,
		})
	}
	strategies[strategy.GetName()] = strategy
}

func registerHelpStrategy(strategy strategy.TestStrategy) {
	if _, exists := helpStrategies[strategy.GetName()]; exists {
		panic(error.Error{
			Code:        100,
			Message:     fmt.Sprintf("Strategies registry error occurred. This could be due to:\n- test with Id %s already exists", strategy.GetName()),
			Source:      "Strategies Registry",
			IsRetryable: false,
		})
	}
	helpStrategies[strategy.GetName()] = strategy
}

// GetStrategy retrieves a registered TestStrategy by its identifier.
func GetStrategy(name string) (strategy.TestStrategy, bool) {
	s, ok := strategies[name]
	return s, ok
}
func GetHelpStrategy(name string) (strategy.TestStrategy, bool) {
	s, ok := helpStrategies[name]
	return s, ok
}
