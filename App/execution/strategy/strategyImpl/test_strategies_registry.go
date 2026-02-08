package strategyImpl

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution/strategy"
	"fmt"
)

// strategies holds the global registry of all available TestStrategy implementations.
// It is unexported to ensure that the registry can only be modified through
// controlled internal functions like registerStrategy.
var strategies = make(map[string]strategy.TestStrategy)
var helpStrategies = make(map[string]strategy.TestStrategy)

// init is a special Go function that runs automatically when the package is initialized.
// It is used here to bootstrap the registry with core strategies, ensuring they
// are available as soon as the application starts.
func init() {
	// Scan strategies initialization
	registerStrategy(InitializeHeaderStrategy())

	// Help strategies initialization

}

// registerStrategy adds a new TestStrategy to the global registry map.
// This function acts as a gatekeeper to ensure that every strategy name is unique.
//
// Arguments:
//   - strategy: An implementation of the TestStrategy interface.
//
// Panic Behavior:
//
//	To prevent accidental configuration errors during development or startup,
//	this function panics with an error.Error (code 100) if a strategy with
//	the same name (retrieved via GetName()) is already registered.
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
// This is the primary entry point for the Formatter or Orchestrator to
// obtain a specific testing algorithm based on user input.
//
// Returns:
//   - TestStrategy: The matching strategy implementation.
//   - bool: A boolean indicating whether the strategy was found (true) or not (false).
func GetStrategy(name string) (strategy.TestStrategy, bool) {
	s, ok := strategies[name]
	return s, ok
}
func GetHelpStrategy(name string) (strategy.TestStrategy, bool) {
	s, ok := helpStrategies[name]
	return s, ok
}
