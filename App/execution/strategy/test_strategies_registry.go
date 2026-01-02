package strategy

import (
	error "Engine-AntiGinx/App/Errors"
	"fmt"
)

var strategies = make(map[string]TestStrategy)

func init() {
	registerStrategy(InitializeHeaderStrategy())
}

func registerStrategy(strategy TestStrategy) {
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

func GetStrategy(name string) (TestStrategy, bool) {
	s, ok := strategies[name]
	return s, ok
}
