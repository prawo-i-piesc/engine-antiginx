package formatterImpl

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/execution/strategy/strategyImpl"
	"Engine-AntiGinx/App/parser/config/types"
	"os"
)

type HelpFormatter struct {
}

// NewHelpFormatter initializes and returns a new instance of the HelpFormatter.
//
// Returns:
//   - *HelpFormatter: A pointer to the newly created HelpFormatter instance
func NewHelpFormatter() *HelpFormatter {
	return &HelpFormatter{}
}

// FormatParameters processes the parsed command parameters to construct an execution plan
// specifically for help operations.
//
// This method enforces strict environment checks:
//  1. It validates that the "BACK_URL" environment variable is NOT set. If it is,
//     the method panics, as help operations are incompatible with backend mode.
//  2. If no parameters are provided, it attempts to load a default help strategy.
//  3. If parameters are present, it maps them to specific help strategies via `mapHelpStrategies`.
//
// Parameters:
//   - params: A slice of CommandParameter objects parsed from user input
//
// Returns:
//   - *execution.Plan: A fully constructed plan containing the target strategies and contexts
func (h *HelpFormatter) FormatParameters(params []*types.CommandParameter) *execution.Plan {
	if _, exists := os.LookupEnv("BACK_URL"); exists {
		panic(Errors.Error{
			Code: 100,
			Message: `Help Formatter error occurred. This could be due to:
					- Cannot perform help operation while BACK_URL env variable is set`,
			Source:      "Help Formatter",
			IsRetryable: false,
		})
	}

	if len(params) < 1 {
		helpStrategy, ok := strategyImpl.GetHelpStrategy("")
		if !ok {
			panic(Errors.Error{
				Code: 102,
				Message: `Help Formatter error occurred. This could be due to:
							- invalid help param passed`,
				Source:      "Help Formatter",
				IsRetryable: false,
			})
		}
		return &execution.Plan{
			Target:      "",
			AntiBotFlag: false,
			Strategies:  []strategy.TestStrategy{helpStrategy},
			Contexts:    nil,
			TaskId:      "",
			IsHelp:      true,
		}
	}

	mappedHelpStrategies, mappedHelpContexts := h.mapHelpStrategies(params)
	return &execution.Plan{
		Target:      "",
		AntiBotFlag: false,
		Strategies:  mappedHelpStrategies,
		Contexts:    mappedHelpContexts,
		TaskId:      "",
		IsHelp:      true,
	}
}

// mapHelpStrategies transforms a list of command parameters into their corresponding
// test strategies and execution contexts.
//
// It iterates through the provided parameters and retrieves the matching help strategy
// from the strategy implementation. If a strategy cannot be found for a given parameter
// name, the method panics.
//
// Parameters:
//   - params: The list of parameters to map
//
// Returns:
//   - []strategy.TestStrategy: A slice of resolved test strategies
//   - map[string]strategy.TestContext: A map associating strategy names with their contexts
func (h *HelpFormatter) mapHelpStrategies(params []*types.CommandParameter) ([]strategy.TestStrategy, map[string]strategy.TestContext) {
	mappedHelpStrategies := make([]strategy.TestStrategy, 0, len(params))
	mappedHelpContexts := make(map[string]strategy.TestContext)
	for _, val := range params {
		strat, ok := strategyImpl.GetHelpStrategy(val.Name)
		if !ok {
			panic(Errors.Error{
				Code: 102,
				Message: `Help Formatter error occurred. This could be due to:
							- invalid help param passed`,
				Source:      "Help Formatter",
				IsRetryable: false,
			})
		}
		mappedHelpStrategies = append(mappedHelpStrategies, strat)
		mappedHelpContexts[strat.GetName()] = strategy.TestContext{
			Target: "",
			Args:   nil,
		}
	}
	return mappedHelpStrategies, mappedHelpContexts
}
