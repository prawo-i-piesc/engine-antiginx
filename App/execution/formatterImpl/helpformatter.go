package formatterImpl

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/parser/config/types"
	"os"
)

type HelpFormatter struct {
	getHelpStrategy func(name string) (strategy.TestStrategy, bool)
}

// NewHelpFormatter initializes and returns a new instance of the HelpFormatter.
func NewHelpFormatter(getHelpStrategy func(name string) (strategy.TestStrategy, bool)) *HelpFormatter {
	return &HelpFormatter{
		getHelpStrategy: getHelpStrategy,
	}
}

// FormatParameters processes the parsed command parameters to construct an execution plan specifically for help operations.
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
		helpStrategy, ok := h.getHelpStrategy("")
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

// mapHelpStrategies transforms a list of command parameters into their corresponding test strategies and execution contexts.
func (h *HelpFormatter) mapHelpStrategies(params []*types.CommandParameter) ([]strategy.TestStrategy, map[string]strategy.TestContext) {
	mappedHelpStrategies := make([]strategy.TestStrategy, 0, len(params))
	mappedHelpContexts := make(map[string]strategy.TestContext)
	for _, val := range params {
		strat, ok := h.getHelpStrategy(val.Name)
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
