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

func NewHelpFormatter() *HelpFormatter {
	return &HelpFormatter{}
}

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
