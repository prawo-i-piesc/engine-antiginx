package impl

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/parser/config"
	"Engine-AntiGinx/App/parser/config/types"
)

type HelpParser struct{}

func CreateHelpParser() *HelpParser {
	return &HelpParser{}
}

func (h *HelpParser) Parse(userParameters []string) []*types.CommandParameter {
	length := len(userParameters)
	if length < 3 {
		return []*types.CommandParameter{}
	}
	var commands []*types.CommandParameter
	for i := 2; i < length; i++ {
		val := userParameters[i]
		_, ok := config.Params[val]
		if !ok {
			panic(Errors.Error{
				Code: 100,
				Message: `Help parser error occurred. This could be due to:
						- invalid help param passed`,
				Source:      "Help parser",
				IsRetryable: false,
			})
		}
		commands = append(commands, &types.CommandParameter{
			Name:      val,
			Arguments: nil,
		})
	}
	return commands
}
