package execution

import (
	error "Engine-AntiGinx/App/Errors"
	parameterparser "Engine-AntiGinx/App/Parameter-Parser"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
)

type Formatter struct{}

func InitializeFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) FormatParameters(params []*parameterparser.CommandParameter) *Plan {
	target := params[0].Arguments[0]
	antiBotParam := findParam(params, "--antiBotDetection")
	useAntiBotDetection := antiBotParam != -1
	mappedStrategies, mappedContexts := mapStrategies(params, target)
	if _, exists := os.LookupEnv("BACK_URL"); exists {
		taskIdParam := findParam(params, "--taskId")
		if taskIdParam == -1 {
			panic(error.Error{
				Code: 101,
				Message: `Runner error occurred. This could be due to:
					- Misconfiguration of testId param`,
				Source:      "Runner",
				IsRetryable: false,
			})
		}
		taskId := params[taskIdParam].Arguments[0]
		return &Plan{
			Target:      target,
			AntiBotFlag: useAntiBotDetection,
			Strategies:  mappedStrategies,
			Contexts:    mappedContexts,
			TaskId:      taskId,
		}
	}

	return &Plan{
		Target:      target,
		AntiBotFlag: useAntiBotDetection,
		Strategies:  mappedStrategies,
		Contexts:    mappedContexts,
		TaskId:      "",
	}
}

func mapStrategies(params []*parameterparser.CommandParameter, target string) ([]strategy.TestStrategy, map[string]strategy.TestContext) {
	maxCapacity := len(params) - 1
	if maxCapacity <= 0 {
		return nil, nil
	}
	mappedStrategies := make([]strategy.TestStrategy, 0, maxCapacity)
	mappedContexts := make(map[string]strategy.TestContext)
	for i := 1; i < len(params); i++ {
		s, ok := strategy.GetStrategy(params[i].Name)
		if ok {
			mappedStrategies = append(mappedStrategies, s)
			mappedContexts[s.GetName()] = strategy.TestContext{
				Target: target,
				Args:   params[i].Arguments,
			}
		}
	}
	return mappedStrategies, mappedContexts
}
func findParam(params []*parameterparser.CommandParameter, paramToFind string) int {
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if paramToFind == currPtr.Name {
			return i
		}
	}
	return -1
}
