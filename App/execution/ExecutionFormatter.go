package execution

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution/strategy"
	parameterparser "Engine-AntiGinx/App/parser/impl"
	"os"
)

type Formatter struct{}

// InitializeFormatter creates a new instance of the Formatter.
// It is used to prepare the environment for transforming raw command-line
// arguments into a structured execution plan.
func InitializeFormatter() *Formatter {
	return &Formatter{}
}

// FormatParameters transforms a slice of CommandParameters into a cohesive Plan.
// It extracts global flags (like anti-bot detection), maps specific command names
// to their corresponding test strategies, and validates environment-specific
// requirements such as TaskId.
//
// Arguments:
//   - params: A slice of pointers to CommandParameter, usually provided by the parser.
//
// Panic Behavior:
//
//	If the environment variable "BACK_URL" is set, the function requires a "--taskId"
//	parameter to be present. If missing, it panics with an error.Error (code 101).
//
// Returns:
//
//	A pointer to a Plan ready to be executed by the JobRunner.
func (f *Formatter) FormatParameters(params []*parameterparser.CommandParameter) *Plan {
	target := params[0].Arguments[0]

	// Check for global flags
	antiBotParam := findParam(params, "--antiBotDetection")
	useAntiBotDetection := antiBotParam != -1

	// Map parameters to executable strategies and their specific contexts
	mappedStrategies, mappedContexts := mapStrategies(params, target)
	var taskId string
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
		taskId = params[taskIdParam].Arguments[0]
	}

	return &Plan{
		Target:      target,
		AntiBotFlag: useAntiBotDetection,
		Strategies:  mappedStrategies,
		Contexts:    mappedContexts,
		TaskId:      taskId,
	}
}

// mapStrategies iterates through provided parameters to find matching implementations
// in the strategy registry. It separates the logic of "what to do" (Strategy)
// from "what data to use" (Context).
//
// Returns:
//   - A slice of TestStrategy: The sequence of tests to be performed.
//   - A map of TestContext: Data specific to each strategy, keyed by strategy name.
func mapStrategies(params []*parameterparser.CommandParameter, target string) ([]strategy.TestStrategy, map[string]strategy.TestContext) {
	maxCapacity := len(params) - 1
	if maxCapacity <= 0 {
		return nil, nil
	}

	mappedStrategies := make([]strategy.TestStrategy, 0, maxCapacity)
	mappedContexts := make(map[string]strategy.TestContext)

	// Skip the first parameter (target URL) and iterate through potential tests
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

// findParam is a helper function that performs a linear search through parameters
// to find a match by name. Returns the index of the parameter or -1 if not found.
func findParam(params []*parameterparser.CommandParameter, paramToFind string) int {
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if paramToFind == currPtr.Name {
			return i
		}
	}
	return -1
}
