// Package formatterImpl provides implementations of the execution formatter.
package formatterImpl

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/parser/config/types"
	"log/slog"
	"os"
)

type ScanFormatter struct {
	getStrategy func(name string) (strategy.TestStrategy, bool)
}

// InitializeFormatter creates a new instance of the ScanFormatter.
func InitializeFormatter(getStrategy func(name string) (strategy.TestStrategy, bool)) *ScanFormatter {
	return &ScanFormatter{
		getStrategy: getStrategy,
	}
}

// FormatParameters transforms a slice of CommandParameters into a cohesive Plan.
func (f *ScanFormatter) FormatParameters(params []*types.CommandParameter) *execution.Plan {
	slog.Info("Starting to format parsed parameters into execution plan")

	target := params[0].Arguments[0]

	// Check for global flags
	antiBotParam := findParam(params, "--antiBotDetection")
	useAntiBotDetection := antiBotParam != -1

	if useAntiBotDetection {
		slog.Debug("Anti-bot detection flag enabled")
	}

	// Map parameters to executable strategies and their specific contexts
	slog.Debug("Mapping strategies and contexts from parameters")
	mappedStrategies, mappedContexts := f.mapStrategies(params, target)

	var taskId string
	if _, exists := os.LookupEnv("PIPE_COMMUNICATION"); exists {
		slog.Debug("PIPE_COMMUNICATION mode detected, extracting TaskId")
		taskIdParam := findParam(params, "--taskId")
		if taskIdParam == -1 {
			slog.Error("Missing --taskId parameter in PIPE_COMMUNICATION mode")
			panic(error.Error{
				Code:        101,
				Message:     `Runner error occurred. This could be due to: - Misconfiguration of testId param`,
				Source:      "Runner",
				IsRetryable: false,
			})
		}
		taskId = params[taskIdParam].Arguments[0]
		slog.Debug("TaskId extracted successfully", slog.String("taskId", taskId))
	}

	plan := &execution.Plan{
		Target:      target,
		AntiBotFlag: useAntiBotDetection,
		Strategies:  mappedStrategies,
		Contexts:    mappedContexts,
		TaskId:      taskId,
		IsHelp:      false,
	}

	plan.LogPlan()
	slog.Info("Successfully formatted execution plan")
	return plan
}

// mapStrategies iterates through provided parameters to find matching implementations in the strategy registry.
func (f *ScanFormatter) mapStrategies(params []*types.CommandParameter, target string) ([]strategy.TestStrategy, map[string]strategy.TestContext) {
	maxCapacity := len(params) - 1
	if maxCapacity <= 0 {
		return nil, nil
	}

	mappedStrategies := make([]strategy.TestStrategy, 0, maxCapacity)
	mappedContexts := make(map[string]strategy.TestContext)

	// Skip the first parameter (target URL) and iterate through potential tests
	for i := 1; i < len(params); i++ {
		s, ok := f.getStrategy(params[i].Name)
		if ok {
			slog.Debug("Found matching strategy for parameter", slog.String("strategy", s.GetName()))

			if s.GetName() == "--all" {
				slog.Debug("Strategy is '--all', applying shortcut")
				allStrategy := append(make([]strategy.TestStrategy, 0, 1), s)
				allStrategyContext := make(map[string]strategy.TestContext)
				allStrategyContext[s.GetName()] = strategy.TestContext{
					Target: target,
					Args:   params[i].Arguments,
				}
				return allStrategy, allStrategyContext
			}

			mappedStrategies = append(mappedStrategies, s)
			mappedContexts[s.GetName()] = strategy.TestContext{
				Target: target,
				Args:   params[i].Arguments,
			}
		}
	}
	return mappedStrategies, mappedContexts
}

func findParam(params []*types.CommandParameter, paramToFind string) int {
	for i := 1; i < len(params); i++ {
		currPtr := params[i]
		if paramToFind == currPtr.Name {
			return i
		}
	}
	return -1
}
