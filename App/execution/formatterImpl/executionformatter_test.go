package formatterImpl

import (
	"Engine-AntiGinx/App/Runner"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/parser/config/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

type scanFormatterTest struct {
	Name          string
	wantErr       bool
	input         []*types.CommandParameter
	output        *execution.Plan
	getStrategies func(name string) (strategy.TestStrategy, bool)
	backEnvSet    bool
}

func TestScanFormatter_FormatParameters(t *testing.T) {
	mockStrategy := &Runner.MockStrategy{Name: "--tests"}
	mockAllStrategy := &Runner.MockStrategy{Name: "--all"}
	tests := []scanFormatterTest{
		{
			Name:    "Happy path",
			wantErr: false,
			input: []*types.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"testTarget"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"test"},
				},
			},
			output: &execution.Plan{
				Target:      "testTarget",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockStrategy,
				},
				Contexts: map[string]strategy.TestContext{
					"--tests": {
						Target: "testTarget",
						Args:   []string{"test"},
					},
				},
				TaskId: "",
				IsHelp: false,
			},
			getStrategies: func(name string) (strategy.TestStrategy, bool) {
				return mockStrategy, true
			},
			backEnvSet: false,
		},
		{
			Name:    "TaskId param not set",
			wantErr: true,
			input: []*types.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"testTarget"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"test"},
				},
			},
			output: &execution.Plan{
				Target:      "testTarget",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockStrategy,
				},
				Contexts: map[string]strategy.TestContext{
					"--tests": {
						Target: "testTarget",
						Args:   []string{"test"},
					},
				},
				IsHelp: false,
			},
			getStrategies: func(name string) (strategy.TestStrategy, bool) {
				return mockStrategy, true
			},
			backEnvSet: true,
		},
		{
			Name:    "Formatting with configured taskId",
			wantErr: false,
			input: []*types.CommandParameter{
				{
					Name:      "--target",
					Arguments: []string{"testTarget"},
				},
				{
					Name:      "--tests",
					Arguments: []string{"test"},
				},
				{
					Name:      "--taskId",
					Arguments: []string{"dummy taskId"},
				},
			},
			output: &execution.Plan{
				Target:      "testTarget",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockStrategy,
				},
				Contexts: map[string]strategy.TestContext{
					"--tests": {
						Target: "testTarget",
						Args:   []string{"test"},
					},
				},
				TaskId: "dummy taskId",
				IsHelp: false,
			},
			getStrategies: func(name string) (strategy.TestStrategy, bool) {
				if name == "--taskId" {
					return nil, false
				}
				return mockStrategy, true
			},
			backEnvSet: true,
		},
		{
			Name:    "Formatting with --all param",
			wantErr: false,
			input: []*types.CommandParameter{
				{Name: "--target", Arguments: []string{"testTarget"}},
				{Name: "--tests", Arguments: []string{"test"}},
				{Name: "--all", Arguments: []string{}},
			},
			output: &execution.Plan{
				Target:      "testTarget",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockAllStrategy,
				},
				Contexts: map[string]strategy.TestContext{
					"--all": {
						Target: "testTarget",
						Args:   []string{},
					},
				},
				IsHelp: false,
			},
			getStrategies: func(name string) (strategy.TestStrategy, bool) {
				if name == "--all" {
					return mockAllStrategy, true
				}
				if name == "--taskId" {
					return nil, false
				}
				return mockStrategy, true
			},
			backEnvSet: false,
		},
	}

	for _, val := range tests {
		t.Run(val.Name, func(t *testing.T) {
			if val.backEnvSet {
				t.Setenv("BACK_URL", "test")
			}
			if val.wantErr {
				assert.Panics(t, func() {
					formatter := InitializeFormatter(val.getStrategies)
					formatter.FormatParameters(val.input)
				}, "Should panic on invalid input")
				return
			}

			formatter := InitializeFormatter(val.getStrategies)
			result := formatter.FormatParameters(val.input)

			assert.Equal(t, val.output, result, "Result execution.Plan should match expected output")
		})
	}
}
