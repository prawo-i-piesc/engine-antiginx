package formatterImpl

import (
	"Engine-AntiGinx/App/Runner"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/parser/config/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

type helpFormatterTest struct {
	Name            string
	wantErr         bool
	input           []*types.CommandParameter
	output          *execution.Plan
	getHelpStrategy func(name string) (strategy.TestStrategy, bool)
	backEnvSet      bool
}

func TestHelpFormatter_FormatParameters(t *testing.T) {
	mockDefaultHelpStrategy := &Runner.MockStrategy{Name: "defaultHelp"}
	mockHelpStrategy1 := &Runner.MockStrategy{Name: "--help1"}
	mockHelpStrategy2 := &Runner.MockStrategy{Name: "--help2"}

	help1Param := &types.CommandParameter{Name: "--help1", Arguments: nil}
	help2Param := &types.CommandParameter{Name: "--help2", Arguments: nil}
	invalidHelpParam := &types.CommandParameter{Name: "--invalid", Arguments: nil}

	tests := []helpFormatterTest{
		{
			Name:       "Panic when BACK_URL is set",
			wantErr:    true,
			input:      []*types.CommandParameter{help1Param},
			output:     nil,
			backEnvSet: true,
			getHelpStrategy: func(name string) (strategy.TestStrategy, bool) {
				return mockHelpStrategy1, true
			},
		},
		{
			Name:       "Empty params (default help) - Happy path",
			wantErr:    false,
			input:      []*types.CommandParameter{},
			backEnvSet: false,
			output: &execution.Plan{
				Target:      "",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockDefaultHelpStrategy,
				},
				Contexts: nil,
				TaskId:   "",
				IsHelp:   true,
			},
			getHelpStrategy: func(name string) (strategy.TestStrategy, bool) {
				if name == "" {
					return mockDefaultHelpStrategy, true
				}
				return nil, false
			},
		},
		{
			Name:       "Empty params (default help) - Strategy not found",
			wantErr:    true,
			input:      []*types.CommandParameter{},
			backEnvSet: false,
			output:     nil,
			getHelpStrategy: func(name string) (strategy.TestStrategy, bool) {
				return nil, false
			},
		},
		{
			Name:       "Provided multiple help params - Happy path",
			wantErr:    false,
			input:      []*types.CommandParameter{help1Param, help2Param},
			backEnvSet: false,
			output: &execution.Plan{
				Target:      "",
				AntiBotFlag: false,
				Strategies: []strategy.TestStrategy{
					mockHelpStrategy1,
					mockHelpStrategy2,
				},
				Contexts: map[string]strategy.TestContext{
					"--help1": {
						Target: "",
						Args:   nil,
					},
					"--help2": {
						Target: "",
						Args:   nil,
					},
				},
				TaskId: "",
				IsHelp: true,
			},
			getHelpStrategy: func(name string) (strategy.TestStrategy, bool) {
				if name == "--help1" {
					return mockHelpStrategy1, true
				}
				if name == "--help2" {
					return mockHelpStrategy2, true
				}
				return nil, false
			},
		},
		{
			Name:       "Provided help params - Invalid param passed",
			wantErr:    true,
			input:      []*types.CommandParameter{help1Param, invalidHelpParam},
			backEnvSet: false,
			output:     nil,
			getHelpStrategy: func(name string) (strategy.TestStrategy, bool) {
				if name == "--help1" {
					return mockHelpStrategy1, true
				}
				return nil, false
			},
		},
	}

	for _, val := range tests {
		t.Run(val.Name, func(t *testing.T) {
			if val.backEnvSet {
				t.Setenv("BACK_URL", "test")
			}

			if val.wantErr {
				assert.Panics(t, func() {
					formatter := NewHelpFormatter(val.getHelpStrategy)
					formatter.FormatParameters(val.input)
				}, "Should panic on invalid input or environment")
				return
			}

			formatter := NewHelpFormatter(val.getHelpStrategy)
			result := formatter.FormatParameters(val.input)

			assert.Equal(t, val.output, result, "Result execution.Plan should match expected output")
		})
	}
}
