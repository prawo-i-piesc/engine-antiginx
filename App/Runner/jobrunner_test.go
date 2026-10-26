package Runner

import (
	"Engine-AntiGinx/App/Metrics"
	"Engine-AntiGinx/App/Reporter/types"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
	"testing"
)

func TestJobRunner_Orchestrate(t *testing.T) {
	if _, isSet := os.LookupEnv("PIPE_COMMUNICATION"); isSet {
		_ = os.Unsetenv("PIPE_COMMUNICATION")
	}
	// Given
	mockContext := map[string]strategy.TestContext{
		"--tests": {
			Target: "http://example.com",
			Args:   []string{"https", "hsts", "xframe"},
		},
	}
	happyPlan := &execution.Plan{
		Target:      "https://example.com",
		AntiBotFlag: false,
		Strategies:  []strategy.TestStrategy{&MockStrategy{Name: "--tests"}},
		Contexts:    mockContext,
	}

	noStrategies := &execution.Plan{
		Target:      "https://example.com",
		AntiBotFlag: false,
		Strategies:  []strategy.TestStrategy{},
		Contexts:    mockContext,
	}

	noContexts := &execution.Plan{
		Target:      "https://example.com",
		AntiBotFlag: false,
		Strategies:  []strategy.TestStrategy{&MockStrategy{Name: "--tests"}},
		Contexts:    map[string]strategy.TestContext{},
	}

	tests := []struct {
		name         string
		plan         *execution.Plan
		wantErr      bool
		expectedCode int
	}{
		{
			name:    "Happy path with CLI reporter",
			plan:    happyPlan,
			wantErr: false,
		},
		{
			name:         "No strategies",
			plan:         noStrategies,
			wantErr:      true,
			expectedCode: 100,
		},
		{
			name:         "No contexts",
			plan:         noContexts,
			wantErr:      true,
			expectedCode: 100,
		},
	}

	for _, val := range tests {
		// When
		t.Run(val.name, func(t *testing.T) {
			defer func() {
				r := recover()

				if !val.wantErr {
					if r != nil {
						t.Errorf("Unexpected panic in test %s, \n %v ", val.name, r)
					}
					return
				}

				if r == nil {
					t.Errorf("Expected panic but got none in test %s, \n %v", val.name, r)
				}
			}()

			// Then
			runner := CreateJobRunner()

			// Tworzymy buforowane kanały na potrzeby zaktualizowanej sygnatury Orchestrate
			logChan := make(chan types.LogEvent, 10)
			metricsChan := make(chan Metrics.MetricsEvent, 10)

			runner.Orchestrate(val.plan, &MockResolver{}, logChan, metricsChan)
		})
	}
}
