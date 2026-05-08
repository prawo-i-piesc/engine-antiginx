package Runner

import (
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
	"testing"
)

// Will be used when a factory pattern appears in project
//type MockReporter struct {
//}
//
//func (r *MockReporter) StartListening() <-chan int {
//	done := make(chan int)
//	done <- 0
//	return done
//}

// For now tests only cover cases with CliReporter
// Add more cases after implementation of factory pattern
func TestJobRunner_Orchestrate(t *testing.T) {
	if _, isSet := os.LookupEnv("BACK_URL"); isSet {
		_ = os.Unsetenv("BACK_URL")
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
			runner.Orchestrate(val.plan, &MockResolver{})
		})
	}

}
