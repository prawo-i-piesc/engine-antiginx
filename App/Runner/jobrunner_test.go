package Runner

import (
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution"
	"Engine-AntiGinx/App/execution/strategy"
	"os"
	"sync"
	"testing"
)

type MockReporter struct {
	Ch chan Tests.TestResult
}

func (mr *MockReporter) StartListening() <-chan int {
	go func() {
		for range mr.Ch {
			//	Consume all data passed
		}
	}()
	mockChan := make(chan int, 1)
	mockChan <- 0
	return mockChan
}

type MockResolver struct{}

func (mRes *MockResolver) Resolve(ch chan Tests.TestResult, taskId string,
	target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter.Reporter {
	return &MockReporter{ch}
}

type MockStrategy struct {
	name string
}

func (m *MockStrategy) Execute(ctx strategy.TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	defer wg.Done()
	channel <- Tests.TestResult{
		Name:        "Mock test",
		Certainty:   0,
		ThreatLevel: 0,
		Metadata:    nil,
		Description: "Mock test",
	}
}

func (m *MockStrategy) GetName() string {
	return m.name
}
func (m *MockStrategy) GetPreferredReporterType() strategy.ReporterType {
	// It will be changed to mock
	return strategy.CLIReporter
}

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
	os.Unsetenv("BACK_URL")
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
		Strategies:  []strategy.TestStrategy{&MockStrategy{name: "--tests"}},
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
		Strategies:  []strategy.TestStrategy{&MockStrategy{name: "--tests"}},
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
