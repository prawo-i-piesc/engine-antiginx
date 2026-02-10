package Reporter

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockStrategyHelpPref struct{}

func (m MockStrategyHelpPref) GetName() string {
	return "test"
}

func (m MockStrategyHelpPref) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
func (m MockStrategyHelpPref) Execute(ctx strategy.TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool) {
}

type MockCliPrefStrategy struct{}

func (m MockCliPrefStrategy) GetName() string {
	return "test"
}

func (m MockCliPrefStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.CLIReporter
}
func (m MockCliPrefStrategy) Execute(ctx strategy.TestContext, channel chan Tests.TestResult, wg *sync.WaitGroup, antiBotFlag bool) {
}

type ResolverTest struct {
	Name             string
	strategies       []strategy.TestStrategy
	wantErr          bool
	wantReporterType reflect.Type
	setEnv           bool
}

func TestResolver_Resolve(t *testing.T) {
	tests := []ResolverTest{
		{
			Name: "Resolve CLI Reporter",
			strategies: []strategy.TestStrategy{
				MockCliPrefStrategy{},
			},
			wantErr:          false,
			wantReporterType: reflect.TypeOf(&cliReporter{}),
			setEnv:           false,
		},
		//{
		//	Name: "Resolve Help Reporter",
		//	strategies: []strategy.TestStrategy{
		//		MockStrategyHelpPref{},
		//	},
		//	wantErr: false,
		//	wantReporterType: reflect.TypeOf(&{}),
		//},
		{
			Name: "Resolve Backend Reporter",
			strategies: []strategy.TestStrategy{
				MockCliPrefStrategy{},
			},
			wantErr:          false,
			wantReporterType: reflect.TypeOf(&backendReporter{}),
			setEnv:           true,
		},
		{
			Name:             "Internal error",
			strategies:       nil,
			wantErr:          true,
			wantReporterType: nil,
			setEnv:           false,
		},
		{
			Name: "Multiple preferred reporters",
			strategies: []strategy.TestStrategy{
				MockStrategyHelpPref{},
				MockCliPrefStrategy{},
			},
			wantErr: true,
			setEnv:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv("BACK_URL", "test")
			}
			defer func() {
				r := recover()
				if tt.wantErr {
					if r == nil {
						t.Errorf("Expected error but got none")
					}

					_, ok := r.(Errors.Error)

					if !ok {
						t.Errorf("Unexpected error %v", r)
					}
				} else {
					if r != nil {
						t.Errorf("Unexpected panic %v", r)
					}
				}
			}()
			resolver := NewResolver()
			reporter := resolver.Resolve(make(chan Tests.TestResult), "test", "test", 0, 0, tt.strategies)
			of := reflect.TypeOf(reporter)
			if !assert.Equal(t, tt.wantReporterType, of) {
				t.Errorf("Expected reporter with type %T but got %T", tt.wantReporterType, of)
			}
		})
	}
}
