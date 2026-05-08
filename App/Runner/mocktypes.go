package Runner

import (
	"Engine-AntiGinx/App/Reporter"
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
)

type MockReporter struct {
	Ch chan strategy.ResultWrapper
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

func (mRes *MockResolver) Resolve(ch chan strategy.ResultWrapper, taskId string,
	target string, clientTimeOut int, retryDelay int, strategies []strategy.TestStrategy) Reporter.Reporter {
	return &MockReporter{ch}
}

type MockStrategy struct {
	Name string
}

func (m *MockStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	defer wg.Done()
	testResult := Tests.TestResult{
		Name:        "Mock test",
		Certainty:   0,
		ThreatLevel: 0,
		Metadata:    nil,
		Description: "Mock test",
	}
	channel <- strategy.WrapStrategyResult(&testResult, nil)
}

func (m *MockStrategy) GetName() string {
	return m.Name
}
func (m *MockStrategy) GetPreferredReporterType() strategy.ReporterType {
	// It will be changed to mock
	return strategy.CLIReporter
}
