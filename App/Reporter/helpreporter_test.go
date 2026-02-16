package Reporter

import (
	"Engine-AntiGinx/App/execution/strategy"
	"testing"
)

type helpRepTest struct {
	Name             string
	TestResult       strategy.ResultWrapper
	ExpectedFailures int
}

func prepareHelpData() strategy.ResultWrapper {
	helpMess := strategy.HelpStrategyResult{}
	helpSec := []strategy.HelpSection{
		{
			SectionName: "test section",
			SectionData: "test data",
		},
	}
	helpMess.AppendSection(helpSec)
	helpMess.HelpHeader("test header")
	return strategy.WrapStrategyResult(nil, &helpMess)
}
func TestHelpReporter_StartListening(t *testing.T) {
	tests := []helpRepTest{
		{
			Name:             "Happy path",
			TestResult:       prepareHelpData(),
			ExpectedFailures: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ch := make(chan strategy.ResultWrapper, 10)
			reporter := NewHelpReporter(ch)
			done := reporter.StartListening()
			ch <- tt.TestResult
			close(ch)
			failed := <-done
			if failed != tt.ExpectedFailures {
				t.Errorf("Failed uploads %d, expected %d", failed, tt.ExpectedFailures)
			}
		})
	}
}
