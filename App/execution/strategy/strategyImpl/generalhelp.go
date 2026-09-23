package strategyImpl

import (
	"Engine-AntiGinx/App/execution/strategy"
	"sync"
)

var name = "General Help"
var sectionsArr = []strategy.HelpSection{
	{
		SectionName: `PATTERN`,
		SectionData: `antiginx [command input strategy][command input strategy related params]`,
	},
	{
		SectionName: `OPTIONS`,
		SectionData: `command input strategy:
 test - full cli input
 json - json file input
 rawjson - raw json bytes via stdin`,
	},
	{
		SectionName: `USAGE`,
		SectionData: ` antiginx test --target website.com --tests https hsts
 antiginx json filename.json`,
	},
}

type generalHelpStrategy struct{}

// NewGeneralHelpStrategy initializes and returns a new instance of the generalHelpStrategy.
func NewGeneralHelpStrategy() *generalHelpStrategy {
	return &generalHelpStrategy{}
}

// Execute performs the logic for the general help strategy.
func (s *generalHelpStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		helpMess := strategy.HelpStrategyResult{}
		helpMess.AppendSection(sectionsArr)
		helpMess.HelpHeader(name)
		result := strategy.WrapStrategyResult(nil, &helpMess, nil)
		channel <- result
	}()
}

// GetName returns the unique identifier for this strategy.
func (s *generalHelpStrategy) GetName() string {
	return ""
}

// GetPreferredReporterType specifies the type of reporter best suited for this strategy.
func (s *generalHelpStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
