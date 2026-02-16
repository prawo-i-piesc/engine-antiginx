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
// This strategy is responsible for displaying the main help information and usage patterns.
//
// Returns:
//   - *generalHelpStrategy: A pointer to the newly created strategy instance
func NewGeneralHelpStrategy() *generalHelpStrategy {
	return &generalHelpStrategy{}
}

// Execute performs the logic for the general help strategy.
//
// Instead of running a security test, this implementation constructs a help message
// containing usage patterns, options, and examples defined in `sectionsArr`.
// It runs asynchronously, wrapping the help data into a `HelpStrategyResult` and
// sending it through the provided channel.
//
// Implements:
//   - strategy.TestStrategy.Execute
//
// Parameters:
//   - ctx: The execution context (unused in this specific strategy)
//   - channel: The channel to send the constructed help result back to the reporter
//   - wg: WaitGroup used to signal the completion of the help generation
//   - antiBotFlag: Global evasion flag (unused in this specific strategy)
func (s *generalHelpStrategy) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		helpMess := strategy.HelpStrategyResult{}
		helpMess.AppendSection(sectionsArr)
		helpMess.HelpHeader(name)
		result := strategy.WrapStrategyResult(nil, &helpMess)
		channel <- result
	}()
}

// GetName returns the unique identifier for this strategy.
//
// For the general help strategy, this returns an empty string as it serves as the
// default fallback or root help command when no specific test is targeted.
//
// Implements:
//   - strategy.TestStrategy.GetName
//
// Returns:
//   - string: An empty string identifier
func (s *generalHelpStrategy) GetName() string {
	return ""
}

// GetPreferredReporterType specifies the type of reporter best suited for this strategy.
//
// This strategy mandates the use of `HelpReporter` to ensure the output is formatted
// as a readable manual/guide rather than a standard test report.
//
// Implements:
//   - strategy.TestStrategy.GetPreferredReporterType
//
// Returns:
//   - strategy.ReporterType: Always returns strategy.HelpReporter
func (s *generalHelpStrategy) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
