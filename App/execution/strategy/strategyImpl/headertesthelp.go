package strategyImpl

import (
	"Engine-AntiGinx/App/execution/strategy"
	"Engine-AntiGinx/App/parser/config"
	"strings"
	"sync"
)

var header = "Headers tests"

var description = []strategy.HelpSection{
	{
		SectionName: "DESCRIPTION",
		SectionData: `--tests parameter launches a targeted security analysis of your website's configuration
and headers. It provides clear, actionable insights by grading security risks on a standard 
scale from "None" to "Critical" and assigning a confidence score to every finding. Furthermore, it 
automatically cross-references detected issues with the official NIST NVD database to identify 
known CVE vulnerabilities.`,
	},
	{
		SectionName: "OPTIONS",
		SectionData: strings.Join(config.Params["--tests"].Arguments, ", "),
	},
}

type headerTestHelp struct{}

// NewHeaderTestHelp initializes and returns a new instance of the headerTestHelp strategy.
func NewHeaderTestHelp() *headerTestHelp {
	return &headerTestHelp{}
}

// Execute performs the logic for the header test help strategy.
func (h *headerTestHelp) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		helpMess := strategy.HelpStrategyResult{}
		helpMess.AppendSection(description)
		helpMess.HelpHeader(header)
		res := strategy.WrapStrategyResult(nil, &helpMess, nil)
		channel <- res
	}()
}

// GetName returns the unique identifier for this strategy, which corresponds to the CLI flag used to invoke the security tests.
func (h *headerTestHelp) GetName() string {
	return "--tests"
}

// GetPreferredReporterType specifies the type of reporter required for this strategy.
func (h *headerTestHelp) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
