package strategyImpl

import (
	"Engine-AntiGinx/App/execution/strategy"
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
		SectionData: `https, hsts, serv-h-a, csp, cookie-sec, js-obf, xframe, permission-policy, 
x-content-type-options, referrer-policy, cross-origin-x`,
	},
}

type headerTestHelp struct{}

// NewHeaderTestHelp initializes and returns a new instance of the headerTestHelp strategy.
// This strategy provides documentation specifically for the "--tests" command argument.
//
// Returns:
//   - *headerTestHelp: A pointer to the newly created strategy instance
func NewHeaderTestHelp() *headerTestHelp {
	return &headerTestHelp{}
}

// Execute performs the logic for the header test help strategy.
//
// Instead of running security scans, this method assembles the help documentation
// regarding the header analysis capabilities (e.g., risk grading, CVE checks) and
// the list of valid test options (like CSP, HSTS). It wraps this information in a
// HelpStrategyResult and sends it to the reporting channel asynchronously.
//
// Implements:
//   - strategy.TestStrategy.Execute
//
// Parameters:
//   - ctx: The execution context (unused here)
//   - channel: The channel to transmit the help result
//   - wg: WaitGroup used to signal completion
//   - antiBotFlag: Global evasion flag (unused here)
func (h *headerTestHelp) Execute(ctx strategy.TestContext, channel chan strategy.ResultWrapper, wg *sync.WaitGroup, antiBotFlag bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		helpMess := strategy.HelpStrategyResult{}
		helpMess.AppendSection(description)
		helpMess.HelpHeader(header)
		res := strategy.WrapStrategyResult(nil, &helpMess)
		channel <- res
	}()
}

// GetName returns the unique identifier for this strategy, which corresponds to
// the CLI flag used to invoke the security tests.
//
// Implements:
//   - strategy.TestStrategy.GetName
//
// Returns:
//   - string: Returns "--tests"
func (h *headerTestHelp) GetName() string {
	return "--tests"
}

// GetPreferredReporterType specifies the type of reporter required for this strategy.
//
// Since this is a help strategy, it mandates the use of HelpReporter to format
// the output as user documentation.
//
// Implements:
//   - strategy.TestStrategy.GetPreferredReporterType
//
// Returns:
//   - strategy.ReporterType: Always returns strategy.HelpReporter
func (h *headerTestHelp) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
