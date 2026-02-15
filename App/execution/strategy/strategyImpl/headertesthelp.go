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

func NewHeaderTestHelp() *headerTestHelp {
	return &headerTestHelp{}
}
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

func (h *headerTestHelp) GetName() string {
	return "--tests"
}
func (h *headerTestHelp) GetPreferredReporterType() strategy.ReporterType {
	return strategy.HelpReporter
}
