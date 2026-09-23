package strategy

import (
	"Engine-AntiGinx/App/SiteTests"
)

// RequestInfo describes the outcome of loading the target's content.
type RequestInfo struct {
	Message     string   `json:"Message"`
	Code        int      `json:"Code"`
	Protections []string `json:"Protections,omitempty"`
}

// ResultWrapper encapsulates the outcome of a strategy execution.
type ResultWrapper struct {
	testResult  *SiteTests.TestResult
	reqInfo     *RequestInfo
	helpMessage *HelpStrategyResult
}

// HelpStrategyResult represents the structured content of a help command output.
type HelpStrategyResult struct {
	helpHeader string
	sectionArr []HelpSection
}

// HelpSection defines a specific block of information within a help page.
type HelpSection struct {
	SectionName string
	SectionData string
}

// WrapStrategyResult constructs a new ResultWrapper containing either a test result, a help message.
func WrapStrategyResult(testResult *SiteTests.TestResult, helpMessage *HelpStrategyResult, info *RequestInfo) ResultWrapper {
	return ResultWrapper{
		testResult:  testResult,
		helpMessage: helpMessage,
		reqInfo:     info,
	}
}

// GetTestResult retrieves the underlying security test result from the wrapper.
func (w ResultWrapper) GetTestResult() (bool, *SiteTests.TestResult) {
	return w.testResult != nil, w.testResult
}

func (w ResultWrapper) GetReqInfo() (bool, *RequestInfo) {
	return w.reqInfo != nil, w.reqInfo
}

// GetHelpMessage retrieves the underlying help strategy result from the wrapper.
func (w ResultWrapper) GetHelpMessage() (bool, *HelpStrategyResult) {
	return w.helpMessage != nil, w.helpMessage
}

// GetSectionArray returns the list of all help sections currently stored.
func (h *HelpStrategyResult) GetSectionArray() []HelpSection {
	return h.sectionArr
}

// AppendSection adds one or more new sections to the help message.
func (h *HelpStrategyResult) AppendSection(section []HelpSection) {
	h.sectionArr = append(h.sectionArr, section...)
}

// HelpHeader sets the main title or header for the help message.
func (h *HelpStrategyResult) HelpHeader(name string) {
	h.helpHeader = name
}

// GetHelpHeader retrieves the main title of the help message.
func (h *HelpStrategyResult) GetHelpHeader() string {
	return h.helpHeader
}
