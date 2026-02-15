package strategy

import "Engine-AntiGinx/App/Tests"

type ResultWrapper struct {
	testResult  *Tests.TestResult
	helpMessage *HelpStrategyResult
}

type HelpStrategyResult struct {
	helpHeader string
	sectionArr []HelpSection
}

type HelpSection struct {
	SectionName string
	SectionData string
}

func WrapStrategyResult(testResult *Tests.TestResult, helpMessage *HelpStrategyResult) ResultWrapper {
	return ResultWrapper{
		testResult:  testResult,
		helpMessage: helpMessage,
	}
}

func (w ResultWrapper) GetTestResult() (bool, *Tests.TestResult) {
	return w.testResult != nil, w.testResult
}
func (w ResultWrapper) GetHelpMessage() (bool, *HelpStrategyResult) {
	return w.helpMessage != nil, w.helpMessage
}
func (h *HelpStrategyResult) GetSectionArray() []HelpSection {
	return h.sectionArr
}
func (h *HelpStrategyResult) AppendSection(section []HelpSection) {
	h.sectionArr = append(h.sectionArr, section...)
}
func (h *HelpStrategyResult) HelpHeader(name string) {
	h.helpHeader = name
}
func (h *HelpStrategyResult) GetHelpHeader() string {
	return h.helpHeader
}
