package strategy

import "Engine-AntiGinx/App/Tests"

// ResultWrapper encapsulates the outcome of a strategy execution.
//
// It serves as a unified transport object sent through the results channel, allowing
// the system to handle both standard security test results (e.g., vulnerabilities found)
// and help/usage information (e.g., manual pages) using a single data structure.
type ResultWrapper struct {
	testResult  *Tests.TestResult
	helpMessage *HelpStrategyResult
}

// HelpStrategyResult represents the structured content of a help command output.
// It is designed to be parsed by a HelpReporter to generate readable CLI documentation.
type HelpStrategyResult struct {
	helpHeader string
	sectionArr []HelpSection
}

// HelpSection defines a specific block of information within a help page.
// Examples include "USAGE", "OPTIONS", or "DESCRIPTION".
type HelpSection struct {
	SectionName string
	SectionData string
}

// WrapStrategyResult constructs a new ResultWrapper containing either a test result,
// a help message.
//
// This factory function is used by strategies to package their output before sending
// it to the reporting layer.
//
// Parameters:
//   - testResult: A pointer to the security test results (can be nil if this is a help operation)
//   - helpMessage: A pointer to the help data (can be nil if this is a standard test)
//
// Returns:
//   - ResultWrapper: The initialized wrapper struct
func WrapStrategyResult(testResult *Tests.TestResult, helpMessage *HelpStrategyResult) ResultWrapper {
	return ResultWrapper{
		testResult:  testResult,
		helpMessage: helpMessage,
	}
}

// GetTestResult retrieves the underlying security test result from the wrapper.
//
// It provides a safe way to check for the existence of test data.
//
// Returns:
//   - bool: True if a test result exists (is not nil), false otherwise
//   - *Tests.TestResult: The pointer to the test result (or nil)
func (w ResultWrapper) GetTestResult() (bool, *Tests.TestResult) {
	return w.testResult != nil, w.testResult
}

// GetHelpMessage retrieves the underlying help strategy result from the wrapper.
//
// It provides a safe way to check if the result contains help documentation.
//
// Returns:
//   - bool: True if a help message exists (is not nil), false otherwise
//   - *HelpStrategyResult: The pointer to the help message (or nil)
func (w ResultWrapper) GetHelpMessage() (bool, *HelpStrategyResult) {
	return w.helpMessage != nil, w.helpMessage
}

// GetSectionArray returns the list of all help sections currently stored.
//
// Returns:
//   - []HelpSection: The slice of help sections
func (h *HelpStrategyResult) GetSectionArray() []HelpSection {
	return h.sectionArr
}

// AppendSection adds one or more new sections to the help message.
//
// Parameters:
//   - section: A slice of HelpSection objects to append to the existing list
func (h *HelpStrategyResult) AppendSection(section []HelpSection) {
	h.sectionArr = append(h.sectionArr, section...)
}

// HelpHeader sets the main title or header for the help message.
//
// Parameters:
//   - name: The string to be used as the header (e.g., "General Help")
func (h *HelpStrategyResult) HelpHeader(name string) {
	h.helpHeader = name
}

// GetHelpHeader retrieves the main title of the help message.
//
// Returns:
//   - string: The currently set header string
func (h *HelpStrategyResult) GetHelpHeader() string {
	return h.helpHeader
}
