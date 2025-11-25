// Package Tests provides the core testing framework for security analysis of HTTP responses.
// This file defines fundamental types including ThreatLevel enumeration, TestResult structure,
// and the ResponseTest interface that all security tests must implement.
//
// The framework enables:
//   - Standardized security threat classification (None to Critical)
//   - Structured test results with metadata
//   - Extensible test implementations
//   - JSON serialization for reporting
package Tests

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
	"net/http"
)

// ThreatLevel represents the security threat classification for test results.
// It provides a standardized scale from None (no threat) to Critical (severe vulnerability)
// aligned with industry security standards and risk assessment frameworks.
//
// The enumeration enables:
//   - Consistent threat classification across all tests
//   - Priority-based vulnerability triage
//   - Risk-based decision making
//   - Compliance with security reporting standards
type ThreatLevel int

// ThreatLevel enumeration constants representing increasing levels of security concern.
// These levels align with CVSS severity ratings and common security frameworks.
//
// Level definitions:
//   - None (0): No security issues detected, configuration meets best practices
//   - Info (1): Informational findings, no immediate security impact
//   - Low (2): Minor security issues with low exploitability or impact
//   - Medium (3): Moderate security concerns requiring attention
//   - High (4): Serious vulnerabilities with significant security impact
//   - Critical (5): Severe vulnerabilities requiring immediate remediation
const (
	None     ThreatLevel = iota // 0 - No security issues
	Info                        // 1 - Informational findings
	Low                         // 2 - Low severity issues
	Medium                      // 3 - Medium severity issues
	High                        // 4 - High severity vulnerabilities
	Critical                    // 5 - Critical vulnerabilities
)

// TestResult represents the comprehensive output of a security test execution.
// It encapsulates all information about the test findings including classification,
// confidence level, detailed metadata, and human-readable descriptions.
//
// The structure is designed for:
//   - JSON serialization for API reporting
//   - Human-readable console output
//   - Automated processing and aggregation
//   - Detailed forensic analysis
//
// Fields provide multiple levels of detail:
//   - Name: Test identifier for categorization
//   - Certainty: Confidence percentage (0-100) in the finding
//   - ThreatLevel: Security classification (None to Critical)
//   - Metadata: Test-specific data (headers, configurations, CVEs, etc.)
//   - Description: Human-readable explanation of findings
type TestResult struct {
	Name        string      `json:"Name"`        // Test name for identification
	Certainty   int         `json:"Certainty"`   // Confidence percentage (0-100)
	ThreatLevel ThreatLevel `json:"ThreatLevel"` // Security threat classification
	Metadata    any         `json:"Metadata"`    // Test-specific detailed data
	Description string      `json:"Description"` // Human-readable findings explanation
}

// ResponseTestParams encapsulates the parameters passed to a ResponseTest for execution.
// It provides the HTTP response object that tests analyze to detect security issues,
// misconfigurations, and vulnerabilities.
//
// The structure enables:
//   - Clean test interface with extensibility
//   - Sharing of HTTP response across multiple tests
//   - Future addition of context or configuration parameters
//
// The Response object contains:
//   - HTTP headers (security headers, server information, etc.)
//   - Status code
//   - Request details (URL, method, original request)
//   - Body content (if read by test)
type ResponseTestParams struct {
	Response *http.Response // HTTP response to analyze for security issues
}

// ResponseTest defines a security test that analyzes an HTTP response for vulnerabilities,
// misconfigurations, or security issues. It provides the structure and execution interface
// for all security tests in the framework.
//
// The structure uses composition with a function field for flexible test implementation:
//   - Allows inline test definition without separate structs
//   - Enables closure-based tests with captured context
//   - Simplifies test registration and discovery
//   - Supports both simple and complex test logic
//
// Each test should:
//   - Analyze specific security aspects (HTTPS, HSTS, headers, etc.)
//   - Return structured TestResult with appropriate ThreatLevel
//   - Include detailed Metadata for findings
//   - Provide actionable Description for remediation
//
// Fields:
//   - Id: Unique identifier for test registration and selection (e.g., "https", "hsts")
//   - Name: Human-readable test name for display
//   - Description: Detailed explanation of what the test checks
//   - RunTest: Function that executes the test logic
type ResponseTest struct {
	Id          string                                     // Unique test identifier (e.g., "https", "hsts", "csp")
	Name        string                                     // Human-readable test name
	Description string                                     // Detailed test description
	RunTest     func(params ResponseTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
// This method provides read-only access to the test's ID.
//
// Returns:
//   - string: The test's unique identifier
func (brt *ResponseTest) GetId() string { return brt.Id }

// GetName returns the human-readable name of the test for display purposes.
// This method provides read-only access to the test's display name.
//
// Returns:
//   - string: The test's display name
func (brt *ResponseTest) GetName() string { return brt.Name }

// GetDescription returns the detailed description of what the test analyzes.
// This method provides read-only access to the test's purpose and functionality.
//
// Returns:
//   - string: The test's detailed description
func (brt *ResponseTest) GetDescription() string { return brt.Description }

// Run executes the test logic against the provided HTTP response parameters and returns
// the security analysis results. This is the main entry point for test execution.
//
// The method validates that RunTest is implemented before execution and panics if not,
// ensuring tests are properly configured before use.
//
// Parameters:
//   - params: ResponseTestParams containing the HTTP response to analyze
//
// Returns:
//   - TestResult: Structured results including threat level and findings
//
// Panics:
//   - string: "Run method not implemented" if RunTest function is nil
//
// Example:
//
//	test := NewHTTPSTest()
//	params := ResponseTestParams{Response: httpResponse}
//	result := test.Run(params)
//	fmt.Printf("Threat Level: %v\n", result.ThreatLevel)
func (rt *ResponseTest) Run(params ResponseTestParams) TestResult {
	if rt.RunTest == nil {
		panic("Run method not implemented")
	}
	return rt.RunTest(params)
}

// String converts a ThreatLevel value to its human-readable string representation.
// This method implements the Stringer interface enabling automatic string conversion
// for logging, display, and debugging purposes.
//
// String representations:
//   - None (0) → "None"
//   - Info (1) → "Info"
//   - Low (2) → "Low"
//   - Medium (3) → "Medium"
//   - High (4) → "High"
//   - Critical (5) → "Critical"
//
// Returns:
//   - string: Human-readable threat level name
//
// Panics:
//   - Errors.Error: If the ThreatLevel value is invalid/unknown
//
// Example:
//
//	level := High
//	fmt.Println(level.String())  // Output: "High"
//	fmt.Printf("Threat: %v\n", level)  // Output: "Threat: High"
func (t ThreatLevel) String() string {
	switch t {
	case None:
		return "None"
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	default:
		panic(Errors.Error{
			Message: fmt.Sprintf("Unknown Threat Level %d", t),
		})
	}
}

// MarshalJSON implements custom JSON marshaling for ThreatLevel, converting the
// enumeration value to its string representation in JSON output. This ensures
// human-readable JSON instead of numeric values.
//
// Without this method, ThreatLevel would serialize as integers (0, 1, 2, etc.).
// With this method, it serializes as strings ("None", "Info", "Low", etc.).
//
// This is particularly important for:
//   - API responses that need to be human-readable
//   - Log files and reports
//   - Integration with external systems expecting string values
//   - Debugging and analysis
//
// Returns:
//   - []byte: JSON-encoded string representation of the threat level
//   - error: Error from JSON marshaling (typically nil)
//
// Example:
//
//	result := TestResult{
//	    Name: "HTTPS Test",
//	    ThreatLevel: High,
//	}
//	jsonData, _ := json.Marshal(result)
//	// Output includes: "ThreatLevel": "High" (not "ThreatLevel": 4)
func (t ThreatLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
