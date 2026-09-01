// Package Tests provides the core testing framework for security analysis of web targets.
// This file defines fundamental types including ThreatLevel enumeration, TestResult structure,
// the TestKind classification and the Test interface that all security tests must implement.
//
// The framework enables:
//   - Standardized security threat classification (None to Critical)
//   - Structured test results with metadata
//   - Extensible test implementations across three execution phases
//   - JSON serialization for reporting
package Tests

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// TestKind classifies a test by the input it actually needs, which determines the
// execution phase it is scheduled into. Splitting tests this way keeps a failure in
// one phase from cancelling the others: a target hidden behind a bot protection layer
// still gets its URL and its infrastructure analysed even though no page body arrives.
//
// The classification answers a single question: what does this test read to do its job?
//   - Only the target URL, without contacting it       -> PreResponse
//   - The body and headers of the main HTTP response   -> Response
//   - The target's configuration, over its own probes  -> Structure
type TestKind int

// TestKind enumeration constants ordered by the execution phase they belong to.
//
// Phase definitions:
//   - PreResponse (0): Runs against the bare target URL, before and independently of the
//     main request. Covers URL analysis, DNS verification and bot protection fingerprinting.
//   - Response (1): Requires a successful main GET and analyses what came back — security
//     headers, cookies, page content. This is the only phase blocked by a failed request.
//   - Structure (2): Analyses how the target is configured rather than what it returned.
//     Opens its own connections (TLS handshake, sitemap.xml fetch, path probing).
const (
	PreResponse TestKind = iota // 0 - Needs only the target URL
	Response                    // 1 - Needs the main HTTP response
	Structure                   // 2 - Needs the target, probes it independently
)

// String converts a TestKind value to its human-readable string representation,
// implementing the Stringer interface for logging and reporting.
//
// Returns:
//   - string: Human-readable phase name
//
// Panics:
//   - Errors.Error: If the TestKind value is invalid/unknown
func (k TestKind) String() string {
	switch k {
	case PreResponse:
		return "PreResponse"
	case Response:
		return "Response"
	case Structure:
		return "Structure"
	default:
		panic(Errors.Error{
			Message: fmt.Sprintf("Unknown Test Kind %d", k),
		})
	}
}

// MarshalJSON implements custom JSON marshaling for TestKind, emitting the phase name
// instead of its numeric value so reports stay readable, mirroring ThreatLevel.
//
// Returns:
//   - []byte: JSON-encoded string representation of the test kind
//   - error: Error from JSON marshaling (typically nil)
func (k TestKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// ScanContext carries everything the scheduler knows about the target being scanned.
// It is the single value handed to every test regardless of its kind; each test type
// narrows it down to the typed parameters its implementation actually declares.
//
// This indirection keeps the scheduler working against one interface while test authors
// still write against a parameter struct that contains only what their phase provides.
//
// Fields:
//   - Target: The target URL, always populated
//   - Response: The main HTTP response, populated only during the Response phase
type ScanContext struct {
	Target   *url.URL       // Target URL under analysis, never nil
	Response *http.Response // Main HTTP response, nil outside the Response phase
}

// Test is the common interface implemented by every security test regardless of its kind.
// The Registry stores tests behind this interface and the scheduler executes them through
// it, so adding a new kind of test does not ripple through the execution layer.
//
// Implementations are provided by PreResponseTest, ResponseTest and StructureTest, each
// adapting the shared ScanContext to its own typed parameters.
type Test interface {
	GetId() string          // Unique test identifier used for registration and selection
	GetName() string        // Human-readable test name
	GetDescription() string // Detailed explanation of what the test checks
	GetCategory() string    // Organizational category (e.g., "Headers", "Encryption")
	GetKind() TestKind      // Execution phase this test belongs to
	Run(ctx ScanContext) TestResult
}

// PreResponseTestParams encapsulates the parameters passed to a PreResponseTest.
// The phase runs before and independently of the main HTTP request, so the target URL
// is all a test gets — anything else has to be obtained by the test itself.
//
// Kept separate from StructureTestParams despite being structurally identical today,
// because the two are expected to diverge: this one will grow a DNS resolver.
type PreResponseTestParams struct {
	Target *url.URL // Target URL to analyze, never nil
}

// StructureTestParams encapsulates the parameters passed to a StructureTest.
// Structure tests analyze how a target is configured rather than what it returned,
// so they receive the target and open whatever connections they need themselves.
//
// Kept separate from PreResponseTestParams despite being structurally identical today,
// because the two are expected to diverge: this one will grow a shared HTTP client
// carrying a probe budget.
type StructureTestParams struct {
	Target *url.URL // Target URL to analyze, never nil
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
	Category	string                                     // Test category for organizational purposes (e.g., "Headers", "TLS", "CSP")
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


// GetCategory returns the category of the test for organizational purposes.
// This method provides read-only access to the test's category.
//
// Returns:
//   - string: The test's category (e.g., "Headers", "TLS", "CSP")
func (brt *ResponseTest) GetCategory() string { return brt.Category }

// GetKind reports that this test belongs to the Response phase and therefore requires
// a successful main HTTP request before it can run.
//
// Returns:
//   - TestKind: Always Response
func (brt *ResponseTest) GetKind() TestKind { return Response }

// Run executes the test logic against the HTTP response carried by the scan context and
// returns the security analysis results. This is the main entry point for test execution.
//
// The method validates that RunTest is implemented before execution and panics if not,
// ensuring tests are properly configured before use.
//
// Parameters:
//   - ctx: ScanContext whose Response field holds the HTTP response to analyze
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
//	result := test.Run(ScanContext{Target: target, Response: httpResponse})
//	fmt.Printf("Threat Level: %v\n", result.ThreatLevel)
func (rt *ResponseTest) Run(ctx ScanContext) TestResult {
	if rt.RunTest == nil {
		panic("Run method not implemented")
	}
	return rt.RunTest(ResponseTestParams{Response: ctx.Response})
}

// PreResponseTest defines a security test that analyzes a target before, and independently
// of, the main HTTP request. It never needs the page body, so it still produces a verdict
// when the target is unreachable or hidden behind a challenge.
//
// Each test should:
//   - Derive its findings from the target URL alone, or from its own lightweight probes
//   - Return structured TestResult with appropriate ThreatLevel
//   - Include detailed Metadata for findings
//   - Provide actionable Description for remediation
//
// Fields:
//   - Id: Unique identifier for test registration and selection (e.g., "phishing-url")
//   - Name: Human-readable test name for display
//   - Description: Detailed explanation of what the test checks
//   - Category: Test category for organizational purposes
//   - RunTest: Function that executes the test logic
type PreResponseTest struct {
	Id          string                                        // Unique test identifier (e.g., "phishing-url", "bot-protection")
	Name        string                                        // Human-readable test name
	Description string                                        // Detailed test description
	Category    string                                        // Test category for organizational purposes
	RunTest     func(params PreResponseTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
//
// Returns:
//   - string: The test's unique identifier
func (prt *PreResponseTest) GetId() string { return prt.Id }

// GetName returns the human-readable name of the test for display purposes.
//
// Returns:
//   - string: The test's display name
func (prt *PreResponseTest) GetName() string { return prt.Name }

// GetDescription returns the detailed description of what the test analyzes.
//
// Returns:
//   - string: The test's detailed description
func (prt *PreResponseTest) GetDescription() string { return prt.Description }

// GetCategory returns the category of the test for organizational purposes.
//
// Returns:
//   - string: The test's category
func (prt *PreResponseTest) GetCategory() string { return prt.Category }

// GetKind reports that this test belongs to the PreResponse phase and can run without
// the main HTTP request having succeeded.
//
// Returns:
//   - TestKind: Always PreResponse
func (prt *PreResponseTest) GetKind() TestKind { return PreResponse }

// Run executes the test logic against the target carried by the scan context.
//
// Parameters:
//   - ctx: ScanContext whose Target field holds the URL to analyze
//
// Returns:
//   - TestResult: Structured results including threat level and findings
//
// Panics:
//   - string: "Run method not implemented" if RunTest function is nil
func (prt *PreResponseTest) Run(ctx ScanContext) TestResult {
	if prt.RunTest == nil {
		panic("Run method not implemented")
	}
	return prt.RunTest(PreResponseTestParams{Target: ctx.Target})
}

// StructureTest defines a security test that analyzes how a target is configured rather
// than what it returned for a single request. It opens its own connections — a TLS
// handshake, a sitemap.xml fetch, path probing — and therefore runs independently of the
// main HTTP request.
//
// Each test should:
//   - Derive its findings from the target's configuration, over its own probes
//   - Return structured TestResult with appropriate ThreatLevel
//   - Include detailed Metadata for findings
//   - Provide actionable Description for remediation
//
// Fields:
//   - Id: Unique identifier for test registration and selection (e.g., "ssl-cert")
//   - Name: Human-readable test name for display
//   - Description: Detailed explanation of what the test checks
//   - Category: Test category for organizational purposes
//   - RunTest: Function that executes the test logic
type StructureTest struct {
	Id          string                                      // Unique test identifier (e.g., "ssl-cert", "sitemap")
	Name        string                                      // Human-readable test name
	Description string                                      // Detailed test description
	Category    string                                      // Test category for organizational purposes
	RunTest     func(params StructureTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
//
// Returns:
//   - string: The test's unique identifier
func (st *StructureTest) GetId() string { return st.Id }

// GetName returns the human-readable name of the test for display purposes.
//
// Returns:
//   - string: The test's display name
func (st *StructureTest) GetName() string { return st.Name }

// GetDescription returns the detailed description of what the test analyzes.
//
// Returns:
//   - string: The test's detailed description
func (st *StructureTest) GetDescription() string { return st.Description }

// GetCategory returns the category of the test for organizational purposes.
//
// Returns:
//   - string: The test's category
func (st *StructureTest) GetCategory() string { return st.Category }

// GetKind reports that this test belongs to the Structure phase and can run without
// the main HTTP request having succeeded.
//
// Returns:
//   - TestKind: Always Structure
func (st *StructureTest) GetKind() TestKind { return Structure }

// Run executes the test logic against the target carried by the scan context.
//
// Parameters:
//   - ctx: ScanContext whose Target field holds the URL to analyze
//
// Returns:
//   - TestResult: Structured results including threat level and findings
//
// Panics:
//   - string: "Run method not implemented" if RunTest function is nil
func (st *StructureTest) Run(ctx ScanContext) TestResult {
	if st.RunTest == nil {
		panic("Run method not implemented")
	}
	return st.RunTest(StructureTestParams{Target: ctx.Target})
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
