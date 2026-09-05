// Package SiteTests is the security test framework: the result and threat types every
// test reports through, and the three kinds of test the scheduler knows how to run.
// See README.md for the directory layout and the conventions every test follows.
package SiteTests

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ThreatLevel represents the security threat classification for test results.
type ThreatLevel int

// ThreatLevel enumeration constants representing increasing levels of security concern.
const (
	None     ThreatLevel = iota // 0 - No security issues
	Info                        // 1 - Informational findings
	Low                         // 2 - Low severity issues
	Medium                      // 3 - Medium severity issues
	High                        // 4 - High severity vulnerabilities
	Critical                    // 5 - Critical vulnerabilities
)

// TestResult represents the comprehensive output of a security test execution.
type TestResult struct {
	Name        string      `json:"Name"`        // Test name for identification
	Certainty   int         `json:"Certainty"`   // Confidence percentage (0-100)
	ThreatLevel ThreatLevel `json:"ThreatLevel"` // Security threat classification
	Metadata    any         `json:"Metadata"`    // Test-specific detailed data
	Description string      `json:"Description"` // Human-readable findings explanation
}

// TestKind classifies a test by the input it actually needs, which determines the execution
// phase it is scheduled into.
type TestKind int

// TestKind enumeration constants ordered by the execution phase they belong to.
const (
	PreResponse TestKind = iota // 0 - Needs only the target URL
	Response                    // 1 - Needs the main HTTP response
	Structure                   // 2 - Needs the target, probes it independently
)

// String converts a TestKind value to its human-readable string representation, implementing
// the Stringer interface for logging and reporting.
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

// MarshalJSON implements custom JSON marshaling for TestKind, emitting the phase name instead
// of its numeric value so reports stay readable, mirroring ThreatLevel.
func (k TestKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// ScanContext carries everything the scheduler knows about the target being scanned.
type ScanContext struct {
	Target   *url.URL       // Target URL under analysis, never nil
	Response *http.Response // Main HTTP response, nil outside the Response phase
}

// Test is the common interface implemented by every security test regardless of its kind.
type Test interface {
	GetId() string          // Unique test identifier used for registration and selection
	GetName() string        // Human-readable test name
	GetDescription() string // Detailed explanation of what the test checks
	GetCategory() string    // Organizational category (e.g., "Headers", "Encryption")
	GetKind() TestKind      // Execution phase this test belongs to
	Run(ctx ScanContext) TestResult
}

// PreResponseTestParams encapsulates the parameters passed to a PreResponseTest.
type PreResponseTestParams struct {
	Target *url.URL // Target URL to analyze, never nil
}

// StructureTestParams encapsulates the parameters passed to a StructureTest.
type StructureTestParams struct {
	Target *url.URL // Target URL to analyze, never nil
}

// ResponseTestParams encapsulates the parameters passed to a ResponseTest for execution.
type ResponseTestParams struct {
	Response *http.Response // HTTP response to analyze for security issues
}

// ResponseTest defines a security test that analyzes an HTTP response for vulnerabilities,
// misconfigurations, or security issues.
type ResponseTest struct {
	Id          string                                     // Unique test identifier (e.g., "https", "hsts", "csp")
	Name        string                                     // Human-readable test name
	Description string                                     // Detailed test description
	Category    string                                     // Test category for organizational purposes (e.g., "Headers", "TLS", "CSP")
	RunTest     func(params ResponseTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
func (brt *ResponseTest) GetId() string { return brt.Id }

// GetName returns the human-readable name of the test for display purposes.
func (brt *ResponseTest) GetName() string { return brt.Name }

// GetDescription returns the detailed description of what the test analyzes.
func (brt *ResponseTest) GetDescription() string { return brt.Description }

// GetCategory returns the category of the test for organizational purposes.
func (brt *ResponseTest) GetCategory() string { return brt.Category }

// GetKind reports that this test belongs to the Response phase and therefore requires a
// successful main HTTP request before it can run.
func (brt *ResponseTest) GetKind() TestKind { return Response }

// Run executes the test logic against the HTTP response carried by the scan context and
// returns the security analysis results.
func (rt *ResponseTest) Run(ctx ScanContext) TestResult {
	if rt.RunTest == nil {
		panic("Run method not implemented")
	}
	return rt.RunTest(ResponseTestParams{Response: ctx.Response})
}

// PreResponseTest defines a security test that analyzes a target before, and independently of,
// the main HTTP request.
type PreResponseTest struct {
	Id          string                                        // Unique test identifier (e.g., "phishing-url", "bot-protection")
	Name        string                                        // Human-readable test name
	Description string                                        // Detailed test description
	Category    string                                        // Test category for organizational purposes
	RunTest     func(params PreResponseTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
func (prt *PreResponseTest) GetId() string { return prt.Id }

// GetName returns the human-readable name of the test for display purposes.
func (prt *PreResponseTest) GetName() string { return prt.Name }

// GetDescription returns the detailed description of what the test analyzes.
func (prt *PreResponseTest) GetDescription() string { return prt.Description }

// GetCategory returns the category of the test for organizational purposes.
func (prt *PreResponseTest) GetCategory() string { return prt.Category }

// GetKind reports that this test belongs to the PreResponse phase and can run without the main
// HTTP request having succeeded.
func (prt *PreResponseTest) GetKind() TestKind { return PreResponse }

// Run executes the test logic against the target carried by the scan context.
func (prt *PreResponseTest) Run(ctx ScanContext) TestResult {
	if prt.RunTest == nil {
		panic("Run method not implemented")
	}
	return prt.RunTest(PreResponseTestParams{Target: ctx.Target})
}

// StructureTest defines a security test that analyzes how a target is configured rather than
// what it returned for a single request.
type StructureTest struct {
	Id          string                                      // Unique test identifier (e.g., "ssl-cert", "sitemap")
	Name        string                                      // Human-readable test name
	Description string                                      // Detailed test description
	Category    string                                      // Test category for organizational purposes
	RunTest     func(params StructureTestParams) TestResult // Test execution function
}

// GetId returns the unique identifier of the test used for registration and lookup.
func (st *StructureTest) GetId() string { return st.Id }

// GetName returns the human-readable name of the test for display purposes.
func (st *StructureTest) GetName() string { return st.Name }

// GetDescription returns the detailed description of what the test analyzes.
func (st *StructureTest) GetDescription() string { return st.Description }

// GetCategory returns the category of the test for organizational purposes.
func (st *StructureTest) GetCategory() string { return st.Category }

// GetKind reports that this test belongs to the Structure phase and can run without the main
// HTTP request having succeeded.
func (st *StructureTest) GetKind() TestKind { return Structure }

// Run executes the test logic against the target carried by the scan context.
func (st *StructureTest) Run(ctx ScanContext) TestResult {
	if st.RunTest == nil {
		panic("Run method not implemented")
	}
	return st.RunTest(StructureTestParams{Target: ctx.Target})
}

// String converts a ThreatLevel value to its human-readable string representation.
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

// MarshalJSON implements custom JSON marshaling for ThreatLevel, converting the enumeration
// value to its string representation in JSON output.
func (t ThreatLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}
