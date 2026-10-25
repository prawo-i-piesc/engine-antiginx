// Package XContentTypeOptionsTest implements the X-Content-Type-Options Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package XContentTypeOptionsTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strings"
)

// check wires this test's analysis stages into the shared single-header test shape.
var check = SiteTests.HeaderTest[XContentTypeOptionsAnalysis]{
	Name:               TestName,
	Header:             "X-Content-Type-Options",
	MissingLevel:       SiteTests.Low,
	MissingDescription: missingDescription,
	Certainty:          Certainty,
	Analyze:            analyzeXContentTypeOptionsHeader,
	Evaluate:           evaluateXContentTypeOptionsThreatLevel,
	Describe:           generateXContentTypeOptionsDescription,
}

// New creates a new ResponseTest that analyzes X-Content-Type-Options header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest:     check.Run,
	}
}

// XContentTypeOptionsAnalysis is what the X-Content-Type-Options header declares, reported as
// the result's metadata.
// Fields are in the alphabetical order of their JSON names, the order the metadata map this
// replaced was serialized in, so reports keep the same shape.
type XContentTypeOptionsAnalysis struct {
	IsNosniff   bool   `json:"is_nosniff"`   // Whether the value is exactly nosniff
	ParsedValue string `json:"parsed_value"` // The first value, trimmed and lowercased
	RawHeader   string `json:"raw_header"`   // The value as sent
}

// analyzeXContentTypeOptionsHeader parses the X-Content-Type-Options header value. Browsers
// split the header on commas and act on the first value only (Fetch, "determine nosniff"),
// so a value repeated by a proxy or a second header line still counts.
func analyzeXContentTypeOptionsHeader(xContentTypeHeader string) XContentTypeOptionsAnalysis {
	headerValue := SiteTests.NormalizeHeaderValue(strings.Split(xContentTypeHeader, ",")[0])

	return XContentTypeOptionsAnalysis{
		IsNosniff:   headerValue == "nosniff",
		ParsedValue: headerValue,
		RawHeader:   xContentTypeHeader,
	}
}

// evaluateXContentTypeOptionsThreatLevel determines the security threat level
func evaluateXContentTypeOptionsThreatLevel(metadata XContentTypeOptionsAnalysis) SiteTests.ThreatLevel {
	if metadata.IsNosniff {
		return SiteTests.None // Perfect configuration
	}

	return SiteTests.Low // Invalid value, ignored like a missing header
}

// generateXContentTypeOptionsDescription creates a human-readable description
func generateXContentTypeOptionsDescription(metadata XContentTypeOptionsAnalysis) string {
	if metadata.IsNosniff {
		return "X-Content-Type-Options header properly configured with 'nosniff' - prevents MIME type sniffing attacks and content-type confusion vulnerabilities"
	}

	return "X-Content-Type-Options header configured with invalid value '" + metadata.RawHeader + "' - should be 'nosniff' to prevent MIME sniffing attacks"
}
