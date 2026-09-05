// Package XContentTypeOptionsTest implements the X-Content-Type-Options Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package XContentTypeOptionsTest

import (
	"Engine-AntiGinx/App/SiteTests"
)

// New creates a new ResponseTest that analyzes X-Content-Type-Options header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Check for X-Content-Type-Options header
			xContentTypeHeader := params.Response.Header.Get("X-Content-Type-Options")

			if xContentTypeHeader == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.High,
					Metadata:    nil,
					Description: "Missing X-Content-Type-Options header - browsers may MIME-sniff content leading to potential XSS vulnerabilities",
				}
			}

			// Parse header for analysis
			metadata := analyzeXContentTypeOptionsHeader(xContentTypeHeader)

			// Determine threat level based on configuration
			threatLevel := evaluateXContentTypeOptionsThreatLevel(metadata)

			// Generate description based on findings
			description := generateXContentTypeOptionsDescription(metadata)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// analyzeXContentTypeOptionsHeader parses the X-Content-Type-Options header value
func analyzeXContentTypeOptionsHeader(xContentTypeHeader string) map[string]interface{} {
	headerValue := SiteTests.NormalizeHeaderValue(xContentTypeHeader)

	return map[string]interface{}{
		"raw_header":   xContentTypeHeader,
		"parsed_value": headerValue,
		"is_nosniff":   headerValue == "nosniff",
	}
}

// evaluateXContentTypeOptionsThreatLevel determines the security threat level
func evaluateXContentTypeOptionsThreatLevel(metadata map[string]interface{}) SiteTests.ThreatLevel {
	isNosniff, _ := metadata["is_nosniff"].(bool)

	if isNosniff {
		return SiteTests.None // Perfect configuration
	}

	return SiteTests.Medium // Invalid value
}

// generateXContentTypeOptionsDescription creates a human-readable description
func generateXContentTypeOptionsDescription(metadata map[string]interface{}) string {
	isNosniff, _ := metadata["is_nosniff"].(bool)
	rawHeader, _ := metadata["raw_header"].(string)

	if isNosniff {
		return "X-Content-Type-Options header properly configured with 'nosniff' - prevents MIME type sniffing attacks and content-type confusion vulnerabilities"
	}

	return "X-Content-Type-Options header configured with invalid value '" + rawHeader + "' - should be 'nosniff' to prevent MIME sniffing attacks"
}
