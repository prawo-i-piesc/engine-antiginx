// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the X-Content-Type-Options test that checks for proper MIME type
// sniffing protection to prevent content-type confusion attacks.
package Tests

import (
	"strings"
)

// NewXContentTypeOptionsTest creates a new ResponseTest that analyzes X-Content-Type-Options header
// configuration. The X-Content-Type-Options header prevents browsers from MIME-sniffing a response
// away from the declared content-type, which helps prevent XSS attacks and other security issues.
//
// The test evaluates:
//   - Presence of X-Content-Type-Options header
//   - Correct "nosniff" directive value
//   - Case sensitivity and formatting
//
// Threat level assessment:
//   - None (0): Excellent - X-Content-Type-Options: nosniff properly configured
//   - High (4): Missing - No header found, vulnerable to MIME sniffing attacks
//   - Medium (3): Invalid - Header present but with incorrect value
//
// Security implications:
//   - Missing header: Browsers may MIME-sniff content leading to XSS vulnerabilities
//   - Invalid value: Header ignored by browsers, same risk as missing
//   - Correct "nosniff": Prevents MIME type sniffing attacks
//
// Returns:
//   - *ResponseTest: Configured X-Content-Type-Options test ready for execution
func NewXContentTypeOptionsTest() *ResponseTest {
	return &ResponseTest{
		Id:          "x-content-type-options",
		Name:        "X-Content-Type-Options Header Analysis",
		Description: "Checks for X-Content-Type-Options header to prevent MIME type sniffing attacks",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for X-Content-Type-Options header
			xContentTypeHeader := params.Response.Header.Get("X-Content-Type-Options")

			if xContentTypeHeader == "" {
				return TestResult{
					Name:        "X-Content-Type-Options Header Analysis",
					Certainty:   100,
					ThreatLevel: High,
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

			return TestResult{
				Name:        "X-Content-Type-Options Header Analysis",
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
	headerValue := strings.TrimSpace(strings.ToLower(xContentTypeHeader))
	
	return map[string]interface{}{
		"raw_header":    xContentTypeHeader,
		"parsed_value":  headerValue,
		"is_nosniff":    headerValue == "nosniff",
	}
}

// evaluateXContentTypeOptionsThreatLevel determines the security threat level
func evaluateXContentTypeOptionsThreatLevel(metadata map[string]interface{}) ThreatLevel {
	isNosniff, _ := metadata["is_nosniff"].(bool)

	if isNosniff {
		return None // Perfect configuration
	}

	return Medium // Invalid value
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