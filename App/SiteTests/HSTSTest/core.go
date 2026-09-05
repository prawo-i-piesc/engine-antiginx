// Package HSTSTest implements the HSTS Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package HSTSTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strconv"
	"strings"
)

// New creates a new ResponseTest that analyzes HTTP Strict Transport Security (HSTS) header
// configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Check for HSTS header
			hstsHeader := params.Response.Header.Get("Strict-Transport-Security")

			if hstsHeader == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Medium,
					Metadata:    nil,
					Description: "Missing HSTS header - site vulnerable to protocol downgrade attacks and man-in-the-middle attacks",
				}
			}

			// Parse HSTS header for security analysis
			metadata := analyzeHSTSHeader(hstsHeader)

			// Determine threat level based on HSTS configuration
			threatLevel := evaluateHSTSThreatLevel(metadata)

			// Generate description based on findings
			description := generateHSTSDescription(metadata)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   95,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// analyzeHSTSHeader parses the Strict-Transport-Security header value and extracts
// configuration directives into a structured metadata map.
func analyzeHSTSHeader(hstsHeader string) map[string]interface{} {
	metadata := map[string]interface{}{
		"include_subdomains": false,
		"preload":            false,
		"max_age":            0,
		"directives":         []string{},
	}

	// Convert to lowercase for case-insensitive parsing
	headerLower := strings.ToLower(hstsHeader)

	// Check for includeSubDomains directive
	if strings.Contains(headerLower, "includesubdomains") {
		metadata["include_subdomains"] = true
		metadata["directives"] = append(metadata["directives"].([]string), "includeSubDomains")
	}

	// Check for preload directive
	if strings.Contains(headerLower, "preload") {
		metadata["preload"] = true
		metadata["directives"] = append(metadata["directives"].([]string), "preload")
	}

	// Extract max-age value
	if maxAge := extractMaxAge(hstsHeader); maxAge > 0 {
		metadata["max_age"] = maxAge
	}

	return metadata
}

// extractMaxAge extracts and parses the max-age directive value from the HSTS header.
func extractMaxAge(hstsHeader string) int {
	for _, part := range SiteTests.SplitHeaderList(hstsHeader, ";") {
		partLower := strings.ToLower(part)
		if strings.HasPrefix(partLower, "max-age=") {
			maxAgeStr := strings.TrimPrefix(partLower, "max-age=")
			if maxAge, err := strconv.Atoi(maxAgeStr); err == nil {
				return maxAge
			}
		}
	}
	return 0
}

// evaluateHSTSThreatLevel determines the security threat level based on HSTS configuration
// quality.
func evaluateHSTSThreatLevel(metadata map[string]interface{}) SiteTests.ThreatLevel {
	maxAge := metadata["max_age"].(int)
	includeSubdomains := metadata["include_subdomains"].(bool)
	preload := metadata["preload"].(bool)

	oneYear := 60 * 60 * 24 * 365
	sixMonths := 60 * 60 * 24 * 30 * 6

	// Excellent configuration
	if maxAge >= oneYear && includeSubdomains && preload {
		return SiteTests.None
	}

	// Good configuration
	if maxAge >= oneYear && includeSubdomains {
		return SiteTests.Info
	}

	// Acceptable configuration
	if maxAge >= sixMonths {
		return SiteTests.Low
	}

	// Weak configuration
	if maxAge > 0 {
		return SiteTests.Medium
	}

	// Invalid or missing max-age
	return SiteTests.High
}

// generateHSTSDescription creates a human-readable description of the HSTS configuration
// analysis including the configuration details and security assessment.
func generateHSTSDescription(metadata map[string]interface{}) string {
	maxAge := metadata["max_age"].(int)
	includeSubdomains := metadata["include_subdomains"].(bool)
	preload := metadata["preload"].(bool)
	directives := metadata["directives"].([]string)

	if maxAge == 0 {
		return "HSTS header present but missing or invalid max-age directive"
	}

	ageDescription := SiteTests.FormatDuration(maxAge) + " max-age"

	description := "HSTS header configured with " + ageDescription

	if len(directives) > 0 {
		description += " and includes: " + strings.Join(directives, ", ")
	}

	oneYear := 60 * 60 * 24 * 365
	sixMonths := 60 * 60 * 24 * 30 * 6

	if includeSubdomains && preload && maxAge >= oneYear {
		description += " - Excellent security configuration"
	} else if includeSubdomains && maxAge >= oneYear {
		description += " - Good security configuration"
	} else if maxAge >= sixMonths {
		description += " - Acceptable security configuration"
	} else {
		description += " - Weak security configuration, consider increasing max-age"
	}

	return description
}
