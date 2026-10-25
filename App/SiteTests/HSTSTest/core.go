// Package HSTSTest implements the HSTS Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package HSTSTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strconv"
	"strings"
)

// check wires this test's analysis stages into the shared single-header test shape.
var check = SiteTests.HeaderTest[HSTSAnalysis]{
	Name:               TestName,
	Header:             "Strict-Transport-Security",
	MissingLevel:       SiteTests.Medium,
	MissingDescription: missingDescription,
	Certainty:          Certainty,
	Analyze:            analyzeHSTSHeader,
	Evaluate:           evaluateHSTSThreatLevel,
	Describe:           generateHSTSDescription,
}

// New creates a new ResponseTest that analyzes HTTP Strict Transport Security (HSTS) header
// configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest:     check.Run,
	}
}

// HSTSAnalysis is what the Strict-Transport-Security header declares, reported as the
// result's metadata.
// Fields are in the alphabetical order of their JSON names, the order the metadata map this
// replaced was serialized in, so reports keep the same shape.
type HSTSAnalysis struct {
	Directives        []string `json:"directives"`         // The optional directives present, in canonical spelling
	IncludeSubdomains bool     `json:"include_subdomains"` // Whether includeSubDomains is set
	MaxAge            int      `json:"max_age"`            // The max-age in seconds, 0 when missing or invalid
	Preload           bool     `json:"preload"`            // Whether preload is set
}

// analyzeHSTSHeader parses the Strict-Transport-Security header value and extracts
// configuration directives into an analysis.
func analyzeHSTSHeader(hstsHeader string) HSTSAnalysis {
	metadata := HSTSAnalysis{Directives: []string{}}

	// Convert to lowercase for case-insensitive parsing
	headerLower := strings.ToLower(hstsHeader)

	// Check for includeSubDomains directive
	if strings.Contains(headerLower, "includesubdomains") {
		metadata.IncludeSubdomains = true
		metadata.Directives = append(metadata.Directives, "includeSubDomains")
	}

	// Check for preload directive
	if strings.Contains(headerLower, "preload") {
		metadata.Preload = true
		metadata.Directives = append(metadata.Directives, "preload")
	}

	// Extract max-age value
	if maxAge := extractMaxAge(hstsHeader); maxAge > 0 {
		metadata.MaxAge = maxAge
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
func evaluateHSTSThreatLevel(metadata HSTSAnalysis) SiteTests.ThreatLevel {
	maxAge := metadata.MaxAge
	includeSubdomains := metadata.IncludeSubdomains
	preload := metadata.Preload

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
func generateHSTSDescription(metadata HSTSAnalysis) string {
	maxAge := metadata.MaxAge
	includeSubdomains := metadata.IncludeSubdomains
	preload := metadata.Preload
	directives := metadata.Directives

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
