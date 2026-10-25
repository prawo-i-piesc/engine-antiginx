// Package PermissionsPolicyTest implements the Permissions-Policy Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package PermissionsPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strconv"
	"strings"
)

// check wires this test's analysis stages into the shared single-header test shape.
var check = SiteTests.HeaderTest[PermissionsPolicyAnalysis]{
	Name:               TestName,
	Header:             "Permissions-Policy",
	MissingLevel:       SiteTests.High,
	MissingDescription: missingDescription,
	Certainty:          Certainty,
	Analyze:            analyzePermissionsPolicyHeader,
	Evaluate:           evaluatePermissionsPolicyThreatLevel,
	Describe:           generatePermissionsPolicyDescription,
}

// New creates a new ResponseTest that analyzes Permissions-Policy header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest:     check.Run,
	}
}

// isAllowlistRestricted determines if an allowlist value represents a restricted/safe
// configuration.
func isAllowlistRestricted(allowlist string) bool {
	// Strip parentheses if present and get inner value
	innerValue := allowlist
	if len(innerValue) >= 2 && strings.HasPrefix(innerValue, "(") && strings.HasSuffix(innerValue, ")") {
		innerValue = innerValue[1 : len(innerValue)-1]
	}
	innerValue = strings.TrimSpace(innerValue)

	// Empty inner value means restricted (handles "", "()", "( )", etc.)
	if innerValue == "" {
		return true
	}

	// Only "self" (without additional origins) is considered restricted/safe
	// This handles both (self) and self formats
	// Case-insensitive comparison per web standards
	// Per the Permissions-Policy specification, quoted "self" (i.e. `"self"`) is treated as
	// an origin string, not as the self keyword, so ensure the value is not quoted.
	isQuotedString := len(innerValue) >= 2 && strings.HasPrefix(innerValue, "\"") && strings.HasSuffix(innerValue, "\"")
	if !isQuotedString && strings.EqualFold(innerValue, "self") {
		return true
	}

	// Anything else (wildcards, origins, self + origins) is not restricted
	return false
}

// PermissionsPolicyAnalysis is what the Permissions-Policy header declares, reported as the
// result's metadata.
// Fields are in the alphabetical order of their JSON names, the order the metadata map this
// replaced was serialized in, so reports keep the same shape.
type PermissionsPolicyAnalysis struct {
	AllowedFeatures    []string `json:"allowed_features"`    // Other features opened beyond the page itself
	DangerousAllowed   []string `json:"dangerous_allowed"`   // Dangerous features left unrestricted
	RawHeader          string   `json:"raw_header"`          // The value as sent
	RestrictedFeatures []string `json:"restricted_features"` // Dangerous or suspicious features limited to none or self
	SuspiciousAllowed  []string `json:"suspicious_allowed"`  // Suspicious features left unrestricted
	TotalDirectives    int      `json:"total_directives"`    // Comma-separated entries in the header, malformed ones included
	WildcardFeatures   []string `json:"wildcard_features"`   // Features whose allowlist contains *
}

// analyzePermissionsPolicyHeader parses the Permissions-Policy header value and extracts
// feature directives into an analysis.
func analyzePermissionsPolicyHeader(permissionsPolicyHeader string) PermissionsPolicyAnalysis {

	// Split by comma and analyze each directive
	directives := strings.Split(permissionsPolicyHeader, ",")
	var allowedFeatures []string
	var restrictedFeatures []string
	var wildcardFeatures []string
	var dangerousAllowed []string
	var suspiciousAllowed []string

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		// Parse feature=allowlist format
		parts := strings.Split(directive, "=")
		if len(parts) != 2 {
			continue
		}

		feature := strings.TrimSpace(parts[0])
		allowlist := strings.TrimSpace(parts[1])

		// Check if feature uses wildcards
		if strings.Contains(allowlist, "*") {
			wildcardFeatures = append(wildcardFeatures, feature)
		}

		// Track if feature has been categorized as dangerous or suspicious
		categorized := false

		// Check if dangerous feature is allowed
		for _, dangerous := range dangerousFeatures {
			if feature == dangerous {
				if isAllowlistRestricted(allowlist) {
					restrictedFeatures = append(restrictedFeatures, feature)
				} else {
					dangerousAllowed = append(dangerousAllowed, feature)
				}
				categorized = true
				break
			}
		}

		// Check if suspicious feature is allowed
		for _, suspicious := range suspiciousFeatures {
			if feature == suspicious {
				if isAllowlistRestricted(allowlist) {
					restrictedFeatures = append(restrictedFeatures, feature)
				} else {
					suspiciousAllowed = append(suspiciousAllowed, feature)
				}
				categorized = true
				break
			}
		}

		if !isAllowlistRestricted(allowlist) {
			// Only add to allowedFeatures if not already categorized
			if !categorized && allowlist != "()" && allowlist != "" {
				allowedFeatures = append(allowedFeatures, feature)
			}
		}
	}
	return PermissionsPolicyAnalysis{
		AllowedFeatures:    allowedFeatures,
		DangerousAllowed:   dangerousAllowed,
		RawHeader:          permissionsPolicyHeader,
		RestrictedFeatures: restrictedFeatures,
		SuspiciousAllowed:  suspiciousAllowed,
		TotalDirectives:    len(directives),
		WildcardFeatures:   wildcardFeatures,
	}
}

// evaluatePermissionsPolicyThreatLevel determines the security threat level based on
// Permissions-Policy configuration.
func evaluatePermissionsPolicyThreatLevel(metadata PermissionsPolicyAnalysis) SiteTests.ThreatLevel {
	dangerousAllowed := metadata.DangerousAllowed
	suspiciousAllowed := metadata.SuspiciousAllowed
	wildcardFeatures := metadata.WildcardFeatures
	totalDirectives := metadata.TotalDirectives

	// High threat if many dangerous features are unrestricted
	if len(dangerousAllowed) >= 3 {
		return SiteTests.High
	}

	// Medium threat if some dangerous features allowed or wildcards used
	if len(dangerousAllowed) > 0 || len(wildcardFeatures) > 0 {
		return SiteTests.Medium
	}

	// Low threat if many suspicious features allowed or minimal policy
	if len(suspiciousAllowed) >= 2 || totalDirectives < 3 {
		return SiteTests.Low
	}

	// Info if some suspicious features allowed
	if len(suspiciousAllowed) > 0 {
		return SiteTests.Info
	}

	// Good configuration with comprehensive restrictions
	if totalDirectives >= 5 {
		return SiteTests.None
	}

	return SiteTests.Info
}

// generatePermissionsPolicyDescription creates a human-readable description of the
// Permissions-Policy analysis results.
func generatePermissionsPolicyDescription(metadata PermissionsPolicyAnalysis) string {
	dangerousAllowed := metadata.DangerousAllowed
	suspiciousAllowed := metadata.SuspiciousAllowed
	wildcardFeatures := metadata.WildcardFeatures
	restrictedFeatures := metadata.RestrictedFeatures
	totalDirectives := metadata.TotalDirectives

	var description strings.Builder

	description.WriteString("Permissions-Policy header configured with ")
	description.WriteString(strconv.Itoa(totalDirectives))
	description.WriteString(" directives")

	if len(restrictedFeatures) > 0 {
		description.WriteString(". Properly restricts features: ")
		description.WriteString(strings.Join(restrictedFeatures, ", "))
	}

	if len(dangerousAllowed) > 0 {
		description.WriteString(". WARNING: Allows dangerous features: ")
		description.WriteString(strings.Join(dangerousAllowed, ", "))
	}

	if len(suspiciousAllowed) > 0 {
		description.WriteString(". Allows suspicious features: ")
		description.WriteString(strings.Join(suspiciousAllowed, ", "))
	}

	if len(wildcardFeatures) > 0 {
		description.WriteString(". WARNING: Uses wildcards for features: ")
		description.WriteString(strings.Join(wildcardFeatures, ", "))
	}

	if len(dangerousAllowed) == 0 && len(wildcardFeatures) == 0 && len(restrictedFeatures) > 0 {
		if len(suspiciousAllowed) == 0 {
			description.WriteString(". Excellent security configuration")
		} else {
			description.WriteString(". Good security configuration")
		}
	}

	return description.String()
}
