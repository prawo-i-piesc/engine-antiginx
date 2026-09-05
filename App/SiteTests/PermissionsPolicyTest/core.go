// Package PermissionsPolicyTest implements the Permissions-Policy Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package PermissionsPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strconv"
	"strings"
)

// New creates a new ResponseTest that analyzes Permissions-Policy header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Check for Permissions-Policy header
			permissionsPolicyHeader := params.Response.Header.Get("Permissions-Policy")

			if permissionsPolicyHeader == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.High,
					Metadata:    nil,
					Description: "Missing Permissions-Policy header - all browser features available to page and embedded content without restrictions",
				}
			}

			// Parse Permissions-Policy header for security analysis
			metadata := analyzePermissionsPolicyHeader(permissionsPolicyHeader)

			// Determine threat level based on configuration
			threatLevel := evaluatePermissionsPolicyThreatLevel(metadata)

			// Generate description based on findings
			description := generatePermissionsPolicyDescription(metadata)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   90,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
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

// analyzePermissionsPolicyHeader parses the Permissions-Policy header value and extracts
// feature directives into a structured metadata map.

func analyzePermissionsPolicyHeader(permissionsPolicyHeader string) map[string]interface{} {

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
	return map[string]interface{}{
		"allowed_features":    allowedFeatures,
		"restricted_features": restrictedFeatures,
		"wildcard_features":   wildcardFeatures,
		"dangerous_allowed":   dangerousAllowed,
		"suspicious_allowed":  suspiciousAllowed,
		"total_directives":    len(directives),
		"raw_header":          permissionsPolicyHeader,
	}
}

// evaluatePermissionsPolicyThreatLevel determines the security threat level based on
// Permissions-Policy configuration.
func evaluatePermissionsPolicyThreatLevel(metadata map[string]interface{}) SiteTests.ThreatLevel {
	dangerousAllowed, _ := metadata["dangerous_allowed"].([]string)
	suspiciousAllowed, _ := metadata["suspicious_allowed"].([]string)
	wildcardFeatures, _ := metadata["wildcard_features"].([]string)
	totalDirectives, _ := metadata["total_directives"].(int)

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
func generatePermissionsPolicyDescription(metadata map[string]interface{}) string {
	dangerousAllowed, _ := metadata["dangerous_allowed"].([]string)
	suspiciousAllowed, _ := metadata["suspicious_allowed"].([]string)
	wildcardFeatures, _ := metadata["wildcard_features"].([]string)
	restrictedFeatures, _ := metadata["restricted_features"].([]string)
	totalDirectives, _ := metadata["total_directives"].(int)

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
