// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the Permissions-Policy test that checks for proper browser feature
// access control configuration to prevent abuse of sensitive browser APIs.
package Tests

import (
	"strconv"
	"strings"
)

// NewPermissionsPolicyTest creates a new ResponseTest that analyzes Permissions-Policy header
// configuration. The Permissions-Policy header controls which browser features and APIs
// can be used by the page and its embedded content, replacing the deprecated Feature-Policy.
//
// The test evaluates:
//   - Presence of Permissions-Policy header
//   - Dangerous permissions that should be restricted
//   - Overly permissive wildcard (*) usage
//   - Common security-sensitive features
//
// Threat level assessment:
//   - None (0): Excellent - Comprehensive policy with restricted dangerous features
//   - Info (1): Good - Policy present with minor issues
//   - Low (2): Acceptable - Basic policy with some unrestricted features
//   - Medium (3): Weak - Policy present but allows dangerous features
//   - High (4): Missing - No policy header found
//
// Security implications:
//   - Missing header: All features available to page and embedded content
//   - Unrestricted dangerous features: Risk of abuse (camera, microphone, geolocation)
//   - Wildcard usage: Overly permissive access to sensitive APIs
//
// Returns:
//   - *ResponseTest: Configured Permissions-Policy test ready for execution
func NewPermissionsPolicyTest() *ResponseTest {
	return &ResponseTest{
		Id:          "permissions-policy",
		Name:        "Permissions-Policy Header Analysis",
		Description: "Checks for Permissions-Policy header presence and configuration to assess browser feature access control",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for Permissions-Policy header
			permissionsPolicyHeader := params.Response.Header.Get("Permissions-Policy")

			if permissionsPolicyHeader == "" {
				return TestResult{
					Name:        "Permissions-Policy Header Analysis",
					Certainty:   100,
					ThreatLevel: High,
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

			return TestResult{
				Name:        "Permissions-Policy Header Analysis",
				Certainty:   90,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// analyzePermissionsPolicyHeader parses the Permissions-Policy header value and extracts
// feature directives into a structured metadata map.
func analyzePermissionsPolicyHeader(permissionsPolicyHeader string) map[string]interface{} {
	dangerousFeatures := []string{
		"camera", "microphone", "geolocation", "payment", "usb", "bluetooth",
		"serial", "hid", "midi", "notifications", "persistent-storage", "clipboard-read",
	}

	suspiciousFeatures := []string{
		"fullscreen", "autoplay", "screen-wake-lock", "picture-in-picture",
	}

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
				if allowlist != "()" && allowlist != "" {
					dangerousAllowed = append(dangerousAllowed, feature)
				} else {
					restrictedFeatures = append(restrictedFeatures, feature)
				}
				categorized = true
				break
			}
		}

		// Check if suspicious feature is allowed
		for _, suspicious := range suspiciousFeatures {
			if feature == suspicious {
				if allowlist != "()" && allowlist != "" {
					suspiciousAllowed = append(suspiciousAllowed, feature)
				} else {
					restrictedFeatures = append(restrictedFeatures, feature)
				}
				categorized = true
				break
			}
		}

		// Only add to allowedFeatures if not already categorized
		if !categorized && allowlist != "()" && allowlist != "" {
			allowedFeatures = append(allowedFeatures, feature)
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
func evaluatePermissionsPolicyThreatLevel(metadata map[string]interface{}) ThreatLevel {
	dangerousAllowed, _ := metadata["dangerous_allowed"].([]string)
	suspiciousAllowed, _ := metadata["suspicious_allowed"].([]string)
	wildcardFeatures, _ := metadata["wildcard_features"].([]string)
	totalDirectives, _ := metadata["total_directives"].(int)

	// High threat if many dangerous features are unrestricted
	if len(dangerousAllowed) >= 3 {
		return High
	}

	// Medium threat if some dangerous features allowed or wildcards used
	if len(dangerousAllowed) > 0 || len(wildcardFeatures) > 0 {
		return Medium
	}

	// Low threat if many suspicious features allowed or minimal policy
	if len(suspiciousAllowed) >= 2 || totalDirectives < 3 {
		return Low
	}

	// Info if some suspicious features allowed
	if len(suspiciousAllowed) > 0 {
		return Info
	}

	// Good configuration with comprehensive restrictions
	if totalDirectives >= 5 {
		return None
	}

	return Info
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