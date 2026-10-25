// Package ReferrerPolicyTest implements the Referrer-Policy Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package ReferrerPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strings"
)

// New creates a new ResponseTest that analyzes Referrer-Policy header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Check for Referrer-Policy header
			referrerPolicyHeader := params.Response.Header.Get("Referrer-Policy")

			if referrerPolicyHeader == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Info,
					Metadata:    nil,
					Description: "Missing Referrer-Policy header - relying on the browser default policy (strict-origin-when-cross-origin in current browsers; older browsers fall back to no-referrer-when-downgrade, which sends the full URL to other sites)",
				}
			}

			// Parse Referrer-Policy header for security analysis
			metadata := analyzeReferrerPolicyHeader(referrerPolicyHeader)

			// Determine threat level based on Referrer-Policy configuration
			threatLevel := evaluateReferrerPolicyThreatLevel(metadata)

			// Generate description based on findings
			description := generateReferrerPolicyDescription(metadata)

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

// analyzeReferrerPolicyHeader parses the Referrer-Policy header value and extracts policy
// directives into a structured metadata map.
func analyzeReferrerPolicyHeader(referrerPolicyHeader string) map[string]interface{} {

	// Split by comma and clean up whitespace
	policyParts := strings.Split(referrerPolicyHeader, ",")
	var policies []string
	var invalidPolicies []string
	var effectivePolicy string
	hasUnsafe := false

	for _, part := range policyParts {
		policy := SiteTests.NormalizeHeaderValue(part)
		if policy == "" {
			continue
		}

		if validPolicies[policy] {
			policies = append(policies, policy)
			effectivePolicy = policy // Last valid policy takes precedence

			// Check for unsafe policies
			if policy == "unsafe-url" {
				hasUnsafe = true
			}
		} else {
			invalidPolicies = append(invalidPolicies, strings.TrimSpace(part)) // Keep original case for invalid policies
		}
	}

	return map[string]interface{}{
		"policies":         policies,
		"effective_policy": effectivePolicy,
		"policy_count":     len(policies),
		"has_unsafe":       hasUnsafe,
		"invalid_policies": invalidPolicies,
		"raw_header":       referrerPolicyHeader,
	}
}

// evaluateReferrerPolicyThreatLevel determines the security threat level based on Referrer-
// Policy configuration quality.
func evaluateReferrerPolicyThreatLevel(metadata map[string]interface{}) SiteTests.ThreatLevel {
	effectivePolicy, _ := metadata["effective_policy"].(string)
	hasUnsafe, _ := metadata["has_unsafe"].(bool)

	// Only unrecognised values: the browser ignores them and applies its default
	// (strict-origin-when-cross-origin in current browsers), exactly as for a missing header
	if effectivePolicy == "" {
		return SiteTests.Info
	}

	// Check for unsafe configurations
	if hasUnsafe && effectivePolicy == "unsafe-url" {
		return SiteTests.Low
	}

	// Excellent policies - recommended and secure
	switch effectivePolicy {
	case "no-referrer":
		return SiteTests.None // Maximum privacy
	case "strict-origin":
		return SiteTests.None // Strong privacy with origin info
	case "strict-origin-when-cross-origin":
		return SiteTests.None // W3C recommended balance
	case "same-origin":
		return SiteTests.None // Nothing at all sent to other origins
	}

	// Good policies - reasonable privacy protection
	switch effectivePolicy {
	case "origin":
		return SiteTests.Info // Basic privacy, only origin sent
	case "origin-when-cross-origin":
		return SiteTests.Info // Good balance for most use cases
	}

	// Weak policies or configurations
	if effectivePolicy == "no-referrer-when-downgrade" {
		return SiteTests.Low
	}

	// Note: Multiple Referrer-Policy directives are allowed for browser fallback and
	// do not, by themselves, imply higher risk. Threat level is based on the
	// evaluated effective policy and other concrete risk indicators above.

	// Fallback for unhandled cases
	return SiteTests.Low
}

// generateReferrerPolicyDescription creates a human-readable description of the Referrer-
// Policy analysis results, including findings, risks, and recommendations.
func generateReferrerPolicyDescription(metadata map[string]interface{}) string {
	effectivePolicy, _ := metadata["effective_policy"].(string)
	hasUnsafe, _ := metadata["has_unsafe"].(bool)
	policyCount, _ := metadata["policy_count"].(int)
	policies, _ := metadata["policies"].([]string)
	invalidPolicies, _ := metadata["invalid_policies"].([]string)

	var description strings.Builder

	// Handle invalid policies
	if len(invalidPolicies) > 0 {
		description.WriteString("Invalid Referrer-Policy values detected: ")
		description.WriteString(strings.Join(invalidPolicies, ", "))
		description.WriteString(". ")
	}

	// Handle no valid policies
	if effectivePolicy == "" {
		description.WriteString("No valid Referrer-Policy found. Browser will use its default policy (strict-origin-when-cross-origin in current browsers; older browsers fall back to no-referrer-when-downgrade, which sends the full URL to other sites).")
		return description.String()
	}

	// Describe the effective policy
	description.WriteString("Referrer-Policy configured with '")
	description.WriteString(effectivePolicy)
	description.WriteString("'")

	// Add multiple policies note if applicable
	if policyCount > 1 {
		description.WriteString(" (")
		description.WriteString(strings.Join(policies, ", "))
		description.WriteString(")")
	}

	description.WriteString(" - ")

	// Policy-specific descriptions and recommendations
	switch effectivePolicy {
	case "no-referrer":
		description.WriteString("excellent privacy protection. No referrer information is sent with any requests, providing maximum privacy but may break some website functionality that depends on referrer data.")

	case "strict-origin":
		description.WriteString("strong privacy protection. Only the origin is sent as referrer, and no referrer is sent when downgrading from HTTPS to HTTP, providing good security with minimal functionality impact.")

	case "strict-origin-when-cross-origin":
		description.WriteString("excellent privacy protection that balances security with functionality. This W3C recommended policy sends full URL for same-origin requests and only origin for cross-origin requests, with no referrer on protocol downgrades.")

	case "origin":
		description.WriteString("basic privacy protection. Only the origin (scheme, host, and port) is sent as referrer for all requests, which is reasonable but may still leak some information.")

	case "origin-when-cross-origin":
		description.WriteString("good balance between privacy and functionality. Full URL is sent for same-origin requests, but only origin for cross-origin requests, though still vulnerable to protocol downgrade attacks.")

	case "same-origin":
		description.WriteString("strong privacy protection. The full referrer URL is sent only with same-origin requests; requests to other origins carry no referrer at all, so nothing leaks to third parties.")

	case "no-referrer-when-downgrade":
		description.WriteString("weak privacy protection (the default of older browsers). Full referrer URL is sent except when downgrading from HTTPS to HTTP, which still allows significant information leakage in most scenarios.")

	case "unsafe-url":
		description.WriteString("unsafe configuration. The full referrer URL, including path and query string, is sent to every destination including insecure HTTP sites. This policy should be avoided.")

	default:
		description.WriteString("unrecognized policy configuration.")
	}

	// Add warnings for specific issues
	if hasUnsafe {
		description.WriteString(" WARNING: Contains 'unsafe-url' policy, which sends full URLs to every destination.")
	}

	if policyCount > 2 {
		description.WriteString(" Consider simplifying to a single clear policy for better maintainability.")
	}

	return description.String()
}
