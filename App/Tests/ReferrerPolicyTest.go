// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the Referrer-Policy test that checks for proper referrer information
// control configuration to prevent information leakage and protect user privacy.
package Tests

import (
	"strings"
)

// NewReferrerPolicyTest creates a new ResponseTest that analyzes Referrer-Policy header
// configuration. The Referrer-Policy header controls how much referrer information
// (sent via the Referer header) should be included with requests made from your site.
// Proper configuration prevents information leakage and protects user privacy.
//
// The test evaluates:
//   - Presence of Referrer-Policy header
//   - Policy directive values and their security implications
//   - Multiple policy values and their precedence
//   - Deprecated or insecure policy configurations
//
// Threat level assessment:
//   - None (0): Excellent - strict-origin-when-cross-origin, strict-origin, or no-referrer
//   - Info (1): Good - origin-when-cross-origin or origin
//   - Low (2): Acceptable - same-origin
//   - Medium (3): Weak - no-referrer-when-downgrade (default behavior)
//   - High (4): Vulnerable - unsafe-url or missing header with default behavior
//
// Security implications:
//   - Missing header: Uses browser default (typically no-referrer-when-downgrade)
//   - unsafe-url: Full URL sent as referrer to all origins (including HTTP)
//   - origin/origin-when-cross-origin: May leak origin information unnecessarily
//   - no-referrer: Maximum privacy but may break some functionality
//   - strict-origin-when-cross-origin: Recommended balance of security and functionality
//
// Policy values and security levels:
//   - no-referrer: Excellent - No referrer information sent
//   - no-referrer-when-downgrade: Medium - Default, leaks info on HTTPS→HTTP
//   - origin: Info - Only origin sent, reasonable privacy
//   - origin-when-cross-origin: Info - Full URL for same-origin, origin for cross-origin
//   - same-origin: Low - Full URL for same-origin only
//   - strict-origin: Excellent - Origin only, no referrer on downgrade
//   - strict-origin-when-cross-origin: Excellent - Recommended by W3C
//   - unsafe-url: High - Always sends full URL (insecure)
//
// Returns:
//   - *ResponseTest: Configured Referrer-Policy test ready for execution
//
// Example usage:
//
//	referrerTest := NewReferrerPolicyTest()
//	result := referrerTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed policy analysis
func NewReferrerPolicyTest() *ResponseTest {
	return &ResponseTest{
		Id:          "referrer-policy",
		Name:        "Referrer-Policy Header Analysis",
		Description: "Checks for Referrer-Policy header presence and configuration to assess referrer information control and privacy protection",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for Referrer-Policy header
			referrerPolicyHeader := params.Response.Header.Get("Referrer-Policy")

			if referrerPolicyHeader == "" {
				return TestResult{
					Name:        "Referrer-Policy Header Analysis",
					Certainty:   100,
					ThreatLevel: Medium,
					Metadata:    nil,
					Description: "Missing Referrer-Policy header - using browser default policy (typically no-referrer-when-downgrade) which may leak referrer information on HTTPS to HTTP transitions",
				}
			}

			// Parse Referrer-Policy header for security analysis
			metadata := analyzeReferrerPolicyHeader(referrerPolicyHeader)

			// Determine threat level based on Referrer-Policy configuration
			threatLevel := evaluateReferrerPolicyThreatLevel(metadata)

			// Generate description based on findings
			description := generateReferrerPolicyDescription(metadata)

			return TestResult{
				Name:        "Referrer-Policy Header Analysis",
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// analyzeReferrerPolicyHeader parses the Referrer-Policy header value and extracts
// policy directives into a structured metadata map. This function handles multiple
// comma-separated values and normalizes case variations.
//
// Parsed information:
//   - policies: List of referrer policy directives from the header
//   - effective_policy: The policy that will be applied (last valid one)
//   - policy_count: Number of policies specified
//   - has_deprecated: Whether deprecated policies are present
//   - has_unsafe: Whether unsafe policies are present
//
// The function handles various header formats including:
//   - "strict-origin-when-cross-origin"
//   - "no-referrer, strict-origin-when-cross-origin" (multiple policies)
//   - "SAME-ORIGIN" (case-insensitive)
//   - "no-referrer , origin" (with spaces)
//
// Parameters:
//   - referrerPolicyHeader: Raw Referrer-Policy header value from HTTP response
//
// Returns:
//   - map[string]interface{}: Structured metadata containing:
//     * policies: []string - List of policy directives
//     * effective_policy: string - The effective policy (last valid one)
//     * policy_count: int - Number of policies specified
//     * has_deprecated: bool - Whether deprecated policies are present
//     * has_unsafe: bool - Whether unsafe policies (unsafe-url) are present
//     * invalid_policies: []string - List of unrecognized policy values
//
// Example:
//
//	metadata1 := analyzeReferrerPolicyHeader("strict-origin-when-cross-origin")
//	// Returns: {policies: ["strict-origin-when-cross-origin"], effective_policy: "strict-origin-when-cross-origin", ...}
//
//	metadata2 := analyzeReferrerPolicyHeader("no-referrer, unsafe-url")
//	// Returns: {policies: ["no-referrer", "unsafe-url"], effective_policy: "unsafe-url", has_unsafe: true, ...}
func analyzeReferrerPolicyHeader(referrerPolicyHeader string) map[string]interface{} {
	validPolicies := map[string]bool{
		"no-referrer":                     true,
		"no-referrer-when-downgrade":      true,
		"origin":                          true,
		"origin-when-cross-origin":        true,
		"same-origin":                     true,
		"strict-origin":                   true,
		"strict-origin-when-cross-origin": true,
		"unsafe-url":                      true,
	}

	// Split by comma and clean up whitespace
	policyParts := strings.Split(referrerPolicyHeader, ",")
	var policies []string
	var invalidPolicies []string
	var effectivePolicy string
	hasDeprecated := false
	hasUnsafe := false

	for _, part := range policyParts {
		policy := strings.TrimSpace(strings.ToLower(part))
		if policy == "" {
			continue
		}

		if validPolicies[policy] {
			policies = append(policies, policy)
			effectivePolicy = policy // Last valid policy takes precedence

			// Check for deprecated policies
			if policy == "no-referrer-when-downgrade" {
				hasDeprecated = true
			}

			// Check for unsafe policies
			if policy == "unsafe-url" {
				hasUnsafe = true
			}
		} else {
			invalidPolicies = append(invalidPolicies, part) // Keep original case for invalid policies
		}
	}

	return map[string]interface{}{
		"policies":         policies,
		"effective_policy": effectivePolicy,
		"policy_count":     len(policies),
		"has_deprecated":   hasDeprecated,
		"has_unsafe":       hasUnsafe,
		"invalid_policies": invalidPolicies,
		"raw_header":       referrerPolicyHeader,
	}
}

// evaluateReferrerPolicyThreatLevel determines the security threat level based on
// Referrer-Policy configuration quality. It applies privacy and security best practices
// to classify the referrer policy implementation strength.
//
// Threat level classification:
//
//   - None (0): Excellent configuration
//     * strict-origin-when-cross-origin (W3C recommended)
//     * strict-origin (strong privacy)
//     * no-referrer (maximum privacy)
//
//   - Info (1): Good configuration
//     * origin-when-cross-origin (reasonable balance)
//     * origin (basic privacy protection)
//
//   - Low (2): Acceptable configuration
//     * same-origin (limited privacy protection)
//
//   - Medium (3): Weak configuration
//     * no-referrer-when-downgrade (browser default)
//     * Multiple conflicting policies
//     * Contains deprecated policies
//
//   - High (4): Vulnerable configuration
//     * unsafe-url (always sends full URL)
//     * Invalid/unrecognized policies only
//     * Malformed header
//
// The assessment considers:
//   - Privacy protection level
//   - Information leakage potential
//   - Cross-origin data exposure
//   - Protocol downgrade behavior
//   - Policy conflicts and precedence
//
// Parameters:
//   - metadata: Parsed referrer policy metadata from analyzeReferrerPolicyHeader
//
// Returns:
//   - ThreatLevel: Security classification (None, Info, Low, Medium, or High)
//
// Example:
//
//	metadata := map[string]interface{}{
//	    "effective_policy": "strict-origin-when-cross-origin",
//	    "has_unsafe": false,
//	}
//	level := evaluateReferrerPolicyThreatLevel(metadata)
//	// Returns: None (excellent configuration)
func evaluateReferrerPolicyThreatLevel(metadata map[string]interface{}) ThreatLevel {
	effectivePolicy, _ := metadata["effective_policy"].(string)
	hasUnsafe, _ := metadata["has_unsafe"].(bool)
	hasDeprecated, _ := metadata["has_deprecated"].(bool)
	policyCount, _ := metadata["policy_count"].(int)
	invalidPolicies, _ := metadata["invalid_policies"].([]string)

	// If only invalid policies, it's highly vulnerable
	if policyCount == 0 && len(invalidPolicies) > 0 {
		return High
	}

	// If no valid policies at all, treat as missing (should not happen here)
	if effectivePolicy == "" {
		return Medium
	}

	// Check for unsafe configurations
	if hasUnsafe && effectivePolicy == "unsafe-url" {
		return High
	}

	// Excellent policies - recommended and secure
	switch effectivePolicy {
	case "no-referrer":
		return None // Maximum privacy
	case "strict-origin":
		return None // Strong privacy with origin info
	case "strict-origin-when-cross-origin":
		return None // W3C recommended balance
	}

	// Good policies - reasonable privacy protection
	switch effectivePolicy {
	case "origin":
		return Info // Basic privacy, only origin sent
	case "origin-when-cross-origin":
		return Info // Good balance for most use cases
	}

	// Acceptable policies - limited protection
	if effectivePolicy == "same-origin" {
		return Low
	}

	// Weak policies or configurations
	if effectivePolicy == "no-referrer-when-downgrade" || hasDeprecated {
		return Medium
	}

	// Multiple conflicting policies
	if policyCount > 2 {
		return Medium
	}

	// Fallback for unhandled cases
	return Medium
}

// generateReferrerPolicyDescription creates a human-readable description of the
// Referrer-Policy analysis results, including findings, risks, and recommendations.
//
// The description covers:
//   - Current policy configuration assessment
//   - Privacy and security implications
//   - Information leakage risks
//   - Specific recommendations for improvement
//   - Policy conflicts or deprecated usage warnings
//
// Parameters:
//   - metadata: Parsed referrer policy metadata from analyzeReferrerPolicyHeader
//
// Returns:
//   - string: Detailed human-readable description of findings and recommendations
//
// Example output:
//   "Referrer-Policy configured with 'strict-origin-when-cross-origin' - excellent privacy 
//    protection that balances security with functionality. This W3C recommended policy sends 
//    full URL for same-origin requests and only origin for cross-origin requests..."
func generateReferrerPolicyDescription(metadata map[string]interface{}) string {
	effectivePolicy, _ := metadata["effective_policy"].(string)
	hasUnsafe, _ := metadata["has_unsafe"].(bool)
	hasDeprecated, _ := metadata["has_deprecated"].(bool)
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
		description.WriteString("No valid Referrer-Policy found. Browser will use default behavior (typically no-referrer-when-downgrade) which may leak referrer information.")
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
		description.WriteString("limited privacy protection. Full referrer URL is sent only for same-origin requests, providing some privacy for cross-origin requests but no protection against information leakage within the same origin.")

	case "no-referrer-when-downgrade":
		description.WriteString("weak privacy protection (browser default). Full referrer URL is sent except when downgrading from HTTPS to HTTP, which still allows significant information leakage in most scenarios.")

	case "unsafe-url":
		description.WriteString("vulnerable configuration. Full referrer URL is always sent to all destinations including insecure HTTP sites, creating significant privacy and security risks. This policy should be avoided.")

	default:
		description.WriteString("unrecognized policy configuration.")
	}

	// Add warnings for specific issues
	if hasUnsafe {
		description.WriteString(" WARNING: Contains 'unsafe-url' policy which poses significant privacy and security risks.")
	}

	if hasDeprecated {
		description.WriteString(" Note: Contains deprecated policy configurations.")
	}

	if policyCount > 2 {
		description.WriteString(" Consider simplifying to a single clear policy for better maintainability.")
	}

	return description.String()
}