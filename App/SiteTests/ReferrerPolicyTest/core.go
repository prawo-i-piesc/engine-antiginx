// Package ReferrerPolicyTest implements the Referrer-Policy Header Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package ReferrerPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strings"
)

// check wires this test's analysis stages into the shared single-header test shape.
var check = SiteTests.HeaderTest[ReferrerPolicyAnalysis]{
	Name:               TestName,
	Header:             "Referrer-Policy",
	MissingLevel:       SiteTests.Medium,
	MissingDescription: missingDescription,
	Certainty:          Certainty,
	Analyze:            analyzeReferrerPolicyHeader,
	Evaluate:           evaluateReferrerPolicyThreatLevel,
	Describe:           generateReferrerPolicyDescription,
}

// New creates a new ResponseTest that analyzes Referrer-Policy header configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest:     check.Run,
	}
}

// ReferrerPolicyAnalysis is what the Referrer-Policy header declares, reported as the
// result's metadata.
// Fields are in the alphabetical order of their JSON names, the order the metadata map this
// replaced was serialized in, so reports keep the same shape.
type ReferrerPolicyAnalysis struct {
	EffectivePolicy string   `json:"effective_policy"` // The last valid policy, which browsers apply
	HasUnsafe       bool     `json:"has_unsafe"`       // Whether unsafe-url appears among the valid policies
	InvalidPolicies []string `json:"invalid_policies"` // Values that are not a policy, as sent
	Policies        []string `json:"policies"`         // The valid policies, normalized, in header order
	PolicyCount     int      `json:"policy_count"`     // How many valid policies there are
	RawHeader       string   `json:"raw_header"`       // The value as sent
}

// analyzeReferrerPolicyHeader parses the Referrer-Policy header value and extracts policy
// directives into an analysis.
func analyzeReferrerPolicyHeader(referrerPolicyHeader string) ReferrerPolicyAnalysis {

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

	return ReferrerPolicyAnalysis{
		EffectivePolicy: effectivePolicy,
		HasUnsafe:       hasUnsafe,
		InvalidPolicies: invalidPolicies,
		Policies:        policies,
		PolicyCount:     len(policies),
		RawHeader:       referrerPolicyHeader,
	}
}

// evaluateReferrerPolicyThreatLevel determines the security threat level based on Referrer-
// Policy configuration quality.
func evaluateReferrerPolicyThreatLevel(metadata ReferrerPolicyAnalysis) SiteTests.ThreatLevel {
	effectivePolicy := metadata.EffectivePolicy
	hasUnsafe := metadata.HasUnsafe
	policyCount := metadata.PolicyCount
	invalidPolicies := metadata.InvalidPolicies

	// If only invalid policies, it's highly vulnerable
	if policyCount == 0 && len(invalidPolicies) > 0 {
		return SiteTests.High
	}

	// If no valid policies at all, treat as missing (should not happen here)
	if effectivePolicy == "" {
		return SiteTests.Medium
	}

	// Check for unsafe configurations
	if hasUnsafe && effectivePolicy == "unsafe-url" {
		return SiteTests.High
	}

	// Excellent policies - recommended and secure
	switch effectivePolicy {
	case "no-referrer":
		return SiteTests.None // Maximum privacy
	case "strict-origin":
		return SiteTests.None // Strong privacy with origin info
	case "strict-origin-when-cross-origin":
		return SiteTests.None // W3C recommended balance
	}

	// Good policies - reasonable privacy protection
	switch effectivePolicy {
	case "origin":
		return SiteTests.Info // Basic privacy, only origin sent
	case "origin-when-cross-origin":
		return SiteTests.Info // Good balance for most use cases
	}

	// Acceptable policies - limited protection
	if effectivePolicy == "same-origin" {
		return SiteTests.Low
	}

	// Weak policies or configurations
	if effectivePolicy == "no-referrer-when-downgrade" {
		return SiteTests.Medium
	}

	// Note: Multiple Referrer-Policy directives are allowed for browser fallback and
	// do not, by themselves, imply higher risk. Threat level is based on the
	// evaluated effective policy and other concrete risk indicators above.

	// Fallback for unhandled cases
	return SiteTests.Medium
}

// generateReferrerPolicyDescription creates a human-readable description of the Referrer-
// Policy analysis results, including findings, risks, and recommendations.
func generateReferrerPolicyDescription(metadata ReferrerPolicyAnalysis) string {
	effectivePolicy := metadata.EffectivePolicy
	hasUnsafe := metadata.HasUnsafe
	policyCount := metadata.PolicyCount
	policies := metadata.Policies
	invalidPolicies := metadata.InvalidPolicies

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

	if policyCount > 2 {
		description.WriteString(" Consider simplifying to a single clear policy for better maintainability.")
	}

	return description.String()
}
