// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the X-Frame-Options test that checks for proper clickjacking
// protection by analyzing X-Frame-Options and Content-Security-Policy frame directives.
package Tests

import (
	"strings"
)

// NewXFrameTest creates a new ResponseTest that analyzes X-Frame-Options header and CSP frame
// directives to assess clickjacking protection. Clickjacking attacks embed target pages in
// iframes to trick users into performing unintended actions on the embedded content.
//
// The test evaluates:
//   - Presence of X-Frame-Options header (legacy protection)
//   - X-Frame-Options directive values (DENY, SAMEORIGIN, ALLOW-FROM)
//   - Content-Security-Policy frame-ancestors directive (modern protection)
//   - Conflicting or invalid configurations
//
// Threat level assessment:
//   - None (0): Excellent - CSP frame-ancestors 'none' or X-Frame-Options DENY
//   - Info (1): Good - CSP frame-ancestors 'self' or X-Frame-Options SAMEORIGIN
//   - Low (2): Limited - X-Frame-Options ALLOW-FROM (deprecated and limited browser support)
//   - Medium (3): Weak - Only CSP frame-ancestors with specific domains (partial protection)
//   - High (4): Vulnerable - Missing both X-Frame-Options and CSP frame-ancestors
//   - High (4): Invalid - Present but with invalid/malformed directives
//
// Security implications:
//   - Missing protection: Vulnerable to clickjacking attacks, UI redressing, and iframe abuse
//   - ALLOW-FROM directive: Deprecated and not supported in modern browsers
//   - Conflicting headers: May lead to inconsistent protection across browsers
//   - Invalid values: Browsers may ignore protection, leaving site vulnerable
//
// Standards compliance:
//   - X-Frame-Options: RFC 7034 (legacy, but widely supported)
//   - CSP frame-ancestors: CSP Level 2 (modern, preferred approach)
//
// Returns:
//   - *ResponseTest: Configured X-Frame-Options test ready for execution
//
// Example usage:
//
//	xframeTest := NewXFrameTest()
//	result := xframeTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed iframe embedding analysis
func NewXFrameTest() *ResponseTest {
	return &ResponseTest{
		Id:          "xframe",
		Name:        "X-Frame-Options & CSP Frame Protection Analysis",
		Description: "Analyzes X-Frame-Options header and CSP frame-ancestors directive to assess clickjacking protection and iframe embedding policies",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for both X-Frame-Options and CSP frame-ancestors
			xframeHeader := params.Response.Header.Get("X-Frame-Options")
			cspHeader := params.Response.Header.Get("Content-Security-Policy")

			// Analyze frame protection
			hasXFrame := xframeHeader != ""
			var xframeDirective string
			var xframeValid bool

			if hasXFrame {
				xframeDirective = strings.ToUpper(strings.TrimSpace(xframeHeader))
				switch xframeDirective {
				case "DENY", "SAMEORIGIN":
					xframeValid = true
				default:
					if strings.HasPrefix(xframeDirective, "ALLOW-FROM ") {
						xframeValid = true
					} else {
						xframeValid = false
					}
				}
			}

			// Check CSP frame-ancestors
			var cspFrameValue string
			hasCSPFrameAncestors := false
			if cspHeader != "" {
				cspLower := strings.ToLower(cspHeader)
				if strings.Contains(cspLower, "frame-ancestors") {
					hasCSPFrameAncestors = true
					cspFrameValue = extractFrameAncestorsValue(cspHeader)
				}
			}

			// Determine protection level
			protectionLevel := determineProtectionLevel(xframeDirective, cspFrameValue, xframeValid)

			// Evaluate threat level
			var threatLevel ThreatLevel
			switch protectionLevel {
			case "excellent":
				threatLevel = None
			case "good":
				threatLevel = Info
			case "limited":
				threatLevel = Low
			case "weak":
				threatLevel = Medium
			case "vulnerable":
				threatLevel = High
			default:
				threatLevel = High
			}

			// Generate description
			canBeEmbedded := assessEmbeddingCapability(xframeDirective, cspFrameValue, xframeValid)
			description := generateDescription(protectionLevel, hasXFrame, hasCSPFrameAncestors, canBeEmbedded)

			return TestResult{
				Name:        "X-Frame-Options & CSP Frame Protection Analysis",
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    nil,
				Description: description,
			}
		},
	}
}

// extractFrameAncestorsValue parses the Content-Security-Policy header to extract
// the frame-ancestors directive value.
//
// Parameters:
//   - cspHeader: Complete CSP header value
//
// Returns:
//   - string: frame-ancestors directive value or empty string if not found
func extractFrameAncestorsValue(cspHeader string) string {
	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(strings.ToLower(directive), "frame-ancestors") {
			parts := strings.SplitN(directive, " ", 2)
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// determineProtectionLevel assesses the overall frame protection strength based on
// configured headers and directives.
//
// Parameters:
//   - xframeDirective: X-Frame-Options directive value
//   - cspFrameValue: CSP frame-ancestors directive value
//   - xframeValid: Whether X-Frame-Options syntax is valid
//
// Returns:
//   - string: Protection level (excellent, good, limited, weak, vulnerable)
func determineProtectionLevel(xframeDirective, cspFrameValue string, xframeValid bool) string {
	// CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers
	if cspFrameValue != "" {
		cspLower := strings.ToLower(strings.TrimSpace(cspFrameValue))
		switch {
		case cspLower == "'none'":
			return "excellent"
		case cspLower == "'self'":
			return "good"
		case hasOnlyBroadSources(cspLower):
			// Values like "https:" or "http:" alone allow all sources with that scheme - weak protection
			return "weak"
		case strings.Contains(cspLower, "'self'") || hasSpecificDomains(cspLower):
			// 'self' with specific domains, or specific domains only - limited protection
			return "limited"
		default:
			return "weak"
		}
	}

	// Fall back to X-Frame-Options analysis
	if xframeValid {
		switch strings.ToUpper(xframeDirective) {
		case "DENY":
			return "excellent"
		case "SAMEORIGIN":
			return "good"
		default:
			if strings.HasPrefix(strings.ToUpper(xframeDirective), "ALLOW-FROM ") {
				return "limited"
			}
		}
	}

	return "vulnerable"
}

// assessEmbeddingCapability determines whether the page can be embedded in an iframe
// based on the configured frame protection headers.
//
// Parameters:
//   - xframeDirective: X-Frame-Options directive value
//   - cspFrameValue: CSP frame-ancestors directive value
//   - xframeValid: Whether X-Frame-Options syntax is valid
//
// Returns:
//   - string: Embedding capability (blocked, same-origin, limited, allowed)
func assessEmbeddingCapability(xframeDirective, cspFrameValue string, xframeValid bool) string {
	// CSP frame-ancestors takes precedence
	if cspFrameValue != "" {
		cspLower := strings.ToLower(strings.TrimSpace(cspFrameValue))
		switch {
		case cspLower == "'none'":
			return "blocked"
		case cspLower == "'self'":
			return "same-origin"
		case cspLower == "*":
			return "allowed"
		default:
			return "limited"
		}
	}

	// Fall back to X-Frame-Options
	if xframeValid {
		switch strings.ToUpper(xframeDirective) {
		case "DENY":
			return "blocked"
		case "SAMEORIGIN":
			return "same-origin"
		default:
			if strings.HasPrefix(strings.ToUpper(xframeDirective), "ALLOW-FROM ") {
				return "limited"
			}
		}
	}

	return "allowed"
}

// generateDescription creates a description based on protection analysis
func generateDescription(protectionLevel string, hasXFrame, hasCSP bool, canBeEmbedded string) string {
	var description strings.Builder

	// Primary assessment
	switch protectionLevel {
	case "excellent":
		description.WriteString("Excellent clickjacking protection - page cannot be embedded in iframes")
	case "good":
		description.WriteString("Good clickjacking protection - page can only be embedded by same origin")
	case "limited":
		description.WriteString("Limited clickjacking protection - page can be embedded by specific domains")
	case "weak":
		description.WriteString("Weak clickjacking protection - partial protection may not cover all scenarios")
	case "vulnerable":
		description.WriteString("No clickjacking protection - page can be embedded in any iframe")
	default:
		description.WriteString("Invalid frame protection configuration")
	}

	// Add technical details
	description.WriteString(". ")

	if hasXFrame && hasCSP {
		description.WriteString("Both X-Frame-Options and CSP frame-ancestors headers are present")
	} else if hasCSP {
		description.WriteString("Content-Security-Policy frame-ancestors directive is configured")
	} else if hasXFrame {
		description.WriteString("X-Frame-Options header is present")
	} else {
		description.WriteString("No frame protection headers detected")
	}

	// Add embedding capability
	switch canBeEmbedded {
	case "blocked":
		description.WriteString(" - iframe embedding is completely blocked")
	case "same-origin":
		description.WriteString(" - iframe embedding is restricted to same origin")
	case "limited":
		description.WriteString(" - iframe embedding is restricted to specific domains")
	case "allowed":
		description.WriteString(" - iframe embedding is allowed from any source")
	}

	return description.String()
}

// hasOnlyBroadSources checks if the CSP frame-ancestors value contains only broad
// scheme sources (https:, http:, *) without specific domains. Values like "https:"
// alone allow all HTTPS sources, providing minimal real protection.
//
// Parameters:
//   - cspLower: Lowercase CSP frame-ancestors value
//
// Returns:
//   - bool: true if value only contains broad sources without specific domains
func hasOnlyBroadSources(cspLower string) bool {
	parts := strings.Fields(cspLower)
	if len(parts) == 0 {
		return false
	}

	broadSources := map[string]bool{
		"https:": true,
		"http:":  true,
		"*":      true,
	}

	for _, part := range parts {
		if !broadSources[part] {
			return false
		}
	}
	return true
}

// hasSpecificDomains checks if the CSP frame-ancestors value contains specific
// domain restrictions (not just scheme sources or wildcards).
//
// Parameters:
//   - cspLower: Lowercase CSP frame-ancestors value
//
// Returns:
//   - bool: true if value contains at least one specific domain
func hasSpecificDomains(cspLower string) bool {
	parts := strings.Fields(cspLower)
	broadSources := map[string]bool{
		"https:":  true,
		"http:":   true,
		"*":       true,
		"'self'":  true,
		"'none'":  true,
	}

	for _, part := range parts {
		if !broadSources[part] {
			// This part is not a broad source or keyword, likely a specific domain
			return true
		}
	}
	return false
}
