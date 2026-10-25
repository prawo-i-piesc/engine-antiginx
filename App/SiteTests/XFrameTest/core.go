// Package XFrameTest implements the X-Frame-Options & CSP Frame Protection Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package XFrameTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strings"
)

// New creates a new ResponseTest that analyzes X-Frame-Options header and CSP frame directives
// to assess clickjacking protection.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			analysis := analyzeFrameProtection(
				params.Response.Header.Get("X-Frame-Options"),
				params.Response.Header.Get("Content-Security-Policy"),
			)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   Certainty,
				ThreatLevel: evaluateFrameThreatLevel(analysis),
				Metadata:    analysis,
				Description: generateDescription(analysis),
			}
		},
	}
}

// FrameAnalysis is what the two frame-protection mechanisms declare and what they add up to,
// reported as the result's metadata.
type FrameAnalysis struct {
	HasXFrameOptions  bool   `json:"has_x_frame_options"` // Whether X-Frame-Options was sent at all
	XFrameOptions     string `json:"x_frame_options"`     // Its value, trimmed and uppercased
	XFrameValid       bool   `json:"x_frame_valid"`       // Whether that value is DENY, SAMEORIGIN or ALLOW-FROM
	HasFrameAncestors bool   `json:"has_frame_ancestors"` // Whether the CSP names frame-ancestors
	FrameAncestors    string `json:"frame_ancestors"`     // The frame-ancestors sources as written, 'none' for an empty list
	AllowFromIgnored  bool   `json:"allow_from_ignored"`  // ALLOW-FROM is the only protection, and browsers ignore it
	ProtectionLevel   string `json:"protection_level"`    // excellent, good, limited, weak or vulnerable
	Embedding         string `json:"embedding"`           // blocked, same-origin, limited or allowed
}

// analyzeFrameProtection reads X-Frame-Options and the CSP frame-ancestors directive and
// works out how far the page can be framed.
func analyzeFrameProtection(xframeHeader, cspHeader string) FrameAnalysis {
	analysis := FrameAnalysis{HasXFrameOptions: xframeHeader != ""}

	if analysis.HasXFrameOptions {
		analysis.XFrameOptions = strings.ToUpper(strings.TrimSpace(xframeHeader))
		switch analysis.XFrameOptions {
		case "DENY", "SAMEORIGIN":
			analysis.XFrameValid = true
		default:
			analysis.XFrameValid = strings.HasPrefix(analysis.XFrameOptions, "ALLOW-FROM ")
		}
	}

	// A directive present with no sources is an empty source list, which matches no ancestor
	// at all and so blocks framing like 'none'
	if cspHeader != "" {
		analysis.FrameAncestors, analysis.HasFrameAncestors = SiteTests.DirectiveValue(cspHeader, "frame-ancestors")
		if analysis.HasFrameAncestors && strings.TrimSpace(analysis.FrameAncestors) == "" {
			analysis.FrameAncestors = "'none'"
		}
	}

	// ALLOW-FROM is the only protection when frame-ancestors does not take over, and current
	// browsers ignore it
	analysis.AllowFromIgnored = !analysis.HasFrameAncestors && isAllowFrom(analysis.XFrameOptions)

	analysis.ProtectionLevel = determineProtectionLevel(analysis.XFrameOptions, analysis.FrameAncestors, analysis.XFrameValid)
	analysis.Embedding = assessEmbeddingCapability(analysis.XFrameOptions, analysis.FrameAncestors, analysis.XFrameValid)
	return analysis
}

// protectionThreat grades each protection level. A page anyone can frame is open to
// clickjacking, which OWASP ZAP rates Medium (alert 10020); anything unrecognised is graded
// the same.
var protectionThreat = map[string]SiteTests.ThreatLevel{
	"excellent":  SiteTests.None,
	"good":       SiteTests.Info,
	"limited":    SiteTests.Low,
	"weak":       SiteTests.Low,
	"vulnerable": SiteTests.Medium,
}

// evaluateFrameThreatLevel grades the analysis by its protection level.
func evaluateFrameThreatLevel(analysis FrameAnalysis) SiteTests.ThreatLevel {
	if level, known := protectionThreat[analysis.ProtectionLevel]; known {
		return level
	}
	return SiteTests.Medium
}

// determineProtectionLevel assesses the overall frame protection strength based on configured
// headers and directives.
func determineProtectionLevel(xframeDirective, cspFrameValue string, xframeValid bool) string {
	// CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers
	if cspFrameValue != "" {
		cspLower := SiteTests.NormalizeHeaderValue(cspFrameValue)
		switch {
		case cspLower == "'none'":
			return "excellent"
		case cspLower == "'self'":
			return "good"
		case hasBroadSource(cspLower):
			// "*", "https:" or "http:" admit every site (with that scheme) as an ancestor, so
			// whatever else is listed, any such site can frame the page
			return "vulnerable"
		case strings.Contains(cspLower, "'self'") || hasSpecificDomains(cspLower):
			// 'self' with specific domains, or specific domains only - limited protection
			return "limited"
		default:
			return "weak"
		}
	}

	// Fall back to X-Frame-Options analysis. ALLOW-FROM is ignored by current browsers, so
	// it protects nothing.
	if xframeValid {
		switch strings.ToUpper(xframeDirective) {
		case "DENY":
			return "excellent"
		case "SAMEORIGIN":
			return "good"
		}
	}

	return "vulnerable"
}

// assessEmbeddingCapability determines whether the page can be embedded in an iframe based on
// the configured frame protection headers.
func assessEmbeddingCapability(xframeDirective, cspFrameValue string, xframeValid bool) string {
	// CSP frame-ancestors takes precedence
	if cspFrameValue != "" {
		cspLower := SiteTests.NormalizeHeaderValue(cspFrameValue)
		switch {
		case cspLower == "'none'":
			return "blocked"
		case cspLower == "'self'":
			return "same-origin"
		case hasBroadSource(cspLower):
			return "allowed"
		default:
			return "limited"
		}
	}

	// Fall back to X-Frame-Options; ALLOW-FROM is ignored, so it leaves framing allowed
	if xframeValid {
		switch strings.ToUpper(xframeDirective) {
		case "DENY":
			return "blocked"
		case "SAMEORIGIN":
			return "same-origin"
		}
	}

	return "allowed"
}

// generateDescription creates a description based on protection analysis
func generateDescription(analysis FrameAnalysis) string {
	protectionLevel := analysis.ProtectionLevel
	hasXFrame := analysis.HasXFrameOptions
	hasCSP := analysis.HasFrameAncestors
	canBeEmbedded := analysis.Embedding
	allowFromIgnored := analysis.AllowFromIgnored

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
	} else if allowFromIgnored {
		description.WriteString("X-Frame-Options uses ALLOW-FROM, which current browsers ignore")
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

// cspBroadSources contains CSP sources that allow broad access and don't represent specific
// domain restrictions.
var cspBroadSources = map[string]bool{
	"https:": true, // Allows ALL HTTPS sources
	"http:":  true, // Allows ALL HTTP sources
	"*":      true, // Allows ALL sources
}

// cspKeywords contains CSP keywords that are not domain restrictions.
var cspKeywords = map[string]bool{
	"'self'": true,
	"'none'": true,
}

// hasBroadSource checks if the CSP frame-ancestors value contains a broad source (https:,
// http:, *) that admits every site rather than a specific one.
func hasBroadSource(cspLower string) bool {
	for _, part := range strings.Fields(cspLower) {
		if cspBroadSources[part] {
			return true
		}
	}
	return false
}

// isAllowFrom reports whether an X-Frame-Options value uses the obsolete ALLOW-FROM form.
func isAllowFrom(xframeDirective string) bool {
	return strings.HasPrefix(strings.ToUpper(xframeDirective), "ALLOW-FROM ")
}

// hasSpecificDomains checks if the CSP frame-ancestors value contains specific domain
// restrictions (not just scheme sources, wildcards, or CSP keywords).
func hasSpecificDomains(cspLower string) bool {
	parts := strings.Fields(cspLower)
	for _, part := range parts {
		// If not a broad source and not a keyword, it's a specific domain
		if !cspBroadSources[part] && !cspKeywords[part] {
			return true
		}
	}
	return false
}
