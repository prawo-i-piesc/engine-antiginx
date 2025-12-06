// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the CSP (Content Security Policy) test that analyzes Content-Security-Policy
// header configuration to assess protection against XSS, data injection, and other web vulnerabilities.
package Tests

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"fmt"
	"regexp"
	"strings"
)

// NewCSPTest creates a new ResponseTest that analyzes Content Security Policy (CSP) header
// configuration. CSP is a security mechanism that helps prevent cross-site scripting (XSS),
// data injection attacks, and other code injection vulnerabilities by controlling which
// resources the browser is allowed to load for a given page.
//
// The test evaluates:
//   - Presence of Content-Security-Policy header
//   - Critical directive configurations (default-src, script-src, object-src, etc.)
//   - Unsafe directive values ('unsafe-inline', 'unsafe-eval', '*')
//   - Missing security-critical directives
//   - Policy syntax and validity
//
// Threat level assessment:
//   - None (0): Excellent - Comprehensive CSP with strict directives, no unsafe values
//   - Info (1): Good - Well-configured CSP with minor improvements possible
//   - Low (2): Acceptable - Basic CSP present with some weaknesses
//   - Medium (3): Weak - CSP present but with significant security issues
//   - High (4): Poor - CSP present but severely misconfigured or ineffective
//   - Critical (5): Missing - No CSP header found, vulnerable to injection attacks
//
// Security implications:
//   - Missing CSP: Vulnerable to XSS, data injection, and clickjacking attacks
//   - unsafe-inline: Allows inline scripts/styles, negating XSS protection
//   - unsafe-eval: Permits eval() and similar functions, enabling code injection
//   - Wildcard (*): Allows loading from any source, undermining security
//   - Missing object-src: May allow Flash/plugin-based attacks
//   - Missing base-uri: Vulnerable to base tag injection attacks
//
// Standards compliance:
//   - Content Security Policy Level 2 (W3C Recommendation)
//   - Content Security Policy Level 3 (W3C Working Draft)
//
// Returns:
//   - *ResponseTest: Configured CSP test ready for execution
//
// Example usage:
//
//	cspTest := NewCSPTest()
//	result := cspTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed CSP configuration analysis
func NewCSPTest() *ResponseTest {
	return &ResponseTest{
		Id:          "csp",
		Name:        "Content Security Policy Analysis",
		Description: "Analyzes Content-Security-Policy header configuration to assess protection against XSS, injection attacks, and resource loading security",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for CSP header
			cspHeader := params.Response.Header.Get("Content-Security-Policy")

			if cspHeader == "" {
				return TestResult{
					Name:        "Content Security Policy Analysis",
					Certainty:   100,
					ThreatLevel: Critical,
					Metadata:    nil,
					Description: "Missing Content-Security-Policy header - site vulnerable to XSS attacks, data injection, and other script-based vulnerabilities. Implement CSP to restrict resource loading and script execution.",
				}
			}

			// Parse CSP header for comprehensive security analysis
			metadata := analyzeCSPHeader(cspHeader)

			// Determine threat level based on CSP configuration
			threatLevel := evaluateCSPThreatLevel(metadata)

			// Generate description based on findings
			description := generateCSPDescription(metadata)

			return TestResult{
				Name:        "Content Security Policy Analysis",
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// CSPAnalysis represents the parsed and analyzed CSP configuration
type CSPAnalysis struct {
	HasCSP              bool                `json:"hasCSP"`
	Directives          map[string][]string `json:"directives"`
	SecurityIssues      []string            `json:"securityIssues"`
	MissingDirectives   []string            `json:"missingDirectives"`
	UnsafeDirectives    []string            `json:"unsafeDirectives"`
	ProtectionLevel     string              `json:"protectionLevel"`
	RecommendedActions  []string            `json:"recommendedActions"`
	DirectiveCompliance map[string]string   `json:"directiveCompliance"`
	PolicyStrength      int                 `json:"policyStrength"` // 0-100 score
	CriticalVulns       []string            `json:"criticalVulns"`
}

// analyzeCSPHeader performs comprehensive analysis of the CSP header configuration
func analyzeCSPHeader(cspHeader string) CSPAnalysis {
	analysis := CSPAnalysis{
		HasCSP:              true,
		Directives:          make(map[string][]string),
		SecurityIssues:      []string{},
		MissingDirectives:   []string{},
		UnsafeDirectives:    []string{},
		RecommendedActions:  []string{},
		DirectiveCompliance: make(map[string]string),
		CriticalVulns:       []string{},
	}

	// Parse directives
	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) == 0 {
			continue
		}

		directiveName := strings.ToLower(parts[0])
		directiveValues := parts[1:]
		analysis.Directives[directiveName] = directiveValues
	}

	// Analyze security implications
	analyzeDirectiveSecurity(&analysis)
	checkMissingDirectives(&analysis)
	calculatePolicyStrength(&analysis)
	determineCSPProtectionLevel(&analysis)

	return analysis
}

// analyzeDirectiveSecurity checks each directive for security issues
func analyzeDirectiveSecurity(analysis *CSPAnalysis) {
	criticalDirectives := []string{"default-src", "script-src", "object-src", "style-src"}
	unsafeValues := []string{"'unsafe-inline'", "'unsafe-eval'", "*"}

	for directiveName, values := range analysis.Directives {
		// Check for unsafe values
		for _, value := range values {
			valueLower := strings.ToLower(value)
			for _, unsafeValue := range unsafeValues {
				if valueLower == unsafeValue {
					analysis.UnsafeDirectives = append(analysis.UnsafeDirectives, fmt.Sprintf("%s: %s", directiveName, value))

					switch unsafeValue {
					case "'unsafe-inline'":
						analysis.SecurityIssues = append(analysis.SecurityIssues, fmt.Sprintf("%s allows unsafe-inline, negating XSS protection", directiveName))
						if directiveName == "script-src" {
							analysis.CriticalVulns = append(analysis.CriticalVulns, "script-src unsafe-inline allows any inline scripts")
						}
					case "'unsafe-eval'":
						analysis.SecurityIssues = append(analysis.SecurityIssues, fmt.Sprintf("%s allows unsafe-eval, enabling code injection", directiveName))
						analysis.CriticalVulns = append(analysis.CriticalVulns, "unsafe-eval permits eval() and Function() constructors")
					case "*":
						analysis.SecurityIssues = append(analysis.SecurityIssues, fmt.Sprintf("%s allows wildcard (*), permitting any source", directiveName))
						if helpers.StringInSlice(criticalDirectives, directiveName) {
							analysis.CriticalVulns = append(analysis.CriticalVulns, fmt.Sprintf("%s wildcard undermines security policy", directiveName))
						}
					}
				}
			}
		}

		// Evaluate directive compliance
		evaluateDirectiveCompliance(analysis, directiveName, values)
	}
}

// evaluateDirectiveCompliance assesses individual directive configurations
func evaluateDirectiveCompliance(analysis *CSPAnalysis, directiveName string, values []string) {
	switch directiveName {
	case "default-src":
		if helpers.AnyStringInSlice(values, []string{"'none'", "'self'"}) {
			analysis.DirectiveCompliance[directiveName] = "good"
		} else if helpers.StringInSlice(values, "*") {
			analysis.DirectiveCompliance[directiveName] = "poor"
		} else {
			analysis.DirectiveCompliance[directiveName] = "fair"
		}

	case "script-src":
		if helpers.StringInSlice(values, "'none'") {
			analysis.DirectiveCompliance[directiveName] = "excellent"
		} else if helpers.StringInSlice(values, "'unsafe-inline'") || helpers.StringInSlice(values, "'unsafe-eval'") {
			analysis.DirectiveCompliance[directiveName] = "poor"
		} else if containsNonce(values) || containsHash(values) {
			analysis.DirectiveCompliance[directiveName] = "good"
		} else if helpers.StringInSlice(values, "'self'") {
			analysis.DirectiveCompliance[directiveName] = "fair"
		} else {
			analysis.DirectiveCompliance[directiveName] = "fair"
		}

	case "object-src":
		if helpers.StringInSlice(values, "'none'") {
			analysis.DirectiveCompliance[directiveName] = "excellent"
		} else {
			analysis.DirectiveCompliance[directiveName] = "fair"
		}

	case "style-src":
		if helpers.StringInSlice(values, "'unsafe-inline'") {
			analysis.DirectiveCompliance[directiveName] = "poor"
		} else if containsNonce(values) || containsHash(values) {
			analysis.DirectiveCompliance[directiveName] = "good"
		} else {
			analysis.DirectiveCompliance[directiveName] = "fair"
		}

	default:
		analysis.DirectiveCompliance[directiveName] = "present"
	}
}

// checkMissingDirectives identifies important missing CSP directives
func checkMissingDirectives(analysis *CSPAnalysis) {
	recommendedDirectives := map[string]string{
		"default-src":     "Sets fallback policy for resource loading",
		"script-src":      "Controls script execution and loading",
		"object-src":      "Prevents Flash/plugin attacks",
		"style-src":       "Controls stylesheet loading",
		"img-src":         "Controls image loading sources",
		"frame-ancestors": "Prevents clickjacking attacks",
		"base-uri":        "Prevents base tag injection attacks",
		"form-action":     "Controls form submission targets",
	}

	for directive, description := range recommendedDirectives {
		if _, exists := analysis.Directives[directive]; !exists {
			analysis.MissingDirectives = append(analysis.MissingDirectives, directive)
			analysis.RecommendedActions = append(analysis.RecommendedActions, fmt.Sprintf("Add %s directive: %s", directive, description))
		}
	}
}

// calculatePolicyStrength calculates a numerical strength score (0-100)
func calculatePolicyStrength(analysis *CSPAnalysis) {
	score := 0

	// Base score for having CSP
	score += 10

	// Score for important directives
	importantDirectives := []string{"default-src", "script-src", "object-src", "style-src", "frame-ancestors", "base-uri"}
	for _, directive := range importantDirectives {
		if _, exists := analysis.Directives[directive]; exists {
			score += 10
		}
	}

	// Penalty for unsafe directives
	score -= len(analysis.UnsafeDirectives) * 15

	// Bonus for secure configurations
	if compliance, exists := analysis.DirectiveCompliance["script-src"]; exists && (compliance == "excellent" || compliance == "good") {
		score += 15
	}
	if compliance, exists := analysis.DirectiveCompliance["object-src"]; exists && compliance == "excellent" {
		score += 10
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	analysis.PolicyStrength = score
}

// determineCSPProtectionLevel sets overall protection assessment
func determineCSPProtectionLevel(analysis *CSPAnalysis) {
	if analysis.PolicyStrength >= 80 {
		analysis.ProtectionLevel = "excellent"
	} else if analysis.PolicyStrength >= 60 {
		analysis.ProtectionLevel = "good"
	} else if analysis.PolicyStrength >= 40 {
		analysis.ProtectionLevel = "acceptable"
	} else if analysis.PolicyStrength >= 20 {
		analysis.ProtectionLevel = "weak"
	} else {
		analysis.ProtectionLevel = "poor"
	}
}

// evaluateCSPThreatLevel determines the threat level based on CSP analysis
func evaluateCSPThreatLevel(analysis CSPAnalysis) ThreatLevel {
	// Critical vulnerabilities present
	if len(analysis.CriticalVulns) > 0 {
		return High
	}

	switch analysis.ProtectionLevel {
	case "excellent":
		return None
	case "good":
		return Info
	case "acceptable":
		return Low
	case "weak":
		return Medium
	case "poor":
		return High
	default:
		return High
	}
}

// generateCSPDescription creates a detailed description of CSP findings
func generateCSPDescription(analysis CSPAnalysis) string {
	var description strings.Builder

	// Overall assessment
	description.WriteString(fmt.Sprintf("Content Security Policy detected with %s protection level (strength: %d/100). ",
		analysis.ProtectionLevel, analysis.PolicyStrength))

	// Critical vulnerabilities
	if len(analysis.CriticalVulns) > 0 {
		description.WriteString("CRITICAL ISSUES: ")
		description.WriteString(strings.Join(analysis.CriticalVulns, "; "))
		description.WriteString(". ")
	}

	// Security issues
	if len(analysis.SecurityIssues) > 0 {
		description.WriteString("Security concerns: ")
		description.WriteString(strings.Join(analysis.SecurityIssues, "; "))
		description.WriteString(". ")
	}

	// Missing directives
	if len(analysis.MissingDirectives) > 0 {
		description.WriteString(fmt.Sprintf("Missing %d recommended directives: %s. ",
			len(analysis.MissingDirectives), strings.Join(analysis.MissingDirectives, ", ")))
	}

	// Recommendations
	if len(analysis.RecommendedActions) > 0 && len(analysis.RecommendedActions) <= 3 {
		description.WriteString("Recommendations: ")
		description.WriteString(strings.Join(analysis.RecommendedActions[:helpers.MinInt(3, len(analysis.RecommendedActions))], "; "))
		description.WriteString(".")
	}

	result := description.String()
	if result == "" {
		result = "CSP header analysis completed with no specific issues identified."
	}

	return result
}

// CSP-specific utility functions
func containsNonce(values []string) bool {
	nonceRegex := regexp.MustCompile(`'nonce-[A-Za-z0-9+/]+'`)
	for _, value := range values {
		if nonceRegex.MatchString(value) {
			return true
		}
	}
	return false
}

func containsHash(values []string) bool {
	hashRegex := regexp.MustCompile(`'sha(256|384|512)-[A-Za-z0-9+/]+='`)
	for _, value := range values {
		if hashRegex.MatchString(value) {
			return true
		}
	}
	return false
}
