// Package CSPTest implements the Content Security Policy Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package CSPTest

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"regexp"
	"strings"
)

// New creates a new ResponseTest that analyzes Content Security Policy (CSP) header
// configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Check for CSP header
			cspHeader := params.Response.Header.Get("Content-Security-Policy")

			if cspHeader == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Critical,
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

	analysis.Directives = SiteTests.ParseDirectives(cspHeader)

	// Analyze security implications
	analyzeDirectiveSecurity(&analysis)
	checkMissingDirectives(&analysis)
	calculatePolicyStrength(&analysis)
	determineCSPProtectionLevel(&analysis)

	return analysis
}

// analyzeDirectiveSecurity checks each directive for security issues
func analyzeDirectiveSecurity(analysis *CSPAnalysis) {

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
func evaluateCSPThreatLevel(analysis CSPAnalysis) SiteTests.ThreatLevel {
	// Critical vulnerabilities present
	if len(analysis.CriticalVulns) > 0 {
		return SiteTests.High
	}

	switch analysis.ProtectionLevel {
	case "excellent":
		return SiteTests.None
	case "good":
		return SiteTests.Info
	case "acceptable":
		return SiteTests.Low
	case "weak":
		return SiteTests.Medium
	case "poor":
		return SiteTests.High
	default:
		return SiteTests.High
	}
}

// generateCSPDescription creates a detailed description of CSP findings
func generateCSPDescription(analysis CSPAnalysis) string {
	var description strings.Builder

	// Overall assessment
	_, _ = fmt.Fprintf(&description, "Content Security Policy detected with %s protection level (strength: %d/100). ",
		analysis.ProtectionLevel, analysis.PolicyStrength)

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
		_, _ = fmt.Fprintf(&description, "Missing %d recommended directives: %s. ",
			len(analysis.MissingDirectives), strings.Join(analysis.MissingDirectives, ", "))
	}

	// Recommendations
	if len(analysis.RecommendedActions) > 0 {
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
	nonceRegex := regexp.MustCompile(`'nonce-[A-Za-z0-9+/=]+'`)
	for _, value := range values {
		if nonceRegex.MatchString(value) {
			return true
		}
	}
	return false
}

func containsHash(values []string) bool {
	hashRegex := regexp.MustCompile(`'sha(256|384|512)-[A-Za-z0-9+/]+=*'`)
	for _, value := range values {
		if hashRegex.MatchString(value) {
			return true
		}
	}
	return false
}
