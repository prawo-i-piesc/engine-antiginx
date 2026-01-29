// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the Cross-Origin security headers test that analyzes Cross-Origin-Embedder-Policy (COEP),
// Cross-Origin-Resource-Policy (CORP), and Cross-Origin-Opener-Policy (COOP) headers to assess
// protection against cross-origin attacks and isolation vulnerabilities.
package Tests

import (
	"strings"
)

// NewCrossOriginTest creates a new ResponseTest that analyzes Cross-Origin security headers
// configuration. These headers provide defense-in-depth protection against cross-origin attacks,
// Spectre-like vulnerabilities, and help enforce browser-level isolation boundaries.
//
// The test evaluates:
//   - Cross-Origin-Embedder-Policy (COEP): Controls cross-origin resource embedding
//   - Cross-Origin-Resource-Policy (CORP): Controls cross-origin resource access
//   - Cross-Origin-Opener-Policy (COOP): Controls cross-origin window opener access
//   - Header value validation and security implications
//   - Combination effectiveness for comprehensive isolation
//
// Threat level assessment:
//   - None (0): Excellent - All three headers properly configured with strict values
//   - Info (1): Good - Two headers configured with secure values
//   - Low (2): Acceptable - One header configured or less strict configuration
//   - Medium (3): Weak - Headers present but with permissive values
//   - High (4): Poor - No cross-origin security headers found
//
// Security implications:
//   - Missing COEP: Vulnerable to cross-origin resource embedding attacks
//   - Missing CORP: Resources can be accessed cross-origin without restrictions
//   - Missing COOP: Vulnerable to cross-origin opener attacks and window references
//   - Permissive values: Reduced isolation effectiveness
//   - No headers: Full exposure to cross-origin attacks and Spectre-like vulnerabilities
//
// Standards compliance:
//   - Cross-Origin-Embedder-Policy (W3C Draft)
//   - Cross-Origin-Resource-Policy (W3C Recommendation)
//   - Cross-Origin-Opener-Policy (W3C Draft)
//
// Returns:
//   - *ResponseTest: Configured cross-origin security test ready for execution
//
// Example usage:
//
//	crossOriginTest := NewCrossOriginTest()
//	result := crossOriginTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed cross-origin security analysis
func NewCrossOriginTest() *ResponseTest {
	return &ResponseTest{
		Id:          "cross-origin-x",
		Name:        "Cross-Origin Security Headers Analysis",
		Description: "Analyzes Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy, and Cross-Origin-Opener-Policy headers for cross-origin attack protection",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for Cross-Origin security headers
			coepHeader := params.Response.Header.Get("Cross-Origin-Embedder-Policy")
			corpHeader := params.Response.Header.Get("Cross-Origin-Resource-Policy")
			coopHeader := params.Response.Header.Get("Cross-Origin-Opener-Policy")

			// Analyze headers for comprehensive security assessment
			metadata := analyzeCrossOriginHeaders(coepHeader, corpHeader, coopHeader)

			// Determine threat level based on cross-origin configuration
			threatLevel := evaluateCrossOriginThreatLevel(metadata)

			// Generate description based on findings
			description := generateCrossOriginDescription(metadata)

			return TestResult{
				Name:        "Cross-Origin Security Headers Analysis",
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// CrossOriginAnalysis represents the parsed and analyzed cross-origin security headers configuration
type CrossOriginAnalysis struct {
	HasCOEP             bool     `json:"hasCOEP"`
	HasCORP             bool     `json:"hasCORP"`
	HasCOOP             bool     `json:"hasCOOP"`
	COEPValue           string   `json:"coepValue"`
	CORPValue           string   `json:"corpValue"`
	COOPValue           string   `json:"coopValue"`
	SecurityIssues      []string `json:"securityIssues"`
	ConfiguredHeaders   []string `json:"configuredHeaders"`
	MissingHeaders      []string `json:"missingHeaders"`
	ProtectionLevel     string   `json:"protectionLevel"`
	RecommendedActions  []string `json:"recommendedActions"`
	IsolationEffective  bool     `json:"isolationEffective"`
}

// analyzeCrossOriginHeaders parses and analyzes all three cross-origin security headers
// to determine the overall security posture and isolation effectiveness.
//
// Parameters:
//   - coepHeader: Cross-Origin-Embedder-Policy header value
//   - corpHeader: Cross-Origin-Resource-Policy header value
//   - coopHeader: Cross-Origin-Opener-Policy header value
//
// Returns:
//   - map[string]interface{}: Structured metadata containing cross-origin security analysis
func analyzeCrossOriginHeaders(coepHeader, corpHeader, coopHeader string) map[string]interface{} {
	analysis := &CrossOriginAnalysis{
		HasCOEP:            coepHeader != "",
		HasCORP:            corpHeader != "",
		HasCOOP:            coopHeader != "",
		COEPValue:          strings.ToLower(strings.TrimSpace(coepHeader)),
		CORPValue:          strings.ToLower(strings.TrimSpace(corpHeader)),
		COOPValue:          strings.ToLower(strings.TrimSpace(coopHeader)),
		SecurityIssues:     []string{},
		ConfiguredHeaders:  []string{},
		MissingHeaders:     []string{},
		RecommendedActions: []string{},
	}

	// Analyze COEP (Cross-Origin-Embedder-Policy)
	if analysis.HasCOEP {
		analysis.ConfiguredHeaders = append(analysis.ConfiguredHeaders, "Cross-Origin-Embedder-Policy")
		if analysis.COEPValue != "require-corp" && analysis.COEPValue != "credentialless" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "COEP header has permissive value - use 'require-corp' or 'credentialless' for better security")
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Cross-Origin-Embedder-Policy")
		analysis.SecurityIssues = append(analysis.SecurityIssues, "Missing Cross-Origin-Embedder-Policy header - vulnerable to cross-origin resource embedding attacks")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Add Cross-Origin-Embedder-Policy: require-corp header")
	}

	// Analyze CORP (Cross-Origin-Resource-Policy)
	if analysis.HasCORP {
		analysis.ConfiguredHeaders = append(analysis.ConfiguredHeaders, "Cross-Origin-Resource-Policy")
		if analysis.CORPValue != "same-origin" && analysis.CORPValue != "same-site" && analysis.CORPValue != "cross-origin" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "CORP header has invalid value - use 'same-origin', 'same-site', or 'cross-origin'")
		} else if analysis.CORPValue == "cross-origin" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "CORP header allows cross-origin access - consider 'same-origin' or 'same-site' for better security")
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Cross-Origin-Resource-Policy")
		analysis.SecurityIssues = append(analysis.SecurityIssues, "Missing Cross-Origin-Resource-Policy header - resources can be accessed cross-origin without restrictions")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Add Cross-Origin-Resource-Policy: same-origin header")
	}

	// Analyze COOP (Cross-Origin-Opener-Policy)
	if analysis.HasCOOP {
		analysis.ConfiguredHeaders = append(analysis.ConfiguredHeaders, "Cross-Origin-Opener-Policy")
		if analysis.COOPValue != "same-origin" && analysis.COOPValue != "same-origin-allow-popups" && analysis.COOPValue != "unsafe-none" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "COOP header has invalid value - use 'same-origin', 'same-origin-allow-popups', or 'unsafe-none'")
		} else if analysis.COOPValue == "unsafe-none" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "COOP header allows unsafe cross-origin access - consider 'same-origin' for better security")
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Cross-Origin-Opener-Policy")
		analysis.SecurityIssues = append(analysis.SecurityIssues, "Missing Cross-Origin-Opener-Policy header - vulnerable to cross-origin opener attacks")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Add Cross-Origin-Opener-Policy: same-origin header")
	}

	// Determine overall protection level
	configuredCount := len(analysis.ConfiguredHeaders)
	if configuredCount == 3 && len(analysis.SecurityIssues) == 0 {
		analysis.ProtectionLevel = "Excellent"
		analysis.IsolationEffective = true
	} else if configuredCount == 3 {
		analysis.ProtectionLevel = "Good"
		analysis.IsolationEffective = true
	} else if configuredCount == 2 {
		analysis.ProtectionLevel = "Moderate"
		analysis.IsolationEffective = false
	} else if configuredCount == 1 {
		analysis.ProtectionLevel = "Basic"
		analysis.IsolationEffective = false
	} else {
		analysis.ProtectionLevel = "None"
		analysis.IsolationEffective = false
	}

	// Add general recommendations if not all headers are configured optimally
	if configuredCount < 3 || len(analysis.SecurityIssues) > 0 {
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Implement all three cross-origin headers for comprehensive protection")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Test cross-origin functionality after implementing headers")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Consider using Content-Security-Policy in combination for enhanced security")
	}

	// Convert to map for metadata
	return map[string]interface{}{
		"hasCOEP":            analysis.HasCOEP,
		"hasCORP":            analysis.HasCORP,
		"hasCOOP":            analysis.HasCOOP,
		"coepValue":          analysis.COEPValue,
		"corpValue":          analysis.CORPValue,
		"coopValue":          analysis.COOPValue,
		"securityIssues":     analysis.SecurityIssues,
		"configuredHeaders":  analysis.ConfiguredHeaders,
		"missingHeaders":     analysis.MissingHeaders,
		"protectionLevel":    analysis.ProtectionLevel,
		"recommendedActions": analysis.RecommendedActions,
		"isolationEffective": analysis.IsolationEffective,
	}
}

// evaluateCrossOriginThreatLevel determines the security threat level based on cross-origin
// headers configuration and their security implications.
//
// Parameters:
//   - metadata: Analyzed cross-origin headers metadata
//
// Returns:
//   - ThreatLevel: Security threat level based on configuration
func evaluateCrossOriginThreatLevel(metadata map[string]interface{}) ThreatLevel {
	protectionLevel := metadata["protectionLevel"].(string)
	securityIssues := metadata["securityIssues"].([]string)
	configuredHeaders := metadata["configuredHeaders"].([]string)

	switch {
	case protectionLevel == "Excellent":
		return None
	case protectionLevel == "Good" && len(securityIssues) <= 2:
		return Info
	case protectionLevel == "Moderate" || (protectionLevel == "Good" && len(securityIssues) > 2):
		return Low
	case protectionLevel == "Basic" || len(configuredHeaders) == 1:
		return Medium
	case protectionLevel == "None":
		return High
	default:
		return Medium
	}
}

// generateCrossOriginDescription creates a detailed description of the cross-origin security
// headers analysis results, including findings and recommendations.
//
// Parameters:
//   - metadata: Analyzed cross-origin headers metadata
//
// Returns:
//   - string: Comprehensive description of cross-origin security status
func generateCrossOriginDescription(metadata map[string]interface{}) string {
	protectionLevel := metadata["protectionLevel"].(string)
	securityIssues := metadata["securityIssues"].([]string)
	configuredHeaders := metadata["configuredHeaders"].([]string)
	missingHeaders := metadata["missingHeaders"].([]string)
	isolationEffective := metadata["isolationEffective"].(bool)

	description := ""

	// Status overview
	if len(configuredHeaders) == 0 {
		description = "No cross-origin security headers found. Site is vulnerable to cross-origin attacks, resource embedding exploits, and lacks browser-level isolation protection against Spectre-like vulnerabilities. "
	} else {
		description = "Cross-origin security analysis: " + protectionLevel + " protection level. "
		if len(configuredHeaders) > 0 {
			description += "Configured headers: " + strings.Join(configuredHeaders, ", ") + ". "
		}
	}

	// Isolation effectiveness
	if isolationEffective {
		description += "Cross-origin isolation is effective with current configuration. "
	} else if len(configuredHeaders) > 0 {
		description += "Cross-origin isolation is incomplete - additional headers needed for full protection. "
	}

	// Missing headers
	if len(missingHeaders) > 0 {
		description += "Missing headers: " + strings.Join(missingHeaders, ", ") + ". "
	}

	// Security issues
	if len(securityIssues) > 0 {
		if len(securityIssues) == 1 {
			description += "Security issue: " + securityIssues[0] + ". "
		} else {
			description += "Security issues: " + strings.Join(securityIssues, "; ") + ". "
		}
	}

	// Recommendations based on protection level
	switch protectionLevel {
	case "None":
		description += "Implement Cross-Origin-Embedder-Policy: require-corp, Cross-Origin-Resource-Policy: same-origin, and Cross-Origin-Opener-Policy: same-origin headers for comprehensive cross-origin protection."
	case "Basic":
		description += "Add remaining cross-origin headers and review current configuration for security improvements."
	case "Moderate", "Good":
		description += "Complete cross-origin header implementation and address any configuration issues for optimal security."
	case "Excellent":
		description += "Cross-origin security headers are properly configured providing excellent protection against cross-origin attacks."
	}

	return description
}