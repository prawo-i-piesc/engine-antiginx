// Package CrossOriginTest implements the Cross-Origin Security Headers Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package CrossOriginTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"strings"
)

// New creates a new ResponseTest that analyzes Cross-Origin security headers configuration.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
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

// CrossOriginAnalysis represents the parsed and analyzed cross-origin security headers
// configuration
type CrossOriginAnalysis struct {
	HasCOEP            bool     `json:"hasCOEP"`
	HasCORP            bool     `json:"hasCORP"`
	HasCOOP            bool     `json:"hasCOOP"`
	COEPValue          string   `json:"coepValue"`
	CORPValue          string   `json:"corpValue"`
	COOPValue          string   `json:"coopValue"`
	SecurityIssues     []string `json:"securityIssues"`
	ConfiguredHeaders  []string `json:"configuredHeaders"`
	MissingHeaders     []string `json:"missingHeaders"`
	ProtectionLevel    string   `json:"protectionLevel"`
	RecommendedActions []string `json:"recommendedActions"`
	IsolationEffective bool     `json:"isolationEffective"`
}

// analyzeCrossOriginHeaders parses and analyzes all three cross-origin security headers to
// determine the overall security posture and isolation effectiveness.
func analyzeCrossOriginHeaders(coepHeader, corpHeader, coopHeader string) map[string]interface{} {
	analysis := &CrossOriginAnalysis{
		HasCOEP:            coepHeader != "",
		HasCORP:            corpHeader != "",
		HasCOOP:            coopHeader != "",
		COEPValue:          SiteTests.NormalizeHeaderValue(coepHeader),
		CORPValue:          SiteTests.NormalizeHeaderValue(corpHeader),
		COOPValue:          SiteTests.NormalizeHeaderValue(coopHeader),
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
		} else if analysis.COOPValue == "same-origin-allow-popups" {
			analysis.SecurityIssues = append(analysis.SecurityIssues, "COOP same-origin-allow-popups keeps popups in the same browsing context group, so the page is not cross-origin isolated - use 'same-origin' for isolation")
		}
	} else {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Cross-Origin-Opener-Policy")
		analysis.SecurityIssues = append(analysis.SecurityIssues, "Missing Cross-Origin-Opener-Policy header - vulnerable to cross-origin opener attacks")
		analysis.RecommendedActions = append(analysis.RecommendedActions, "Add Cross-Origin-Opener-Policy: same-origin header")
	}

	// Cross-origin isolation is what a browser grants only when the page both requires its
	// subresources to opt in (COEP) and keeps its own browsing context group (COOP).
	coepSecure := analysis.COEPValue == "require-corp" || analysis.COEPValue == "credentialless"
	corpSecure := analysis.CORPValue == "same-origin" || analysis.CORPValue == "same-site"
	coopSecure := analysis.COOPValue == "same-origin" || analysis.COOPValue == "same-origin-allow-popups"
	analysis.IsolationEffective = coepSecure && analysis.COOPValue == "same-origin"

	// Grade on the headers that actually protect: one present with a permissive or invalid
	// value configures the header without gaining anything.
	secureCount := 0
	for _, secure := range []bool{coepSecure, corpSecure, coopSecure} {
		if secure {
			secureCount++
		}
	}
	configuredCount := len(analysis.ConfiguredHeaders)
	switch {
	case configuredCount == 3 && len(analysis.SecurityIssues) == 0 && analysis.IsolationEffective:
		analysis.ProtectionLevel = "Excellent"
	case configuredCount == 3 && (analysis.IsolationEffective || secureCount == 3):
		analysis.ProtectionLevel = "Good"
	case secureCount >= 2:
		analysis.ProtectionLevel = "Moderate"
	case secureCount == 1:
		analysis.ProtectionLevel = "Basic"
	default:
		analysis.ProtectionLevel = "None"
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
func evaluateCrossOriginThreatLevel(metadata map[string]interface{}) SiteTests.ThreatLevel {
	protectionLevel := metadata["protectionLevel"].(string)

	switch protectionLevel {
	case "Excellent":
		return SiteTests.None
	case "Good":
		return SiteTests.Info
	default:
		// Moderate, Basic and None: isolation is a defence-in-depth layer (ZAP 90004), so
		// lacking it is Low however many headers are missing
		return SiteTests.Low
	}
}

// generateCrossOriginDescription creates a detailed description of the cross-origin security
// headers analysis results, including findings and recommendations.
func generateCrossOriginDescription(metadata map[string]interface{}) string {
	protectionLevel := metadata["protectionLevel"].(string)
	securityIssues := metadata["securityIssues"].([]string)
	configuredHeaders := metadata["configuredHeaders"].([]string)
	missingHeaders := metadata["missingHeaders"].([]string)
	isolationEffective := metadata["isolationEffective"].(bool)

	description := ""

	// Status overview
	if len(configuredHeaders) == 0 {
		description = "No cross-origin security headers found. The page is not cross-origin isolated and its resources may be embedded by any origin, so it lacks browser-level protection against Spectre-like side-channel attacks. "
	} else {
		if protectionLevel == "None" {
			description = "Cross-origin security headers are present but none is set to a protective value. "
		} else {
			description = "Cross-origin security analysis: " + protectionLevel + " protection level. "
		}
		description += "Configured headers: " + strings.Join(configuredHeaders, ", ") + ". "
	}

	// Isolation effectiveness
	if isolationEffective {
		description += "Cross-origin isolation is effective with current configuration. "
	} else if len(configuredHeaders) > 0 {
		description += "Cross-origin isolation is not effective - it requires Cross-Origin-Embedder-Policy require-corp or credentialless together with Cross-Origin-Opener-Policy same-origin. "
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
