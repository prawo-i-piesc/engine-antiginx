// Package CookieSecurityTest implements the Cookie Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package CookieSecurityTest

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CookieSecurityTest/modules"
	"fmt"
	"strings"
)

// The analysis types keep the names they are reported under while living beside the code that
// populates them.
type (
	CookieSecurityAnalysis = modules.CookieSecurityAnalysis
	CookieSecurityDetail   = modules.CookieSecurityDetail
)

// analyzer wires the name lists owned by this package into the inspection stage.
var analyzer = modules.Analyzer{
	SensitiveNames: sensitiveCookieNames,
	SessionNames:   sessionCookieNames,
}

// New creates a new ResponseTest that analyzes cookie security configurations.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			// Get all Set-Cookie headers
			cookies := params.Response.Cookies()

			if len(cookies) == 0 {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   100,
					ThreatLevel: SiteTests.Info,
					Metadata:    nil,
					Description: "No cookies set by the server - no cookie security concerns for this response.",
				}
			}

			// Analyze all cookies
			analysis := analyzer.Analyze(cookies, params.Response.Header)

			// Determine threat level
			threatLevel := evaluateCookieThreatLevel(analysis)

			// Generate description
			description := generateCookieDescription(analysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// evaluateCookieThreatLevel determines threat level based on analysis
func evaluateCookieThreatLevel(analysis CookieSecurityAnalysis) SiteTests.ThreatLevel {
	// Critical: Session cookies completely unsecured or high fixation risk with session issues
	if analysis.InsecureSession && analysis.FixationRisk {
		return SiteTests.Critical
	}

	// High: Multiple critical issues
	if len(analysis.CriticalIssues) > 0 {
		return SiteTests.High
	}

	// Medium: Missing important security flags
	if analysis.MissingHttpOnly > 0 || analysis.MissingSecure > 0 {
		return SiteTests.Medium
	}

	// Low: Minor issues like SameSite or long expiration
	if analysis.MissingSameSite > 0 || analysis.LongExpiration > 0 {
		return SiteTests.Low
	}

	// Info: Very minor issues
	if analysis.OverallSecurityScore >= 90 && len(analysis.SecurityIssues) > 0 {
		return SiteTests.Info
	}

	// None: All cookies properly secured
	return SiteTests.None
}

// generateCookieDescription creates detailed description of findings
func generateCookieDescription(analysis CookieSecurityAnalysis) string {
	var description strings.Builder

	// Before lint
	//description.WriteString(fmt.Sprintf("Analyzed %d cookie(s) with overall security score of %d/100. ",
	//	analysis.TotalCookies, analysis.OverallSecurityScore))

	// After lint
	_, _ = fmt.Fprintf(&description, "Analyzed %d cookie(s) with overall security score of %d/100. ",
		analysis.TotalCookies, analysis.OverallSecurityScore)

	// Critical issues first
	if len(analysis.CriticalIssues) > 0 {
		description.WriteString("CRITICAL: ")
		description.WriteString(strings.Join(analysis.CriticalIssues, "; "))
		description.WriteString(". ")
	}

	// General security issues
	if len(analysis.SecurityIssues) > 0 {
		description.WriteString("Issues found: ")
		maxIssues := helpers.MinInt(3, len(analysis.SecurityIssues))
		description.WriteString(strings.Join(analysis.SecurityIssues[:maxIssues], "; "))
		if len(analysis.SecurityIssues) > 3 {
			_, _ = fmt.Fprintf(&description, " and %d more", len(analysis.SecurityIssues)-3)
		}
		description.WriteString(".")
	}

	result := description.String()
	if result == "" {
		result = "All cookies properly secured with HttpOnly, Secure, and SameSite attributes."
	}

	return result
}

// Utility functions
