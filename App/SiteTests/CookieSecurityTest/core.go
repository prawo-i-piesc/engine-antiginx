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

// evaluateCookieThreatLevel grades the response by its most serious single cookie finding;
// several findings do not add up to a higher level.
func evaluateCookieThreatLevel(analysis CookieSecurityAnalysis) SiteTests.ThreatLevel {
	level := SiteTests.None
	for _, cookie := range analysis.CookieDetails {
		level = SiteTests.HighestThreatLevel(level, cookieThreatLevel(cookie))
	}
	return level
}

// cookieThreatLevel grades one cookie. A cookie whose name marks it as a session identifier or
// a credential is held to the stricter standard, since its value is the account:
//   - a guessable value invites session fixation and hijacking (CWE-330, CWE-384): High — only
//     a heuristic, so not the Critical a confirmed predictable session identifier would be;
//   - no HttpOnly (CWE-1004, readable by any injected script) or no Secure (CWE-614, sent over
//     plain HTTP): Medium;
//   - no SameSite, or SameSite=None (CSRF, CWE-352; browsers default to Lax): Low.
//
// Any other cookie missing a flag is Low, as OWASP ZAP rates these alerts (10010, 10011,
// 10054); an excessive lifetime alone is Info.
func cookieThreatLevel(cookie CookieSecurityDetail) SiteTests.ThreatLevel {
	missingSameSite := cookie.SameSite == "" || cookie.SameSite == "None"
	if cookie.CarriesAuthority {
		switch {
		case cookie.PredictableValue:
			return SiteTests.High
		case !cookie.HasHttpOnly || !cookie.HasSecure:
			return SiteTests.Medium
		case missingSameSite:
			return SiteTests.Low
		}
	} else if !cookie.HasHttpOnly || !cookie.HasSecure || missingSameSite {
		return SiteTests.Low
	}
	if cookie.MaxAge > longLifetimeSeconds {
		return SiteTests.Info
	}
	return SiteTests.None
}

// generateCookieDescription creates detailed description of findings
func generateCookieDescription(analysis CookieSecurityAnalysis) string {
	var description strings.Builder

	_, _ = fmt.Fprintf(&description, "Analyzed %d cookie(s) with overall security score of %d/100. ",
		analysis.TotalCookies, analysis.OverallSecurityScore)

	// The most serious issues first
	if len(analysis.CriticalIssues) > 0 {
		description.WriteString("Most serious: ")
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
