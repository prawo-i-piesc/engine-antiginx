// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the Cookie Security test that analyzes Set-Cookie headers for
// security best practices including HttpOnly, Secure, SameSite attributes, expiration times,
// and potential session fixation vulnerabilities.
package Tests

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NewCookieSecurityTest creates a new ResponseTest that analyzes cookie security configurations.
// Cookies are critical for session management and authentication, making their security paramount.
// Improperly configured cookies can lead to session hijacking, XSS exploitation, CSRF attacks,
// and session fixation vulnerabilities.
//
// The test evaluates:
//   - HttpOnly flag (prevents JavaScript access to cookies)
//   - Secure flag (ensures transmission only over HTTPS)
//   - SameSite attribute (protects against CSRF attacks)
//   - Expiration times (Max-Age/Expires values)
//   - Cookie predictability and session fixation risks
//   - Cookie name patterns indicating sensitive data
//
// Threat level assessment:
//   - None (0): All cookies properly secured with HttpOnly, Secure, SameSite, and reasonable expiration
//   - Info (1): Minor issues like long expiration times but critical flags present
//   - Low (2): Some cookies missing non-critical security attributes
//   - Medium (3): Cookies missing important security flags (HttpOnly or Secure)
//   - High (4): Multiple security issues or session cookies without protection
//   - Critical (5): Session cookies completely unsecured or high fixation risk
//
// Security implications:
//   - Missing HttpOnly: Vulnerable to XSS-based cookie theft
//   - Missing Secure: Cookies can be intercepted over HTTP (MITM attacks)
//   - Missing SameSite: Vulnerable to CSRF attacks
//   - Long expiration: Extended window for cookie theft/replay attacks
//   - Predictable values: Session fixation and prediction attacks
//
// Returns:
//   - *ResponseTest: Configured cookie security test ready for execution
//
// Example usage:
//
//	cookieTest := NewCookieSecurityTest()
//	result := cookieTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed cookie security analysis
func NewCookieSecurityTest() *ResponseTest {
	return &ResponseTest{
		Id:          "cookie-sec",
		Name:        "Cookie Security Analysis",
		Description: "Analyzes Set-Cookie headers for security attributes including HttpOnly, Secure, SameSite, expiration times, and session fixation risks",
		RunTest: func(params ResponseTestParams) TestResult {
			// Get all Set-Cookie headers
			cookies := params.Response.Cookies()

			if len(cookies) == 0 {
				return TestResult{
					Name:        "Cookie Security Analysis",
					Certainty:   100,
					ThreatLevel: Info,
					Metadata:    nil,
					Description: "No cookies set by the server - no cookie security concerns for this response.",
				}
			}

			// Analyze all cookies
			analysis := analyzeCookieSecurity(cookies, params.Response.Header)

			// Determine threat level
			threatLevel := evaluateCookieThreatLevel(analysis)

			// Generate description
			description := generateCookieDescription(analysis)

			return TestResult{
				Name:        "Cookie Security Analysis",
				Certainty:   100,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// CookieSecurityAnalysis represents the comprehensive cookie security assessment
type CookieSecurityAnalysis struct {
	TotalCookies         int                    `json:"totalCookies"`
	CookieDetails        []CookieSecurityDetail `json:"cookieDetails"`
	SecurityIssues       []string               `json:"securityIssues"`
	CriticalIssues       []string               `json:"criticalIssues"`
	MissingHttpOnly      int                    `json:"missingHttpOnly"`
	MissingSecure        int                    `json:"missingSecure"`
	MissingSameSite      int                    `json:"missingSameSite"`
	LongExpiration       int                    `json:"longExpiration"`
	SessionCookies       int                    `json:"sessionCookies"`
	InsecureSession      bool                   `json:"insecureSession"`
	FixationRisk         bool                   `json:"fixationRisk"`
	OverallSecurityScore int                    `json:"overallSecurityScore"` // 0-100
}

// CookieSecurityDetail represents security analysis for a single cookie
type CookieSecurityDetail struct {
	Name             string   `json:"name"`
	HasHttpOnly      bool     `json:"hasHttpOnly"`
	HasSecure        bool     `json:"hasSecure"`
	SameSite         string   `json:"sameSite"`
	MaxAge           int      `json:"maxAge"`
	ExpiresIn        string   `json:"expiresIn"`
	IsSessionCookie  bool     `json:"isSessionCookie"`
	SecurityIssues   []string `json:"securityIssues"`
	SecurityScore    int      `json:"securityScore"` // 0-100
	PredictableValue bool     `json:"predictableValue"`
}

// analyzeCookieSecurity performs comprehensive analysis of all cookies
func analyzeCookieSecurity(cookies []*http.Cookie, headers http.Header) CookieSecurityAnalysis {
	analysis := CookieSecurityAnalysis{
		TotalCookies:   len(cookies),
		CookieDetails:  []CookieSecurityDetail{},
		SecurityIssues: []string{},
		CriticalIssues: []string{},
	}

	// Get raw Set-Cookie headers for additional analysis
	setCookieHeaders := headers.Values("Set-Cookie")

	for i, cookie := range cookies {
		detail := analyzeSingleCookie(cookie, setCookieHeaders, i)
		analysis.CookieDetails = append(analysis.CookieDetails, detail)

		// Track security issues
		if !detail.HasHttpOnly {
			analysis.MissingHttpOnly++
		}
		if !detail.HasSecure {
			analysis.MissingSecure++
		}
		if detail.SameSite == "" || detail.SameSite == "None" {
			analysis.MissingSameSite++
		}
		if detail.MaxAge > 31536000 { // More than 1 year
			analysis.LongExpiration++
		}
		if detail.IsSessionCookie {
			analysis.SessionCookies++
			if !detail.HasHttpOnly || !detail.HasSecure {
				analysis.InsecureSession = true
			}
		}
		if detail.PredictableValue {
			analysis.FixationRisk = true
		}
	}

	// Aggregate security issues
	aggregateSecurityIssues(&analysis)

	// Calculate overall security score
	calculateCookieSecurityScore(&analysis)

	return analysis
}

// analyzeSingleCookie performs detailed security analysis of a single cookie
func analyzeSingleCookie(cookie *http.Cookie, setCookieHeaders []string, index int) CookieSecurityDetail {
	detail := CookieSecurityDetail{
		Name:            cookie.Name,
		HasHttpOnly:     cookie.HttpOnly,
		HasSecure:       cookie.Secure,
		SameSite:        getSameSiteString(cookie.SameSite),
		MaxAge:          cookie.MaxAge,
		IsSessionCookie: isSessionCookie(cookie),
		SecurityIssues:  []string{},
	}

	// Calculate expiration
	if cookie.MaxAge > 0 {
		detail.ExpiresIn = formatDuration(time.Duration(cookie.MaxAge) * time.Second)
	} else if !cookie.Expires.IsZero() {
		timeUntilExpiry := time.Until(cookie.Expires)
		if timeUntilExpiry > 0 {
			detail.ExpiresIn = formatDuration(timeUntilExpiry)
			detail.MaxAge = int(timeUntilExpiry.Seconds())
		}
	}

	// Check for predictable values
	detail.PredictableValue = isPredictableValue(cookie.Value)

	// Analyze security issues for this cookie
	analyzeIndividualCookieSecurity(&detail, cookie, setCookieHeaders, index)

	// Calculate individual cookie security score
	detail.SecurityScore = calculateIndividualCookieScore(detail)

	return detail
}

// analyzeIndividualCookieSecurity identifies specific security issues
func analyzeIndividualCookieSecurity(detail *CookieSecurityDetail, cookie *http.Cookie, headers []string, index int) {
	// Check HttpOnly
	if !detail.HasHttpOnly {
		detail.SecurityIssues = append(detail.SecurityIssues, "Missing HttpOnly flag - vulnerable to XSS attacks")
	}

	// Check Secure flag
	if !detail.HasSecure {
		detail.SecurityIssues = append(detail.SecurityIssues, "Missing Secure flag - can be transmitted over HTTP")
	}

	// Check SameSite
	if detail.SameSite == "" || detail.SameSite == "None" {
		detail.SecurityIssues = append(detail.SecurityIssues, "Missing or inadequate SameSite attribute - vulnerable to CSRF")
	}

	// Check session cookie security
	if detail.IsSessionCookie {
		sessionIssues := []string{}
		if !detail.HasHttpOnly {
			sessionIssues = append(sessionIssues, "HttpOnly")
		}
		if !detail.HasSecure {
			sessionIssues = append(sessionIssues, "Secure")
		}
		if detail.SameSite != "Strict" && detail.SameSite != "Lax" {
			sessionIssues = append(sessionIssues, "SameSite")
		}
		if len(sessionIssues) > 0 {
			detail.SecurityIssues = append(detail.SecurityIssues,
				fmt.Sprintf("Session cookie missing critical flags: %s", strings.Join(sessionIssues, ", ")))
		}
	}

	// Check expiration time
	if detail.MaxAge > 31536000 { // More than 1 year
		years := detail.MaxAge / 31536000
		detail.SecurityIssues = append(detail.SecurityIssues,
			fmt.Sprintf("Excessive expiration time (%d+ years) - increases attack window", years))
	} else if detail.MaxAge > 7776000 { // More than 90 days
		detail.SecurityIssues = append(detail.SecurityIssues,
			"Long expiration time (>90 days) - consider shorter duration")
	}

	// Check for predictable values
	if detail.PredictableValue {
		detail.SecurityIssues = append(detail.SecurityIssues,
			"Cookie value appears predictable - potential session fixation risk")
	}

	// Check sensitive cookie names
	sensitiveNames := []string{"session", "sessid", "auth", "token", "jwt", "access"}
	nameLower := strings.ToLower(detail.Name)
	for _, sensitive := range sensitiveNames {
		if strings.Contains(nameLower, sensitive) {
			if !detail.HasHttpOnly || !detail.HasSecure {
				detail.SecurityIssues = append(detail.SecurityIssues,
					fmt.Sprintf("Sensitive cookie '%s' lacks proper security flags", detail.Name))
			}
			break
		}
	}
}

// aggregateSecurityIssues creates high-level security issue summaries
func aggregateSecurityIssues(analysis *CookieSecurityAnalysis) {
	// HttpOnly issues
	if analysis.MissingHttpOnly > 0 {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d cookie(s) missing HttpOnly flag", analysis.MissingHttpOnly))
		if analysis.InsecureSession {
			analysis.CriticalIssues = append(analysis.CriticalIssues,
				"Session cookies without HttpOnly flag - high XSS risk")
		}
	}

	// Secure flag issues
	if analysis.MissingSecure > 0 {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d cookie(s) missing Secure flag", analysis.MissingSecure))
		if analysis.InsecureSession {
			analysis.CriticalIssues = append(analysis.CriticalIssues,
				"Session cookies without Secure flag - vulnerable to interception")
		}
	}

	// SameSite issues
	if analysis.MissingSameSite > 0 {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d cookie(s) missing SameSite attribute", analysis.MissingSameSite))
	}

	// Expiration issues
	if analysis.LongExpiration > 0 {
		analysis.SecurityIssues = append(analysis.SecurityIssues,
			fmt.Sprintf("%d cookie(s) with excessive expiration times", analysis.LongExpiration))
	}

	// Session fixation risk
	if analysis.FixationRisk {
		analysis.CriticalIssues = append(analysis.CriticalIssues,
			"Predictable cookie values detected - potential session fixation vulnerability")
	}

	// Overall insecure session warning
	if analysis.InsecureSession {
		analysis.CriticalIssues = append(analysis.CriticalIssues,
			"Session management cookies lack critical security attributes")
	}
}

// calculateCookieSecurityScore calculates overall security score (0-100)
func calculateCookieSecurityScore(analysis *CookieSecurityAnalysis) {
	if analysis.TotalCookies == 0 {
		analysis.OverallSecurityScore = 100
		return
	}

	totalScore := 0
	for _, detail := range analysis.CookieDetails {
		totalScore += detail.SecurityScore
	}

	analysis.OverallSecurityScore = totalScore / analysis.TotalCookies

	// Apply penalties for critical issues
	if analysis.InsecureSession {
		analysis.OverallSecurityScore -= 30
	}
	if analysis.FixationRisk {
		analysis.OverallSecurityScore -= 20
	}

	// Ensure score is within bounds
	if analysis.OverallSecurityScore < 0 {
		analysis.OverallSecurityScore = 0
	}
	if analysis.OverallSecurityScore > 100 {
		analysis.OverallSecurityScore = 100
	}
}

// calculateIndividualCookieScore calculates security score for a single cookie
func calculateIndividualCookieScore(detail CookieSecurityDetail) int {
	score := 100

	// Deduct for missing security flags
	if !detail.HasHttpOnly {
		score -= 25
	}
	if !detail.HasSecure {
		score -= 25
	}
	if detail.SameSite == "" || detail.SameSite == "None" {
		score -= 20
	} else if detail.SameSite == "Lax" {
		score -= 5 // Minor deduction, Strict is better
	}

	// Deduct for long expiration
	if detail.MaxAge > 31536000 {
		score -= 15
	} else if detail.MaxAge > 7776000 {
		score -= 5
	}

	// Deduct for predictable values
	if detail.PredictableValue {
		score -= 15
	}

	// Extra penalty for insecure session cookies
	if detail.IsSessionCookie && (!detail.HasHttpOnly || !detail.HasSecure) {
		score -= 10
	}

	if score < 0 {
		score = 0
	}

	return score
}

// evaluateCookieThreatLevel determines threat level based on analysis
func evaluateCookieThreatLevel(analysis CookieSecurityAnalysis) ThreatLevel {
	// Critical: Session cookies completely unsecured or high fixation risk with session issues
	if analysis.InsecureSession && analysis.FixationRisk {
		return Critical
	}

	// High: Multiple critical issues
	if len(analysis.CriticalIssues) > 0 {
		return High
	}

	// Medium: Missing important security flags
	if analysis.MissingHttpOnly > 0 || analysis.MissingSecure > 0 {
		return Medium
	}

	// Low: Minor issues like SameSite or long expiration
	if analysis.MissingSameSite > 0 || analysis.LongExpiration > 0 {
		return Low
	}

	// Info: Very minor issues
	if analysis.OverallSecurityScore >= 90 && len(analysis.SecurityIssues) > 0 {
		return Info
	}

	// None: All cookies properly secured
	return None
}

// generateCookieDescription creates detailed description of findings
func generateCookieDescription(analysis CookieSecurityAnalysis) string {
	var description strings.Builder

	description.WriteString(fmt.Sprintf("Analyzed %d cookie(s) with overall security score of %d/100. ",
		analysis.TotalCookies, analysis.OverallSecurityScore))

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
			description.WriteString(fmt.Sprintf(" and %d more", len(analysis.SecurityIssues)-3))
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

// getSameSiteString converts SameSite enum to string
func getSameSiteString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteDefaultMode:
		return ""
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// isSessionCookie determines if a cookie is likely a session cookie
func isSessionCookie(cookie *http.Cookie) bool {
	// Session cookies have no Max-Age and no Expires, or have common session names
	nameLower := strings.ToLower(cookie.Name)
	sessionNames := []string{"session", "sessid", "phpsessid", "jsessionid", "aspsessionid", "sid"}

	for _, sessionName := range sessionNames {
		if strings.Contains(nameLower, sessionName) {
			return true
		}
	}

	// Also consider cookies with short expiration as session-like
	return cookie.MaxAge == 0 && cookie.Expires.IsZero()
}

// isPredictableValue checks if cookie value appears predictable
func isPredictableValue(value string) bool {
	if value == "" {
		return false
	}

	// Check for sequential numbers
	if matched, _ := regexp.MatchString(`^\d+$`, value); matched {
		return true
	}

	// Check for simple patterns (e.g., "user123", "session1")
	if matched, _ := regexp.MatchString(`^[a-zA-Z]+\d+$`, value); matched {
		return true
	}

	// Check if value is too short to be cryptographically secure (less than 16 chars)
	if len(value) < 16 {
		return true
	}

	// Check for timestamp-like values
	if matched, _ := regexp.MatchString(`^\d{10,13}$`, value); matched {
		if timestamp, err := strconv.ParseInt(value, 10, 64); err == nil {
			// Check if it's a reasonable Unix timestamp
			if timestamp > 1000000000 && timestamp < 9999999999 {
				return true
			}
		}
	}

	return false
}

// formatDuration formats a duration in human-readable format
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days > 365 {
		years := days / 365
		remainingDays := days % 365
		if remainingDays > 0 {
			return fmt.Sprintf("%d year(s) %d day(s)", years, remainingDays)
		}
		return fmt.Sprintf("%d year(s)", years)
	} else if days > 0 {
		return fmt.Sprintf("%d day(s)", days)
	} else if d.Hours() > 0 {
		return fmt.Sprintf("%.1f hour(s)", d.Hours())
	} else if d.Minutes() > 0 {
		return fmt.Sprintf("%.0f minute(s)", d.Minutes())
	}
	return fmt.Sprintf("%.0f second(s)", d.Seconds())
}
