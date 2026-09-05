// Package modules holds the stage implementations of the Cookie Security Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Analyzer inspects the cookies a response sets.
type Analyzer struct {
	SensitiveNames []string
	SessionNames   []string
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

// Analyze performs comprehensive analysis of all cookies
func (a Analyzer) Analyze(cookies []*http.Cookie, headers http.Header) CookieSecurityAnalysis {
	analysis := CookieSecurityAnalysis{
		TotalCookies:   len(cookies),
		CookieDetails:  []CookieSecurityDetail{},
		SecurityIssues: []string{},
		CriticalIssues: []string{},
	}

	// Get raw Set-Cookie headers for additional analysis
	setCookieHeaders := headers.Values("Set-Cookie")

	for i, cookie := range cookies {
		detail := a.analyzeSingleCookie(cookie, setCookieHeaders, i)
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
func (a Analyzer) analyzeSingleCookie(cookie *http.Cookie, setCookieHeaders []string, index int) CookieSecurityDetail {
	detail := CookieSecurityDetail{
		Name:            cookie.Name,
		HasHttpOnly:     cookie.HttpOnly,
		HasSecure:       cookie.Secure,
		SameSite:        getSameSiteString(cookie.SameSite),
		MaxAge:          cookie.MaxAge,
		IsSessionCookie: a.isSessionCookie(cookie),
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
	a.analyzeIndividualCookieSecurity(&detail, cookie, setCookieHeaders, index)

	// Calculate individual cookie security score
	detail.SecurityScore = calculateIndividualCookieScore(detail)

	return detail
}

// analyzeIndividualCookieSecurity identifies specific security issues
func (a Analyzer) analyzeIndividualCookieSecurity(detail *CookieSecurityDetail, cookie *http.Cookie, headers []string, index int) {
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
	sensitiveNames := a.SensitiveNames
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
func (a Analyzer) isSessionCookie(cookie *http.Cookie) bool {
	// Session cookies have no Max-Age and no Expires, or have common session names
	nameLower := strings.ToLower(cookie.Name)
	if SiteTests.ContainsAnyFold(nameLower, a.SessionNames) {
		return true
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
