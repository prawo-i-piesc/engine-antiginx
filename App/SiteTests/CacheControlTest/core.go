// Package CacheControlTest implements the Cache-Control Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package CacheControlTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// New creates a ResponseTest that checks the caching headers of pages tied to a user session.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			analysis := analyze(params.Response)
			level, description := grade(&analysis)

			certainty := cacheFactCertainty
			if analysis.HasPasswordField && len(analysis.SessionCookies) == 0 {
				certainty = cacheContentCertainty
			}
			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   certainty,
				ThreatLevel: level,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// analyze reads the caching headers, the session cookies and the password fields of a response.
func analyze(response *http.Response) CacheAnalysis {
	analysis := CacheAnalysis{MaxAge: -1, SharedMaxAge: -1, Issues: []string{}}

	analysis.CacheControl = strings.Join(response.Header.Values("Cache-Control"), ", ")
	analysis.Pragma = strings.TrimSpace(response.Header.Get("Pragma"))

	for _, directive := range SiteTests.SplitHeaderList(analysis.CacheControl, ",") {
		name, value, _ := strings.Cut(directive, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch name {
		case "public":
			analysis.Public = true
		case "private":
			analysis.Private = true
		case "no-store":
			analysis.NoStore = true
		case "no-cache":
			analysis.NoCache = true
		case "max-age":
			if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
				analysis.MaxAge = seconds
			}
		case "s-maxage":
			if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
				analysis.SharedMaxAge = seconds
			}
		}
	}

	for _, cookie := range response.Cookies() {
		if SiteTests.MatchesNameFragment(cookie.Name, sessionCookieNames) {
			analysis.SessionCookies = append(analysis.SessionCookies, cookie.Name)
		}
	}

	if response.Body != nil {
		body, err := io.ReadAll(io.LimitReader(response.Body, maxScannedBody))
		if err == nil {
			analysis.HasPasswordField = passwordInput.Match(body)
		}
	}

	analysis.Sensitive = len(analysis.SessionCookies) > 0 || analysis.HasPasswordField

	// A shared cache may keep the response when it is declared public or given a lifetime,
	// unless private or no-store rules it out.
	explicitLifetime := analysis.Public || analysis.MaxAge > 0 || analysis.SharedMaxAge > 0
	analysis.SharedCacheable = explicitLifetime && !analysis.Private && !analysis.NoStore

	pragmaNoCache := strings.Contains(strings.ToLower(analysis.Pragma), "no-cache")
	analysis.PragmaOnlyGuard = pragmaNoCache && !analysis.NoStore && !analysis.Private && !analysis.NoCache

	return analysis
}

// grade turns the analysis into a threat level and a description.
func grade(a *CacheAnalysis) (SiteTests.ThreatLevel, string) {
	var trigger string
	switch {
	case len(a.SessionCookies) > 0 && a.HasPasswordField:
		trigger = "sets a session cookie and contains a password field"
	case len(a.SessionCookies) > 0:
		trigger = "sets a session cookie"
	case a.HasPasswordField:
		trigger = "contains a password field"
	}

	if !a.Sensitive {
		if a.SharedCacheable {
			return SiteTests.None, "The response is cacheable but sets no session cookie and has no password field."
		}
		return SiteTests.None, "No session cookie or password field found, so Cache-Control is not security relevant for this response."
	}

	level := SiteTests.None
	var issues []string

	if a.SharedCacheable {
		reason := "Cache-Control: public"
		level = SiteTests.High
		if !a.Public {
			reason = "a max-age/s-maxage lifetime"
			if a.SharedMaxAge <= 0 {
				level = SiteTests.Medium
			}
		}
		issues = append(issues, "page "+trigger+" and may be stored in a shared cache ("+reason+" without private or no-store)")
	}

	if a.PragmaOnlyGuard {
		issues = append(issues, "Pragma: no-cache is the only protection against caching; it is an HTTP/1.0 mechanism and Cache-Control: no-store or private is required")
		level = SiteTests.HighestThreatLevel(level, SiteTests.Medium)
	}

	if len(issues) == 0 && !a.NoStore && !a.Private {
		issues = append(issues, "page "+trigger+" but sends neither Cache-Control: no-store nor private, so caches may store it heuristically")
		level = SiteTests.Low
	}

	a.Issues = issues
	if len(issues) == 0 {
		return SiteTests.None, "Page " + trigger + " and is protected from shared caching by Cache-Control."
	}
	return level, "Cache-Control issues: " + strings.Join(issues, "; ") + "."
}
