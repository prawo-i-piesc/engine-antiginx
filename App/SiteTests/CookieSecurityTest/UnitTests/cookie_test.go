package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CookieSecurityTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"testing"
)

func TestCookieFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_cookies.http", SiteTests.Info, []string{"No cookies set by the server"}},
		// A session cookie a cross-site form can make the browser send is the CSRF case
		{"session_without_samesite.http", SiteTests.Low, []string{"1 cookie(s) missing SameSite attribute"}},
		{"session_samesite_none.http", SiteTests.Low, []string{"1 cookie(s) missing SameSite attribute"}},
		// No HttpOnly (CWE-1004) and no Secure (CWE-614) on a session cookie: Medium each, and
		// two findings do not add up to more
		{"session_unprotected.http", SiteTests.Medium, []string{"Session cookies without HttpOnly flag", "Session cookies without Secure flag"}},
		{"session_hardened.http", SiteTests.None, []string{"security score of 100/100"}},
		{"auth_token_lax.http", SiteTests.None, []string{"Analyzed 1 cookie(s)"}},
		// A guessable value is only a fixation risk where the value is the session
		{"predictable_session.http", SiteTests.High, []string{"Predictable cookie values detected"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CookieSecurityTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// The CSRF finding is recorded on the cookie itself, so a report can say which cookie a
// cross-site request would carry.
func TestCSRFFindingNamesTheCookie(t *testing.T) {
	for _, fixture := range []string{"session_without_samesite.http", "session_samesite_none.http"} {
		metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CookieSecurityTest.New(), fixture))
		if metadata["missingSameSite"] != float64(1) {
			t.Errorf("%s: missingSameSite %v, want 1", fixture, metadata["missingSameSite"])
		}
		details, _ := metadata["cookieDetails"].([]any)
		if len(details) != 1 {
			t.Fatalf("%s: cookie details %v", fixture, metadata["cookieDetails"])
		}
		issues, _ := details[0].(map[string]any)["securityIssues"].([]any)
		found := false
		for _, issue := range issues {
			if issue == "Missing or inadequate SameSite attribute - vulnerable to CSRF" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: issues %v do not report the CSRF exposure", fixture, issues)
		}
	}
}

func TestStrictSessionHasNoCSRFFinding(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CookieSecurityTest.New(), "session_hardened.http"))
	if metadata["missingSameSite"] != float64(0) || metadata["insecureSession"] != false {
		t.Errorf("hardened session reported as %v", metadata)
	}
}

// Preference cookies are neither sessions nor credentials: "sid" inside sidebar_state is not
// a session identifier, and theme=dark is supposed to be guessable.
func TestPreferenceCookiesAreNotSessions(t *testing.T) {
	result := UnitTestKit.RunResponse(t, CookieSecurityTest.New(), "preference_cookies.http")
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["fixationRisk"] != false {
		t.Errorf("preference cookies reported as a fixation risk: %s", result.Description)
	}
	for _, detail := range metadata["cookieDetails"].([]any) {
		cookie := detail.(map[string]any)
		if cookie["name"] == "sidebar_state" && cookie["isSessionCookie"] == true {
			t.Error("sidebar_state recognised as a session cookie")
		}
	}
}
