package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CacheControlTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"testing"
)

func TestCacheControlFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"anonymous_page_no_headers.http", SiteTests.None, []string{"Cache-Control is not security relevant"}},
		{"anonymous_page_public.http", SiteTests.None, []string{"cacheable but sets no session cookie"}},
		{"session_public.http", SiteTests.Medium, []string{"sets a session cookie", "Cache-Control: public without private or no-store"}},
		// max-age is aimed at the browser cache, so a shared cache storing it is the lesser case
		{"session_max_age_only.http", SiteTests.Low, []string{"sets a session cookie", "a max-age lifetime"}},
		// s-maxage addresses shared caches directly, so it is graded like public
		{"login_form_s_maxage.http", SiteTests.Medium, []string{"contains a password field", "an s-maxage lifetime for shared caches"}},
		{"session_pragma_max_age_zero.http", SiteTests.Low, []string{"Pragma: no-cache is the only protection"}},
		// Two findings do not raise the level above the more severe of them
		{"session_public_with_pragma.http", SiteTests.Medium, []string{"Cache-Control: public", "Pragma: no-cache is the only protection"}},
		{"session_and_password_no_headers.http", SiteTests.Info, []string{"sets a session cookie and contains a password field", "caches may store it heuristically"}},
		{"session_no_cache_only.http", SiteTests.Info, []string{"neither Cache-Control: no-store nor private"}},
		// Go's net/http, in the scanner as here, adds Cache-Control: no-cache to a response that
		// has Pragma: no-cache and no Cache-Control, so a lone Pragma reaches the test as
		// no-cache: storable but revalidated, which is the heuristic-caching Info.
		{"session_pragma_only.http", SiteTests.Info, []string{"neither Cache-Control: no-store nor private"}},
		// A short fragment such as "sid" counts only as a word of its own, so a UI preference
		// cookie does not make the page sensitive
		{"preference_cookie_public.http", SiteTests.None, []string{"cacheable but sets no session cookie"}},
		{"session_no_store.http", SiteTests.None, []string{"Page sets a session cookie and is protected from shared caching"}},
		{"login_form_private.http", SiteTests.None, []string{"Page contains a password field and is protected from shared caching"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CacheControlTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// A password field found by scanning markup is less certain than a cookie read from a header.
func TestCacheControlCertainty(t *testing.T) {
	cases := map[string]int{
		"login_form_s_maxage.http":             85,
		"session_public.http":                  100,
		"session_and_password_no_headers.http": 100,
	}
	for fixture, certainty := range cases {
		result := UnitTestKit.RunResponse(t, CacheControlTest.New(), fixture)
		if result.Certainty != certainty {
			t.Errorf("%s: certainty %d, want %d", fixture, result.Certainty, certainty)
		}
	}
}

func TestCacheControlMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CacheControlTest.New(), "session_public_with_pragma.http"))
	cookies, _ := metadata["SessionCookies"].([]any)
	if len(cookies) != 1 || cookies[0] != "jwt" {
		t.Errorf("SessionCookies %v, want [jwt]", metadata["SessionCookies"])
	}
	if metadata["Public"] != true || metadata["SharedCacheable"] != true || metadata["PragmaOnlyGuard"] != true || metadata["Pragma"] != "no-cache" {
		t.Errorf("metadata %v does not describe the headers", metadata)
	}
	if issues, _ := metadata["Issues"].([]any); len(issues) != 2 {
		t.Errorf("Issues %v, want the shared-cache and the Pragma finding", metadata["Issues"])
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CacheControlTest.New(), "login_form_s_maxage.http"))
	if metadata["HasPasswordField"] != true || metadata["SharedMaxAge"] != float64(300) || metadata["MaxAge"] != float64(-1) {
		t.Errorf("metadata %v does not describe the login form", metadata)
	}
}
