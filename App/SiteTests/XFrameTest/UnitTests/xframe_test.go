package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"Engine-AntiGinx/App/SiteTests/XFrameTest"
	"testing"
)

func TestXFrameFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_headers.http", SiteTests.Medium, []string{"No clickjacking protection", "No frame protection headers detected", "allowed from any source"}},
		{"invalid_value.http", SiteTests.Medium, []string{"No clickjacking protection", "X-Frame-Options header is present", "allowed from any source"}},
		// Current browsers ignore ALLOW-FROM, so on its own it protects nothing
		{"allow_from.http", SiteTests.Medium, []string{"No clickjacking protection", "ALLOW-FROM, which current browsers ignore", "allowed from any source"}},
		{"deny.http", SiteTests.None, []string{"Excellent clickjacking protection", "X-Frame-Options header is present", "completely blocked"}},
		{"sameorigin.http", SiteTests.Info, []string{"Good clickjacking protection", "restricted to same origin"}},
		{"frame_ancestors_none.http", SiteTests.None, []string{"Excellent clickjacking protection", "frame-ancestors directive is configured", "completely blocked"}},
		// An empty source list matches no ancestor
		{"frame_ancestors_empty.http", SiteTests.None, []string{"Excellent clickjacking protection", "completely blocked"}},
		{"frame_ancestors_partner.http", SiteTests.Low, []string{"Limited clickjacking protection", "restricted to specific domains"}},
		// Broad sources admit every site, whatever else is listed next to them
		{"frame_ancestors_wildcard.http", SiteTests.Medium, []string{"No clickjacking protection", "frame-ancestors directive is configured", "allowed from any source"}},
		{"frame_ancestors_https_scheme.http", SiteTests.Medium, []string{"No clickjacking protection", "allowed from any source"}},
		{"frame_ancestors_self_and_wildcard.http", SiteTests.Medium, []string{"No clickjacking protection", "allowed from any source"}},
		// frame-ancestors takes precedence over X-Frame-Options in browsers that know both
		{"csp_overrides_xfo.http", SiteTests.Info, []string{"Both X-Frame-Options and CSP frame-ancestors headers are present", "restricted to same origin"}},
		{"allow_from_with_frame_ancestors.http", SiteTests.Low, []string{"Both X-Frame-Options and CSP frame-ancestors headers are present", "restricted to specific domains"}},
		// A policy without frame-ancestors leaves the decision to X-Frame-Options
		{"csp_without_frame_ancestors.http", SiteTests.Info, []string{"X-Frame-Options header is present", "restricted to same origin"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, XFrameTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}
