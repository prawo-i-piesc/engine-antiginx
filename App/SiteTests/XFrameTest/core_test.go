package XFrameTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given X-Frame-Options and Content-Security-Policy
// values, leaving out the empty ones.
func run(xframe, csp string) SiteTests.TestResult {
	header := http.Header{}
	if xframe != "" {
		header.Set("X-Frame-Options", xframe)
	}
	if csp != "" {
		header.Set("Content-Security-Policy", csp)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestFrameGrading(t *testing.T) {
	cases := []struct {
		xframe, csp string
		want        SiteTests.ThreatLevel
		embedding   string
	}{
		{"", "", SiteTests.Medium, "allowed"},
		{"DENY", "", SiteTests.None, "blocked"},
		{"sameorigin", "", SiteTests.Info, "same-origin"},
		{"ALLOW-FROM https://a.com", "", SiteTests.Medium, "allowed"}, // ignored by current browsers,
		{"bogus", "", SiteTests.Medium, "allowed"},
		{"", "frame-ancestors 'none'", SiteTests.None, "blocked"},
		{"", "frame-ancestors 'self'", SiteTests.Info, "same-origin"},
		{"", "frame-ancestors 'self' https://a.com", SiteTests.Low, "limited"},
		{"", "frame-ancestors https:", SiteTests.Medium, "allowed"},
		{"", "frame-ancestors *", SiteTests.Medium, "allowed"},
		// frame-ancestors overrides X-Frame-Options in every current browser
		{"DENY", "frame-ancestors *", SiteTests.Medium, "allowed"},
		{"", "default-src 'self'", SiteTests.Medium, "allowed"},
	}
	for _, c := range cases {
		result := run(c.xframe, c.csp)
		if result.ThreatLevel != c.want {
			t.Errorf("%q/%q graded %v, want %v", c.xframe, c.csp, result.ThreatLevel, c.want)
		}
		if got := result.Metadata.(FrameAnalysis).Embedding; got != c.embedding {
			t.Errorf("%q/%q embedding %q, want %q", c.xframe, c.csp, got, c.embedding)
		}
	}
}

func TestDescriptionNamesMechanism(t *testing.T) {
	cases := map[[2]string]string{
		{"DENY", ""}:                       "X-Frame-Options header is present - iframe embedding is completely blocked",
		{"", "frame-ancestors 'self'"}:     "Content-Security-Policy frame-ancestors directive is configured",
		{"DENY", "frame-ancestors 'none'"}: "Both X-Frame-Options and CSP frame-ancestors headers are present",
		{"", ""}:                           "No frame protection headers detected - iframe embedding is allowed from any source",
	}
	for headers, want := range cases {
		if got := run(headers[0], headers[1]).Description; !strings.Contains(got, want) {
			t.Errorf("%q described as %q, want it to mention %q", headers, got, want)
		}
	}
}

func TestMetadataRecordsHeaders(t *testing.T) {
	analysis := run(" sameorigin ", "default-src 'self'; frame-ancestors 'self' https://a.com").Metadata.(FrameAnalysis)
	if analysis.XFrameOptions != "SAMEORIGIN" || !analysis.XFrameValid || analysis.FrameAncestors != "'self' https://a.com" {
		t.Errorf("analysis %+v does not record both headers", analysis)
	}
}
