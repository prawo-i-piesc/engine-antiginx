package CrossOriginTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given COEP, CORP and COOP values, leaving out the empty
// ones.
func run(coep, corp, coop string) SiteTests.TestResult {
	header := http.Header{}
	for name, value := range map[string]string{
		"Cross-Origin-Embedder-Policy": coep,
		"Cross-Origin-Resource-Policy": corp,
		"Cross-Origin-Opener-Policy":   coop,
	} {
		if value != "" {
			header.Set(name, value)
		}
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestCrossOriginGrading(t *testing.T) {
	cases := []struct {
		coep, corp, coop string
		want             SiteTests.ThreatLevel
		level            string
	}{
		{"", "", "", SiteTests.Low, "None"},
		{"require-corp", "same-origin", "same-origin", SiteTests.None, "Excellent"},
		{"credentialless", "same-site", "same-origin-allow-popups", SiteTests.Info, "Good"},
		{"unsafe-none", "cross-origin", "unsafe-none", SiteTests.Low, "None"},
		{"require-corp", "", "", SiteTests.Low, "Basic"},
		{"", "same-origin", "same-origin", SiteTests.Low, "Moderate"},
		{"Require-Corp", "SAME-ORIGIN", "", SiteTests.Low, "Moderate"},
	}
	for _, c := range cases {
		result := run(c.coep, c.corp, c.coop)
		if result.ThreatLevel != c.want {
			t.Errorf("%q/%q/%q graded %v, want %v", c.coep, c.corp, c.coop, result.ThreatLevel, c.want)
		}
		if got := result.Metadata.(CrossOriginAnalysis).ProtectionLevel; got != c.level {
			t.Errorf("%q/%q/%q protection %q, want %q", c.coep, c.corp, c.coop, got, c.level)
		}
	}
}

func TestDescriptionNamesMissingHeaders(t *testing.T) {
	result := run("require-corp", "", "")
	for _, want := range []string{"Basic protection level", "Missing headers: Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy"} {
		if !strings.Contains(result.Description, want) {
			t.Errorf("description %q lacks %q", result.Description, want)
		}
	}
}

func TestCompleteConfigurationIsIsolated(t *testing.T) {
	analysis := run("require-corp", "same-origin", "same-origin").Metadata.(CrossOriginAnalysis)
	if !analysis.IsolationEffective || len(analysis.SecurityIssues) != 0 || len(analysis.RecommendedActions) != 0 {
		t.Errorf("complete configuration analysed as %+v", analysis)
	}
}
