package CSPTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// run grades a response carrying the given Content-Security-Policy value, or none when it is
// empty.
func run(value string) SiteTests.TestResult {
	header := http.Header{}
	if value != "" {
		header.Set("Content-Security-Policy", value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestCSPGrading(t *testing.T) {
	cases := []struct {
		value    string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"", SiteTests.Critical, "Missing Content-Security-Policy header"},
		{"default-src 'none'; script-src 'self' 'nonce-abc'; object-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", SiteTests.None, "excellent protection level"},
		{"default-src 'self'", SiteTests.Medium, "weak protection level"},
		{"default-src *", SiteTests.High, "default-src wildcard undermines security policy"},
		{"script-src 'unsafe-eval'", SiteTests.High, "unsafe-eval permits eval()"},
		{"script-src 'unsafe-inline' *; object-src 'none'", SiteTests.High, "script-src unsafe-inline allows any inline scripts"},
	}
	for _, c := range cases {
		result := run(c.value)
		if result.ThreatLevel != c.want {
			t.Errorf("%q graded %v, want %v", c.value, result.ThreatLevel, c.want)
		}
		if !strings.Contains(result.Description, c.contains) {
			t.Errorf("%q described as %q, want it to mention %q", c.value, result.Description, c.contains)
		}
	}
}

// The missing directives come from a map, so they must be sorted for a report — and the
// recommendations it leads with — to be the same on every run.
func TestMissingDirectivesAreSorted(t *testing.T) {
	analysis := run("default-src 'self'").Metadata.(CSPAnalysis)
	if !slices.IsSorted(analysis.MissingDirectives) {
		t.Errorf("missing directives not sorted: %v", analysis.MissingDirectives)
	}
	if len(analysis.MissingDirectives) != 7 || len(analysis.RecommendedActions) != 7 {
		t.Errorf("got %d missing / %d recommendations, want 7 / 7", len(analysis.MissingDirectives), len(analysis.RecommendedActions))
	}
}

func TestMissingHeaderIsCertain(t *testing.T) {
	result := run("")
	if result.Certainty != 100 || result.Metadata != nil || result.Name != TestName {
		t.Errorf("absent header gave %+v", result)
	}
	if present := run("default-src 'self'"); present.Certainty != Certainty {
		t.Errorf("present header reported certainty %d, want %d", present.Certainty, Certainty)
	}
}
