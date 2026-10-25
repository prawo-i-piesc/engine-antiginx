package HSTSTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given Strict-Transport-Security value, or none when it is empty.
func run(value string) SiteTests.TestResult {
	header := http.Header{}
	if value != "" {
		header.Set("Strict-Transport-Security", value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestHSTSGrading(t *testing.T) {
	cases := []struct {
		value    string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"", SiteTests.Low, "Missing HSTS header"},
		{"max-age=31536000; includeSubDomains; preload", SiteTests.None, "1 year max-age and includes: includeSubDomains, preload - Excellent"},
		{"max-age=31536000; includeSubDomains", SiteTests.Info, "Good security configuration"},
		{"max-age=20000000", SiteTests.Info, "7 months max-age - Acceptable"},
		{"max-age=60", SiteTests.Low, "60 seconds max-age - Weak"},
		{"includeSubDomains", SiteTests.Low, "missing or invalid max-age"},
		{"max-age=abc; preload", SiteTests.Low, "missing or invalid max-age"},
		{"MAX-AGE=63072000; INCLUDESUBDOMAINS", SiteTests.Info, "2 years max-age"},
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

func TestMissingHeaderIsCertain(t *testing.T) {
	result := run("")
	if result.Certainty != 100 || result.Metadata != nil || result.Name != TestName {
		t.Errorf("absent header gave %+v", result)
	}
	if present := run("max-age=60"); present.Certainty != Certainty {
		t.Errorf("present header reported certainty %d, want %d", present.Certainty, Certainty)
	}
}
