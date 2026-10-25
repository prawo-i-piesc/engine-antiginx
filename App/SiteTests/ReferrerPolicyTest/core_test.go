package ReferrerPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given Referrer-Policy value, or none when it is empty.
func run(value string) SiteTests.TestResult {
	header := http.Header{}
	if value != "" {
		header.Set("Referrer-Policy", value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestReferrerPolicyGrading(t *testing.T) {
	cases := []struct {
		value    string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"", SiteTests.Medium, "Missing Referrer-Policy header"},
		{"no-referrer", SiteTests.None, "excellent privacy protection"},
		{"strict-origin", SiteTests.None, "strong privacy protection"},
		{"strict-origin-when-cross-origin", SiteTests.None, "W3C recommended"},
		{"origin", SiteTests.Info, "basic privacy protection"},
		{"origin-when-cross-origin", SiteTests.Info, "good balance"},
		{"same-origin", SiteTests.Low, "limited privacy protection"},
		{"no-referrer-when-downgrade", SiteTests.Medium, "weak privacy protection"},
		{"unsafe-url", SiteTests.High, "WARNING: Contains 'unsafe-url'"},
		{"bogus", SiteTests.High, "Invalid Referrer-Policy values detected: bogus."},
		{"bogus, Weird", SiteTests.High, "Invalid Referrer-Policy values detected: bogus, Weird."},
		{"no-referrer, unsafe-url", SiteTests.High, "'unsafe-url' (no-referrer, unsafe-url)"},
		{"origin, same-origin, strict-origin", SiteTests.None, "Consider simplifying"},
		{",", SiteTests.Medium, "No valid Referrer-Policy found"},
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
	if present := run("no-referrer"); present.Certainty != Certainty {
		t.Errorf("present header reported certainty %d, want %d", present.Certainty, Certainty)
	}
}
