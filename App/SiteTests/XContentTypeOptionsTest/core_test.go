package XContentTypeOptionsTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given X-Content-Type-Options value, or none when it is empty.
func run(value string) SiteTests.TestResult {
	header := http.Header{}
	if value != "" {
		header.Set("X-Content-Type-Options", value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestXContentTypeOptionsGrading(t *testing.T) {
	cases := []struct {
		value    string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"", SiteTests.Low, "Missing X-Content-Type-Options header"},
		{"nosniff", SiteTests.None, "properly configured with 'nosniff'"},
		{" NoSniff ", SiteTests.None, "properly configured"},
		{"sniff", SiteTests.Low, "invalid value 'sniff'"},
		// Browsers act on the first value only
		{"nosniff, nosniff", SiteTests.None, "properly configured with 'nosniff'"},
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
	if present := run("nosniff"); present.Certainty != Certainty {
		t.Errorf("present header reported certainty %d, want %d", present.Certainty, Certainty)
	}
}
