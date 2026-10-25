package PermissionsPolicyTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"strings"
	"testing"
)

// run grades a response carrying the given Permissions-Policy value, or none when it is empty.
func run(value string) SiteTests.TestResult {
	header := http.Header{}
	if value != "" {
		header.Set("Permissions-Policy", value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestPermissionsPolicyGrading(t *testing.T) {
	cases := []struct {
		value    string
		want     SiteTests.ThreatLevel
		contains string
	}{
		{"", SiteTests.High, "Missing Permissions-Policy header"},
		{"camera=(), microphone=()", SiteTests.Low, "Properly restricts features: camera, microphone"},
		{"geolocation=*", SiteTests.Medium, "Uses wildcards for features: geolocation"},
		{"camera=*, microphone=*, geolocation=*, usb=*", SiteTests.High, "Allows dangerous features: camera, microphone, geolocation"},
		{`camera=(self), microphone=("self"), payment=(), usb=(), fullscreen=(self)`, SiteTests.Medium, "Allows dangerous features: microphone"},
		{"fullscreen=*, autoplay=(self https://a.com), x", SiteTests.Medium, "Allows suspicious features: fullscreen"},
		{"camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=()", SiteTests.None, "Excellent security configuration"},
		{"interest-cohort=()", SiteTests.Low, "configured with 1 directives"},
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
	if present := run("camera=()"); present.Certainty != Certainty {
		t.Errorf("present header reported certainty %d, want %d", present.Certainty, Certainty)
	}
}
