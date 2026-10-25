package PhishingURLTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/url"
	"strings"
	"testing"
)

// run grades one target URL.
func run(t *testing.T, raw string) SiteTests.TestResult {
	t.Helper()
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return New().RunTest(SiteTests.PreResponseTestParams{Target: target})
}

func TestPhishingGrading(t *testing.T) {
	cases := []struct {
		url       string
		want      SiteTests.ThreatLevel
		certainty int
		contains  string
	}{
		{"https://google.com/", SiteTests.None, 100, "known legitimate domain"},
		{"https://example.com/", SiteTests.None, 100, "URL carries no query parameters"},
		{"https://example.com/?a=1&b=2&c=3", SiteTests.None, 100, "No phishing indicators detected in the 3 URL parameter(s)"},
		{"https://gooogle.com/", SiteTests.Medium, 95, "gooogle.com appears to impersonate google (google.com)"},
		{"https://googel.com/", SiteTests.Medium, 95, "adjacent-letter transposition"},
		{"https://paypa1.com/login", SiteTests.High, 95, "impersonate paypal (paypal.com)"},
		{"https://gооgle.com/", SiteTests.Medium, 95, "homograph/confusable character"},
		{"https://example.com/?password=hunter2", SiteTests.Critical, 95, "credential parameter(s): password"},
		{"https://example.com/?password=", SiteTests.High, 95, "credential parameter(s): password"},
		{"https://user:pass@example.com/", SiteTests.Critical, 95, "credentials are embedded directly in the URL"},
		{"https://user@example.com/", SiteTests.High, 95, "credentials are embedded directly in the URL"},
		{"https://example.com/?next=javascript:alert(1)", SiteTests.Critical, 85, "dangerous scheme"},
		{"https://example.com/login?redirect=https://evil.com/", SiteTests.High, 85, "external redirect parameter(s): redirect"},
		{"https://example.com/?token=abc&ssn=1&card=2", SiteTests.High, 85, "sensitive data parameter(s)"},
		{"https://example.com/?email=a@b.com", SiteTests.Medium, 85, "victim identity parameter(s): email"},
		{"https://example.com/paypal/verify-account", SiteTests.High, 85, "brand keyword(s) used outside the hostname: paypal"},
		{"https://example.com/verify-account", SiteTests.Low, 85, "phishing-style path keyword(s)"},
		{"https://192.168.1.1/?email=a@b.com", SiteTests.High, 85, "IP literal used instead of a hostname"},
		{"https://example.com/?data=aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbg==", SiteTests.High, 85, "parameter(s) hiding encoded data: data"},
		// A lookalike domain asking for a password is escalated past either finding alone
		{"https://gooogle.com/?password=x", SiteTests.Critical, 95, "impersonate google"},
	}
	for _, c := range cases {
		result := run(t, c.url)
		if result.ThreatLevel != c.want || result.Certainty != c.certainty {
			t.Errorf("%s graded %v at %d%%, want %v at %d%%", c.url, result.ThreatLevel, result.Certainty, c.want, c.certainty)
		}
		if !strings.Contains(result.Description, c.contains) {
			t.Errorf("%s described as %q, want it to mention %q", c.url, result.Description, c.contains)
		}
	}
}

func TestCredentialValuesAreRedacted(t *testing.T) {
	result := run(t, "https://example.com/?password=hunter2")
	if strings.Contains(result.Description, "hunter2") {
		t.Errorf("description leaks the credential: %q", result.Description)
	}
}
