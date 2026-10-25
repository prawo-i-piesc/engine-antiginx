package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/HTTPSTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"net/url"
	"testing"
)

// The verdict depends only on the scheme the response was served over, which each fixture
// sets with X-Fixture-URL.
func TestHTTPSFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"secure_https.http", SiteTests.None, []string{"secured with HTTPS protocol"}},
		{"https_custom_port.http", SiteTests.None, []string{"secured with HTTPS protocol"}},
		{"insecure_http.http", SiteTests.Medium, []string{"insecure HTTP protocol", "plaintext"}},
		// Browsers ignore HSTS received over plain HTTP, so the header changes nothing
		{"http_with_hsts_header.http", SiteTests.Medium, []string{"insecure HTTP protocol"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, HTTPSTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
			if result.Metadata != nil {
				t.Errorf("metadata %v, the test reports none", result.Metadata)
			}
		})
	}
}

// A fixture always carries the address it came from, so a response without one is built here.
func TestHTTPSWithoutServedAddress(t *testing.T) {
	target, _ := url.Parse("https://example.com/")
	responses := map[string]*http.Response{
		"no request":     {StatusCode: http.StatusOK, Header: http.Header{}},
		"no request URL": {StatusCode: http.StatusOK, Header: http.Header{}, Request: &http.Request{Method: http.MethodGet}},
	}
	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			result := HTTPSTest.New().Run(SiteTests.ScanContext{Target: target, Response: response})
			UnitTestKit.Expect(t, result, SiteTests.Info, "address the page was served from is unavailable")
		})
	}
}
