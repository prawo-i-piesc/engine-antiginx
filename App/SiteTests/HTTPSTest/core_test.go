package HTTPSTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"net/url"
	"testing"
)

// run grades a response whose final request went to the given address, or one with no
// request at all when it is empty.
func run(t *testing.T, address string) SiteTests.TestResult {
	t.Helper()
	response := &http.Response{Header: http.Header{}}
	if address != "" {
		target, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		response.Request = &http.Request{URL: target}
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: response})
}

func TestHTTPSGrading(t *testing.T) {
	cases := map[string]SiteTests.ThreatLevel{
		"https://example.com/": SiteTests.None,
		"http://example.com/":  SiteTests.Medium,
		"":                     SiteTests.Info,
	}
	for address, want := range cases {
		if got := run(t, address).ThreatLevel; got != want {
			t.Errorf("%q graded %v, want %v", address, got, want)
		}
	}
}
