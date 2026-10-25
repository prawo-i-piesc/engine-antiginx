package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"slices"
	"testing"
)

// nvdFixtures are the prepared NVD answers for the technologies the fixtures disclose; every
// other technology has no known vulnerabilities.
var nvdFixtures = map[string]string{
	"nginx": "nvd_nginx_critical.json",
	"php":   "nvd_php_medium.json",
}

func TestServerHeaderFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_disclosure.http", SiteTests.None, []string{"No server technology information disclosed"}},
		// The banner names a release with a critical CVE on record
		{"nginx_version.http", SiteTests.Critical, []string{"1 header exposes server information", "Detected technologies: Nginx"}},
		// X-Powered-By names a release with medium CVEs only
		{"php_version.http", SiteTests.Medium, []string{"PHP"}},
		// Cache headers name no release, so only the amount of disclosure counts
		{"cache_layers.http", SiteTests.Low, []string{"Varnish Cache"}},
		// The count is written as a number, and technologies are listed in header order
		{"two_headers.http", SiteTests.Critical, []string{"2 headers expose server information", "Detected technologies: Nginx, PHP"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
			result := UnitTestKit.RunResponse(t, ServerHeaderTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// Disclosed technologies are looked up under the names NVD files them by.
func TestServerHeaderQueriesNVD(t *testing.T) {
	nvd := UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
	UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "nginx_version.http")
	if got := nvd.Searches(); !slices.Equal(got, []string{"nginx"}) {
		t.Errorf("searched NVD for %q, want [nginx]", got)
	}
}

// An unreachable NVD costs only the CVE half of the verdict: a widely attacked server named in
// the banner is still graded on its own.
func TestServerHeaderWithoutNVD(t *testing.T) {
	UnitTestKit.ServeNVD(t, nil, "")
	result := UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "nginx_version.http")
	UnitTestKit.Expect(t, result, SiteTests.High, "Nginx")
}

func TestServerHeaderMetadata(t *testing.T) {
	UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "two_headers.http"))

	headers, _ := metadata["exposed_headers"].([]any)
	if len(headers) != 2 || headers[0] != "Server" || headers[1] != "X-Powered-By" {
		t.Errorf("exposed headers %v, want [Server X-Powered-By]", metadata["exposed_headers"])
	}
	stack, _ := metadata["technology_stack"].(map[string]any)
	if stack["Nginx"] != "1.18.0" || stack["PHP"] != "7.4.3" {
		t.Errorf("technology stack %v lacks the disclosed releases", stack)
	}
	if metadata["total_exposures"] != float64(2) {
		t.Errorf("total exposures %v, want 2", metadata["total_exposures"])
	}
}
