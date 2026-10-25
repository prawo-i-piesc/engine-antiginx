package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"slices"
	"testing"
)

// nvdFixtures are NVD's answers for the releases the fixtures disclose, keyed by the CPE each
// release is looked up by. The nginx and PHP files are real NVD responses retrieved on
// 2026-10-25; every other release has no CVE on record.
var nvdFixtures = map[string]string{
	"cpe:2.3:a:f5:nginx:1.18.0":         "nvd_real_nginx_1.18.0.json",
	"cpe:2.3:a:php:php:7.4.3":           "nvd_real_php_7.4.3.json",
	"cpe:2.3:a:wordpress:wordpress:9.9": "nvd_unscored_only.json",
}

func TestServerHeaderFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_disclosure.http", SiteTests.None, []string{"No server technology information disclosed"}},
		// NVD's most severe CVE against nginx 1.18.0 is rated HIGH (CVSS 3.1, 7.8): High, not
		// Critical, however many HIGH CVEs there are
		{"nginx_version.http", SiteTests.High, []string{
			"1 header exposes server information",
			"NVD records 6 CVE(s) affecting Nginx 1.18.0; the most severe are rated HIGH (CVSS base score 7.8): CVE-2022-41741, CVE-2021-23017, CVE-2023-44487, CVE-2021-3618, CVE-2022-41742.",
		}},
		// PHP 7.4.3 has CVEs NVD rates CRITICAL
		{"php_version.http", SiteTests.Critical, []string{"NVD records 30 CVE(s) affecting PHP 7.4.3; the most severe are rated CRITICAL (CVSS base score 9.8)"}},
		{"two_headers.http", SiteTests.Critical, []string{"2 headers expose server information", "Detected technologies: Nginx, PHP"}},
		// Without a release number no CVE can be attributed: only the disclosure counts
		{"nginx_without_version.http", SiteTests.Info, []string{"No release number that NVD can be searched by is disclosed for Nginx"}},
		// A disclosed release is information an attacker looks up, so at least Low
		{"release_without_cves.http", SiteTests.Low, []string{"NVD records no CVE affecting Nginx 1.29.0."}},
		{"unscored_release.http", SiteTests.Low, []string{"NVD records 2 CVE(s) affecting WordPress 9.9, none of them scored with CVSS yet."}},
		// Cache headers name no release, so only the amount of disclosure counts
		{"cache_layers.http", SiteTests.Low, []string{"Varnish Cache", "no CVE is attributed to it"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
			result := UnitTestKit.RunResponse(t, ServerHeaderTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// Only disclosed releases are looked up, each by its CPE; a technology without a release
// number costs no NVD request at all.
func TestServerHeaderQueriesNVD(t *testing.T) {
	nvd := UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
	UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "two_headers.http")
	if got := nvd.Searches(); !slices.Equal(got, []string{"cpe:2.3:a:f5:nginx:1.18.0", "cpe:2.3:a:php:php:7.4.3"}) {
		t.Errorf("searched NVD for %q, want the CPEs of nginx 1.18.0 and PHP 7.4.3", got)
	}

	silent := UnitTestKit.ServeNVD(t, nvdFixtures, "nvd_empty.json")
	UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "nginx_without_version.http")
	if got := silent.Searches(); len(got) != 0 {
		t.Errorf("searched NVD for %q although no release was disclosed", got)
	}
}

// An unreachable NVD costs only the CVE half of the verdict: the disclosed release is still
// graded for what it gives away, and the description says the CVEs could not be checked.
func TestServerHeaderWithoutNVD(t *testing.T) {
	UnitTestKit.ServeNVD(t, nil, "")
	result := UnitTestKit.RunResponse(t, ServerHeaderTest.New(), "nginx_version.http")
	UnitTestKit.Expect(t, result, SiteTests.Low, "The NVD lookup for Nginx 1.18.0 failed")
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

	releases, _ := metadata["vulnerabilities"].([]any)
	if len(releases) != 2 {
		t.Fatalf("vulnerabilities %v, want one entry per disclosed release", metadata["vulnerabilities"])
	}
	nginx := releases[0].(map[string]any)
	if nginx["cpe"] != "cpe:2.3:a:f5:nginx:1.18.0" || nginx["cve_count"] != float64(6) || nginx["max_severity"] != "HIGH" ||
		nginx["max_score"] != 7.8 || nginx["risk_level"] != "HIGH" {
		t.Errorf("nginx release reported as %v", nginx)
	}
	top := nginx["most_severe"].([]any)[0].(map[string]any)
	if top["id"] != "CVE-2022-41741" || top["score"] != 7.8 || top["cvss_version"] != "3.1" || top["scored_by"] != "nvd@nist.gov" {
		t.Errorf("most severe nginx CVE reported as %v", top)
	}
	if php := releases[1].(map[string]any); php["max_severity"] != "CRITICAL" || php["risk_level"] != "CRITICAL" {
		t.Errorf("PHP release reported as %v", php)
	}
}
