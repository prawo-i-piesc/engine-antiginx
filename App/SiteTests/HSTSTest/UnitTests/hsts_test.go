package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/HSTSTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"testing"
)

func TestHSTSFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"missing_header.http", SiteTests.Low, []string{"Missing HSTS header"}},
		{"weak_max_age.http", SiteTests.Low, []string{"300 seconds max-age", "Weak security configuration"}},
		{"missing_max_age.http", SiteTests.Low, []string{"missing or invalid max-age"}},
		{"six_months.http", SiteTests.Info, []string{"Acceptable security configuration"}},
		{"one_year_subdomains.http", SiteTests.Info, []string{"1 year max-age", "includeSubDomains", "Good security configuration"}},
		{"preload_ready.http", SiteTests.None, []string{"2 years max-age", "preload", "Excellent security configuration"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, HSTSTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

func TestHSTSMetadata(t *testing.T) {
	result := UnitTestKit.RunResponse(t, HSTSTest.New(), "preload_ready.http")
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["max_age"] != float64(63072000) || metadata["include_subdomains"] != true || metadata["preload"] != true {
		t.Errorf("metadata %v does not describe the header", metadata)
	}
}
