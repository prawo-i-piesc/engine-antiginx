package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/CrossOriginTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"strings"
	"testing"
)

func TestCrossOriginFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_headers.http", SiteTests.High, []string{"No cross-origin security headers found"}},
		// Headers switched off protect no more than absent ones
		{"all_permissive.http", SiteTests.High, []string{
			"present but none is set to a protective value",
			"isolation is not effective",
			"COEP header has permissive value",
			"CORP header allows cross-origin access",
			"COOP header allows unsafe cross-origin access"}},
		{"only_coop.http", SiteTests.Medium, []string{"Basic protection level", "Missing headers: Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy"}},
		{"coop_and_corp.http", SiteTests.Low, []string{"Moderate protection level", "isolation is not effective", "Missing headers: Cross-Origin-Embedder-Policy."}},
		{"coop_unsafe_none.http", SiteTests.Low, []string{"Moderate protection level", "isolation is not effective", "COOP header allows unsafe cross-origin access"}},
		// Popups keep a reference to the page, so it is not isolated
		{"coop_allow_popups.http", SiteTests.Info, []string{"Good protection level", "isolation is not effective", "same-origin-allow-popups"}},
		{"cross_origin_resource.http", SiteTests.Info, []string{"Good protection level", "isolation is effective", "CORP header allows cross-origin access"}},
		{"invalid_corp.http", SiteTests.Info, []string{"Good protection level", "isolation is effective", "CORP header has invalid value"}},
		{"fully_isolated.http", SiteTests.None, []string{"Excellent protection level", "isolation is effective"}},
		{"credentialless.http", SiteTests.None, []string{"Excellent protection level", "isolation is effective"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			result := UnitTestKit.RunResponse(t, CrossOriginTest.New(), c.fixture)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
		})
	}
}

// Isolation needs COEP require-corp or credentialless together with COOP same-origin.
func TestCrossOriginIsolation(t *testing.T) {
	cases := map[string]bool{
		"fully_isolated.http":        true,
		"credentialless.http":        true,
		"cross_origin_resource.http": true,
		"coop_allow_popups.http":     false,
		"coop_unsafe_none.http":      false,
		"all_permissive.http":        false,
		"coop_and_corp.http":         false,
		"no_headers.http":            false,
	}
	for fixture, isolated := range cases {
		result := UnitTestKit.RunResponse(t, CrossOriginTest.New(), fixture)
		metadata := UnitTestKit.Metadata(t, result)
		if metadata["isolationEffective"] != isolated {
			t.Errorf("%s: isolationEffective %v, want %v", fixture, metadata["isolationEffective"], isolated)
		}
		if !isolated && strings.Contains(result.Description, "isolation is effective") {
			t.Errorf("%s: description claims isolation: %s", fixture, result.Description)
		}
	}
	if level := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CrossOriginTest.New(), "all_permissive.http"))["protectionLevel"]; level != "None" {
		t.Errorf("all-permissive headers reported as %v protection", level)
	}
}

func TestCrossOriginMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CrossOriginTest.New(), "fully_isolated.http"))
	if metadata["coepValue"] != "require-corp" || metadata["corpValue"] != "same-origin" || metadata["coopValue"] != "same-origin" {
		t.Errorf("metadata %v does not carry the header values", metadata)
	}
	if metadata["protectionLevel"] != "Excellent" {
		t.Errorf("metadata %v does not report excellent protection", metadata)
	}
	if issues, _ := metadata["securityIssues"].([]any); len(issues) != 0 {
		t.Errorf("fully isolated page reported issues %v", issues)
	}

	metadata = UnitTestKit.Metadata(t, UnitTestKit.RunResponse(t, CrossOriginTest.New(), "coop_and_corp.http"))
	missing, _ := metadata["missingHeaders"].([]any)
	if len(missing) != 1 || missing[0] != "Cross-Origin-Embedder-Policy" {
		t.Errorf("metadata %v does not report the missing embedder policy", metadata)
	}
}
