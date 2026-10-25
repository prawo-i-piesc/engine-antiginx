package UnitTests

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"slices"
	"testing"
	"time"
)

// A search that returns vulnerabilities scored under every CVSS version NVD uses, in the shape
// NVD 2.0 actually serves them: zone-less timestamps, a numeric CVSS 2.0 score, and the
// description inside a descriptions array.
func TestAssessmentOfMixedResults(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"nginx": "nvd_nginx_mixed.json"}, "nvd_empty.json")

	assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("Nginx", "")
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	if assessment.CVECount != 5 || assessment.HighSeverity != 2 || assessment.MediumSeverity != 2 || assessment.LowSeverity != 1 {
		t.Errorf("counted %d CVEs (%d high, %d medium, %d low), want 5 (2, 2, 1)",
			assessment.CVECount, assessment.HighSeverity, assessment.MediumSeverity, assessment.LowSeverity)
	}
	if assessment.MaxScore != 9.8 || assessment.RiskLevel != "CRITICAL" {
		t.Errorf("max score %v and risk %q, want 9.8 and CRITICAL", assessment.MaxScore, assessment.RiskLevel)
	}

	first := assessment.CVEs[0]
	if first.ID != "CVE-2099-0001" || first.Severity != "CRITICAL" || first.Description != "Prepared fixture: remote code execution in the nginx resolver." {
		t.Errorf("first CVE decoded as %+v", first)
	}
	if want := time.Date(2099, 1, 10, 12, 15, 7, 853000000, time.UTC); !first.Published.Equal(want) {
		t.Errorf("published %v, want %v", first.Published, want)
	}
	if !slices.Equal(first.References, []string{"https://fixture.antiginx.test/advisories/0001"}) {
		t.Errorf("references %v", first.References)
	}

	// The newest scoring decides: CVSS 3.1 over 2.0 for the first, 2.0 alone for the fourth
	if legacy := assessment.CVEs[3]; legacy.Severity != "MEDIUM" || legacy.Score != 5.0 {
		t.Errorf("CVSS 2.0 only vulnerability decoded as %s %v, want MEDIUM 5.0", legacy.Severity, legacy.Score)
	}
}

func TestRiskLevels(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{
		"lighttpd": "nvd_five_low.json",
		"tomcat":   "nvd_three_medium.json",
	}, "nvd_empty.json")

	cases := map[string]string{
		"lighttpd":        "MEDIUM", // five low severity CVEs together
		"tomcat":          "HIGH",   // three medium severity CVEs
		"unheard-of-tech": "NONE",
	}
	for technology, want := range cases {
		assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities(technology, "")
		if err != nil {
			t.Fatalf("%s: %v", technology, err)
		}
		if assessment.RiskLevel != want {
			t.Errorf("%s risk %q, want %q", technology, assessment.RiskLevel, want)
		}
		if got := CVE.GetThreatLevelFromAssessment(assessment); got < 0 || got > 5 {
			t.Errorf("%s threat level %d out of range", technology, got)
		}
	}
}

func TestSearchQuery(t *testing.T) {
	nvd := UnitTestKit.ServeNVD(t, nil, "nvd_empty.json")

	client := CVE.NewCVEClient()
	for _, call := range [][2]string{{"Apache", "2.4.49"}, {"Microsoft IIS", "detected"}, {"Strapi", ""}} {
		if _, err := client.AssessTechnologyVulnerabilities(call[0], call[1]); err != nil {
			t.Fatalf("%v: %v", call, err)
		}
	}

	// Known names map to NVD's own wording; "detected" is not a version
	want := []string{"apache http server 2.4.49", "internet information services", "strapi"}
	if got := nvd.Searches(); !slices.Equal(got, want) {
		t.Errorf("searched %q, want %q", got, want)
	}
}

func TestFailures(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"broken": "nvd_truncated.json", "overloaded": ""}, "nvd_empty.json")

	for _, technology := range []string{"broken", "overloaded"} {
		if assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities(technology, ""); err == nil {
			t.Errorf("%s: got %+v, want an error", technology, assessment)
		}
	}
}
