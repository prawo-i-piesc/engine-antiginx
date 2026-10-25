package UnitTests

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"slices"
	"testing"
	"time"
)

// The CVSS qualitative severity rating scale, as FIRST defines it for CVSS 3.x and 4.0 and as
// NVD applies it to CVSS 2.0, which has three bands only.
func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		version string
		score   float64
		want    string
	}{
		{"3.1", 0.0, CVE.SeverityNone},
		{"3.1", 0.1, CVE.SeverityLow},
		{"3.1", 3.9, CVE.SeverityLow},
		{"3.1", 4.0, CVE.SeverityMedium},
		{"3.1", 6.9, CVE.SeverityMedium},
		{"3.1", 7.0, CVE.SeverityHigh},
		{"3.1", 8.9, CVE.SeverityHigh},
		{"3.1", 9.0, CVE.SeverityCritical},
		{"3.1", 10.0, CVE.SeverityCritical},
		{"3.0", 9.8, CVE.SeverityCritical},
		{"4.0", 0.0, CVE.SeverityNone},
		{"4.0", 6.9, CVE.SeverityMedium},
		{"4.0", 9.2, CVE.SeverityCritical},
		{"2.0", 0.0, CVE.SeverityLow},
		{"2.0", 3.9, CVE.SeverityLow},
		{"2.0", 4.0, CVE.SeverityMedium},
		{"2.0", 6.9, CVE.SeverityMedium},
		{"2.0", 7.0, CVE.SeverityHigh},
		{"2.0", 10.0, CVE.SeverityHigh}, // CVSS 2.0 has no Critical
	}
	for _, c := range cases {
		if got := CVE.SeverityFromScore(c.version, c.score); got != c.want {
			t.Errorf("CVSS %s score %.1f rated %q, want %q", c.version, c.score, got, c.want)
		}
	}
}

// Real NVD data: what NVD recorded against nginx 1.18.0 on 2026-10-25. Every CVE is rated by
// NVD's own scoring, the most severe is HIGH 7.8, and the count of HIGH CVEs does not turn
// the release Critical.
func TestRealNginxRelease(t *testing.T) {
	nvd := UnitTestKit.ServeNVD(t, map[string]string{"cpe:2.3:a:f5:nginx:1.18.0": "nvd_real_nginx_1.18.0.json"}, "nvd_empty.json")

	assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("Nginx", "1.18.0")
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	if assessment.MatchedBy != CVE.MatchedByCPE || assessment.CPE != "cpe:2.3:a:f5:nginx:1.18.0" {
		t.Errorf("matched by %q (%q), want a CPE match", assessment.MatchedBy, assessment.CPE)
	}
	if got := nvd.Searches(); !slices.Equal(got, []string{"cpe:2.3:a:f5:nginx:1.18.0"}) {
		t.Errorf("searched %q, want the CPE of the release", got)
	}
	if assessment.CVECount != 6 || assessment.HighSeverity != 5 || assessment.MediumSeverity != 1 || assessment.CriticalSeverity != 0 {
		t.Errorf("counted %d CVEs (%d critical, %d high, %d medium), want 6 (0, 5, 1)",
			assessment.CVECount, assessment.CriticalSeverity, assessment.HighSeverity, assessment.MediumSeverity)
	}
	if assessment.MaxSeverity != CVE.SeverityHigh || assessment.MaxScore != 7.8 || assessment.RiskLevel != CVE.SeverityHigh {
		t.Errorf("rated %s (max score %.1f, risk %s), want HIGH 7.8", assessment.MaxSeverity, assessment.MaxScore, assessment.RiskLevel)
	}
	if got := CVE.GetThreatLevelFromAssessment(assessment); got != 4 {
		t.Errorf("threat level %d, want 4 (High)", got)
	}

	byID := map[string]CVE.CVEResult{}
	for _, cve := range assessment.CVEs {
		byID[cve.ID] = cve
	}
	// NVD lists F5's CNA scoring (7.0) before its own (7.8); NVD's own is the one that counts
	if cve := byID["CVE-2022-41741"]; cve.Score != 7.8 || cve.ScoredBy != "nvd@nist.gov" || cve.CVSSVersion != "3.1" {
		t.Errorf("CVE-2022-41741 rated %.1f by %s under %s, want NVD's 7.8 under 3.1", cve.Score, cve.ScoredBy, cve.CVSSVersion)
	}
	// NVD has not scored it; F5 scored it under CVSS 4.0
	if cve := byID["CVE-2025-23419"]; cve.Severity != CVE.SeverityMedium || cve.CVSSVersion != "4.0" || cve.ScoredBy != "f5sirt@f5.com" {
		t.Errorf("CVE-2025-23419 rated %s under %s by %s, want MEDIUM under 4.0 by f5sirt@f5.com", cve.Severity, cve.CVSSVersion, cve.ScoredBy)
	}
	if cve := byID["CVE-2021-23017"]; cve.Status != "Modified" || !cve.Published.Equal(time.Date(2021, 6, 1, 13, 15, 7, 853000000, time.UTC)) || cve.Description == "" {
		t.Errorf("CVE-2021-23017 decoded as %+v", cve)
	}
}

// Real NVD data for PHP 7.4.3: several CVEs scored Critical by NVD under CVSS 3.1.
func TestRealPHPRelease(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"cpe:2.3:a:php:php:7.4.3": "nvd_real_php_7.4.3.json"}, "nvd_empty.json")

	assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("PHP", "7.4.3")
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}
	if assessment.CVECount != 30 || assessment.CriticalSeverity != 7 || assessment.HighSeverity != 9 ||
		assessment.MediumSeverity != 13 || assessment.LowSeverity != 1 {
		t.Errorf("counted %d CVEs (%d/%d/%d/%d), want 30 (7 critical, 9 high, 13 medium, 1 low)", assessment.CVECount,
			assessment.CriticalSeverity, assessment.HighSeverity, assessment.MediumSeverity, assessment.LowSeverity)
	}
	if assessment.RiskLevel != CVE.SeverityCritical || assessment.MaxScore != 9.8 {
		t.Errorf("rated %s %.1f, want CRITICAL 9.8", assessment.RiskLevel, assessment.MaxScore)
	}
}

// Prepared edge cases of how NVD publishes scores, each rated the way CVSS and NVD define.
func TestCVSSEdgeCases(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"cpe:2.3:a:f5:nginx:1.0.0": "nvd_cvss_edge_cases.json"}, "nvd_empty.json")

	assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("Nginx", "1.0.0")
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	want := map[string]struct {
		severity string
		score    float64
		version  string
	}{
		"CVE-2099-0001": {CVE.SeverityHigh, 7.5, "3.1"},     // NVD's High, not the CNA's Critical listed first
		"CVE-2099-0002": {CVE.SeverityHigh, 8.1, "3.1"},     // NVD's own 3.1 scoring over the CNA's 4.0
		"CVE-2099-0003": {CVE.SeverityHigh, 10.0, "2.0"},    // 10.0 under CVSS 2.0 is High
		"CVE-2099-0004": {CVE.SeverityMedium, 6.5, "3.1"},   // CNA-only scoring, rated from its score
		"CVE-2099-0005": {CVE.SeverityUnscored, 0, ""},      // Not scored by anyone: unrated, not Low
		"CVE-2099-0007": {CVE.SeverityNone, 0.0, "3.1"},     // 0.0 is None
		"CVE-2099-0008": {CVE.SeverityCritical, 9.8, "3.1"}, // Rated from the score, not a contradicting label
	}
	got := map[string]CVE.CVEResult{}
	for _, cve := range assessment.CVEs {
		got[cve.ID] = cve
	}
	if _, present := got["CVE-2099-0006"]; present {
		t.Error("a Rejected CVE was counted")
	}
	for id, expected := range want {
		cve, present := got[id]
		if !present {
			t.Errorf("%s missing", id)
			continue
		}
		if cve.Severity != expected.severity || cve.Score != expected.score || cve.CVSSVersion != expected.version {
			t.Errorf("%s rated %q %.1f under %q, want %q %.1f under %q", id, cve.Severity, cve.Score, cve.CVSSVersion,
				expected.severity, expected.score, expected.version)
		}
	}

	if assessment.CVECount != 7 || assessment.Unscored != 1 || assessment.MaxSeverity != CVE.SeverityCritical || assessment.MaxScore != 9.8 {
		t.Errorf("assessment %d CVEs, %d unscored, max %s %.1f; want 7, 1, CRITICAL 9.8",
			assessment.CVECount, assessment.Unscored, assessment.MaxSeverity, assessment.MaxScore)
	}
}

// CVSS rates each vulnerability on its own and defines no way to add several up, so many CVEs
// of one rating are still that rating.
func TestNoEscalationByCount(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{
		"cpe:2.3:a:php:php:1.0.0":     "nvd_five_low.json",
		"cpe:2.3:a:drupal:drupal:1.0": "nvd_three_medium.json",
	}, "nvd_empty.json")

	cases := map[string][2]string{
		"PHP":    {"1.0.0", CVE.SeverityLow},
		"Drupal": {"1.0", CVE.SeverityMedium},
	}
	for technology, c := range cases {
		assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities(technology, c[0])
		if err != nil {
			t.Fatalf("%s: %v", technology, err)
		}
		if assessment.RiskLevel != c[1] {
			t.Errorf("%s with %d CVEs rated %s, want %s", technology, assessment.CVECount, assessment.RiskLevel, c[1])
		}
	}
}

// A CVE that is known but not yet scored is unrated: it is not evidence of a Low.
func TestUnscoredAndEmpty(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"cpe:2.3:a:wordpress:wordpress:9.9": "nvd_unscored_only.json"}, "nvd_empty.json")

	unscored, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("WordPress", "9.9")
	if err != nil {
		t.Fatal(err)
	}
	if unscored.RiskLevel != CVE.RiskUnscored || unscored.Unscored != 2 || CVE.GetThreatLevelFromAssessment(unscored) != 1 {
		t.Errorf("unscored-only assessment rated %s (%d unscored, level %d), want UNSCORED, 2, 1",
			unscored.RiskLevel, unscored.Unscored, CVE.GetThreatLevelFromAssessment(unscored))
	}

	empty, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("WordPress", "10.0")
	if err != nil {
		t.Fatal(err)
	}
	if empty.RiskLevel != CVE.SeverityNone || CVE.GetThreatLevelFromAssessment(empty) != 0 {
		t.Errorf("release without CVEs rated %s (level %d), want NONE, 0", empty.RiskLevel, CVE.GetThreatLevelFromAssessment(empty))
	}
}

// A release is looked up by its CPE, so NVD answers with the CVEs whose affected-version
// ranges include it; without a concrete version or a verified CPE product it falls back to a
// keyword search. Rejected CVEs are always excluded.
func TestQueries(t *testing.T) {
	nvd := UnitTestKit.ServeNVD(t, nil, "nvd_empty.json")
	t.Setenv(CVE.APIKeyEnv, "fixture-api-key")

	client := CVE.NewCVEClient()
	calls := []struct {
		technology, version, search, matchedBy string
	}{
		{"Apache", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49", CVE.MatchedByCPE},
		{"Microsoft IIS", "10.0", "cpe:2.3:a:microsoft:internet_information_services:10.0", CVE.MatchedByCPE},
		{"Nginx", "", "nginx", CVE.MatchedByKeyword},
		{"Nginx", "detected", "nginx", CVE.MatchedByKeyword},
		{"Nginx", "1.18.0:*", "nginx 1.18.0:*", CVE.MatchedByKeyword}, // not a release number
		{"Strapi", "4.1.0", "strapi 4.1.0", CVE.MatchedByKeyword},     // no verified CPE product
	}
	for _, call := range calls {
		assessment, err := client.AssessTechnologyVulnerabilities(call.technology, call.version)
		if err != nil {
			t.Fatalf("%v: %v", call, err)
		}
		if assessment.MatchedBy != call.matchedBy {
			t.Errorf("%s %q matched by %s, want %s", call.technology, call.version, assessment.MatchedBy, call.matchedBy)
		}
	}

	searches := nvd.Searches()
	for i, call := range calls {
		if searches[i] != call.search {
			t.Errorf("%s %q searched %q, want %q", call.technology, call.version, searches[i], call.search)
		}
	}
	for _, request := range nvd.Requests() {
		if _, present := request.URL.Query()["noRejected"]; !present {
			t.Errorf("request %s does not exclude rejected CVEs", request.URL.RawQuery)
		}
		if request.Header.Get("apiKey") != "fixture-api-key" {
			t.Errorf("request %s does not carry the API key", request.URL.RawQuery)
		}
	}
	if got := nvd.Requests()[0].URL.Query().Get("resultsPerPage"); got != "2000" {
		t.Errorf("CPE lookup asks for %s results per page, want 2000", got)
	}
}

func TestFailures(t *testing.T) {
	UnitTestKit.ServeNVD(t, map[string]string{"cpe:2.3:a:php:php:5.0": "nvd_truncated.json", "cpe:2.3:a:php:php:6.0": ""}, "nvd_empty.json")

	for _, version := range []string{"5.0", "6.0"} {
		if assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities("PHP", version); err == nil {
			t.Errorf("PHP %s: got %+v, want an error", version, assessment)
		}
	}
}
