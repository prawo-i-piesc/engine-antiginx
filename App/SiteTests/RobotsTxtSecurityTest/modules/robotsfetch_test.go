package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var testFetcher = Fetcher{
	DangerousPatterns: map[string]string{
		`/admin`:    "Administrative Interface",
		`/wp-admin`: "Administrative Interface",
		`/api`:      "API Endpoint",
		`/api-docs`: "API Documentation",
		`/test`:     "Development Path",
		`/backup`:   "Backup Location",
		`.sql`:      "Database Dump",
	},
	Timeout:      2 * time.Second,
	MaxBodyBytes: 1024 * 1024,
}

func TestParseRobotsReadsOnlyAllowAndDisallow(t *testing.T) {
	rules := parseRobots(`
# comment line
User-agent: *
Disallow: /admin/   # trailing comment
disallow: /admin/
ALLOW: /public
Disallow:
Sitemap: https://example.com/sitemap.xml
Crawl-delay: 10
`)
	want := []rawRule{{DirectiveDisallow, "/admin/"}, {DirectiveAllow, "/public"}}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules %v, want %v", len(rules), rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d: got %v, want %v", i, rules[i], want[i])
		}
	}
}

func TestMatchPrefersLongestPattern(t *testing.T) {
	analysis := testFetcher.match(parseRobots("Disallow: /api-docs/\nDisallow: /api/v1/"), RobotsAnalysis{})
	if analysis.TotalDangerous != 2 {
		t.Fatalf("got %d dangerous rules, want 2", analysis.TotalDangerous)
	}
	if got := analysis.DangerousRules[0].Category; got != "API Documentation" {
		t.Errorf("/api-docs/ categorised as %q, want API Documentation", got)
	}
	if got := analysis.DangerousRules[1].Category; got != "API Endpoint" {
		t.Errorf("/api/v1/ categorised as %q, want API Endpoint", got)
	}
}

func TestMatchWildcardExtension(t *testing.T) {
	analysis := testFetcher.match(parseRobots("Disallow: /*.sql$"), RobotsAnalysis{})
	if analysis.TotalDangerous != 1 || analysis.DangerousRules[0].Category != "Database Dump" {
		t.Fatalf("/*.sql$ not reported as a database dump: %+v", analysis.DangerousRules)
	}
}

func TestAllowCarveOutIsNotExposure(t *testing.T) {
	analysis := testFetcher.match(parseRobots("Disallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php"), RobotsAnalysis{RobotsAccessible: true})
	if analysis.TotalDangerous != 2 || analysis.TotalExposed != 0 {
		t.Fatalf("got %d dangerous / %d exposed, want 2 / 0", analysis.TotalDangerous, analysis.TotalExposed)
	}
	if got := EvaluateThreat(analysis); got != SiteTests.Info {
		t.Errorf("WordPress default robots.txt graded %v, want Info", got)
	}
}

func TestAllowOfSensitivePathIsLow(t *testing.T) {
	analysis := testFetcher.match(parseRobots("Disallow: /\nAllow: /admin/"), RobotsAnalysis{RobotsAccessible: true})
	if analysis.TotalExposed != 1 {
		t.Fatalf("got %d exposed, want 1", analysis.TotalExposed)
	}
	if got := EvaluateThreat(analysis); got != SiteTests.Low {
		t.Errorf("exposed admin graded %v, want Low", got)
	}
}

// The level follows the kind of finding, never how many rules there are.
func TestEvaluateThreatIgnoresCount(t *testing.T) {
	cases := []struct {
		analysis RobotsAnalysis
		want     SiteTests.ThreatLevel
	}{
		{RobotsAnalysis{RobotsAccessible: true}, SiteTests.None},
		{RobotsAnalysis{RobotsAccessible: true, TotalDangerous: 1}, SiteTests.Info},
		{RobotsAnalysis{RobotsAccessible: true, TotalDangerous: 50}, SiteTests.Info},
		{RobotsAnalysis{RobotsAccessible: true, TotalDangerous: 1, TotalExposed: 1}, SiteTests.Low},
		{RobotsAnalysis{RobotsAccessible: true, TotalDangerous: 50, TotalExposed: 20}, SiteTests.Low},
		{RobotsAnalysis{TotalDangerous: 20, TotalExposed: 5}, SiteTests.None},
	}
	for _, c := range cases {
		if got := EvaluateThreat(c.analysis); got != c.want {
			t.Errorf("%+v graded %v, want %v", c.analysis, got, c.want)
		}
	}
}

func TestAnalyzeFetchesRobotsTxt(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /blog\n"))
	}))
	defer srv.Close()

	analysis := testFetcher.Analyze(srv.URL)
	if !analysis.RobotsAccessible || analysis.TotalRules != 3 || analysis.TotalDangerous != 2 {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
}

func TestAnalyzeMissingRobotsTxt(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	analysis := testFetcher.Analyze(srv.URL)
	if analysis.RobotsAccessible {
		t.Fatal("404 robots.txt reported as accessible")
	}
	if got := EvaluateThreat(analysis); got != SiteTests.None {
		t.Errorf("missing robots.txt graded %v, want None", got)
	}
}
