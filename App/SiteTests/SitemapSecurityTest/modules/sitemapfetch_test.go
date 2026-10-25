package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testFetcher = Fetcher{
	DangerousPatterns: map[string]string{
		`/admin`:    "Administrative Interface",
		`/api`:      "API Endpoint",
		`/api-docs`: "API Documentation",
		`/test`:     "Development Path",
		`/backup`:   "Backup Location",
	},
	Timeout:      2 * time.Second,
	MaxBodyBytes: 1024 * 1024,
}

var testGrader = Grader{Thresholds: SiteTests.CountThresholds{LowMax: 2, MediumMax: 5, HighMax: 10}}

func TestMatchUsesPathAndMostSpecificPattern(t *testing.T) {
	analysis := testFetcher.match([]string{
		"https://example.com/api-docs/index.html",
		"https://test.example.com/blog",
		"https://example.com/testimonials",
		"https://example.com/admin/",
		"https://example.com/admin/",
	}, SitemapAnalysis{DangerousPaths: []SitemapPath{}})

	if analysis.TotalURLs != 5 || analysis.TotalDangerous != 2 {
		t.Fatalf("got %d URLs / %d dangerous, want 5 / 2: %+v", analysis.TotalURLs, analysis.TotalDangerous, analysis.DangerousPaths)
	}
	if got := analysis.DangerousPaths[0]; got.Pattern != "/api-docs" || got.Category != "API Documentation" {
		t.Errorf("/api-docs/ matched as %+v, want the /api-docs pattern", got)
	}
	if got := analysis.DangerousPaths[1].URL; got != "https://example.com/admin/" {
		t.Errorf("second finding is %q, want the admin URL reported once", got)
	}
}

func TestMetadataSerializes(t *testing.T) {
	analysis := testFetcher.match([]string{"https://example.com/backup/db.zip"}, SitemapAnalysis{SitemapAccessible: true})
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"sitemap_accessible":true`, `"total_urls":1`, `"total_dangerous":1`, `"category":"Backup Location"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("metadata %s lacks %s", encoded, key)
		}
	}
}

func TestAnalyzeFetchesSitemap(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sitemap.xml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<urlset><url><loc>
			https://example.com/admin/login
		</loc></url><url><loc>https://example.com/about</loc></url></urlset>`))
	}))
	defer server.Close()

	analysis := testFetcher.Analyze(server.URL)
	if !analysis.SitemapAccessible || analysis.TotalURLs != 2 || analysis.TotalDangerous != 1 {
		t.Fatalf("got %+v, want an accessible sitemap with 2 URLs and 1 dangerous path", analysis)
	}
}

func TestEvaluateThreatThresholds(t *testing.T) {
	cases := map[int]SiteTests.ThreatLevel{0: SiteTests.None, 2: SiteTests.Low, 3: SiteTests.Medium, 10: SiteTests.High, 11: SiteTests.Critical}
	for count, want := range cases {
		if got := testGrader.EvaluateThreat(SitemapAnalysis{SitemapAccessible: true, TotalDangerous: count}); got != want {
			t.Errorf("%d dangerous paths graded %v, want %v", count, got, want)
		}
	}
	if got := testGrader.EvaluateThreat(SitemapAnalysis{TotalDangerous: 20}); got != SiteTests.None {
		t.Errorf("inaccessible sitemap graded %v, want None", got)
	}
}

func TestDescribeIsStable(t *testing.T) {
	analysis := testFetcher.match([]string{
		"https://example.com/test/a", "https://example.com/admin/", "https://example.com/backup/x",
	}, SitemapAnalysis{SitemapAccessible: true})
	first := Describe(analysis)
	for range 20 {
		if Describe(analysis) != first {
			t.Fatal("description changed between runs")
		}
	}
	if strings.Index(first, "Administrative") > strings.Index(first, "Backup") {
		t.Errorf("categories not sorted:\n%s", first)
	}
}
