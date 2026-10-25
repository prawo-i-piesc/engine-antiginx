package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"path/filepath"
	"testing"
)

// run serves sites/<name> and runs the test against its home page.
func run(t *testing.T, name string, options ...UnitTestKit.SiteOption) SiteTests.TestResult {
	t.Helper()
	site := UnitTestKit.ServeSite(t, filepath.Join("sites", name), options...)
	return UnitTestKit.RunTarget(t, SitemapSecurityTest.New(), site.URL+"/")
}

func TestSitemapSites(t *testing.T) {
	cases := []struct {
		site      string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_sitemap", SiteTests.None, []string{"not accessible or does not exist"}},
		{"clean", SiteTests.None, []string{"Sitemap.xml is secure", "among 5 URLs"}},
		// /testimonials, /devices, /templates... only begin with a dangerous fragment
		{"lookalike_paths", SiteTests.None, []string{"Sitemap.xml is secure", "among 7 URLs"}},
		// dev., api., admin. and staging. are hostnames, not paths
		{"dangerous_hostnames", SiteTests.None, []string{"Sitemap.xml is secure", "among 4 URLs"}},
		// A repeated <loc> is one URL, and each URL is counted once under its best fragment
		{"mixed_matches", SiteTests.Low, []string{"exposes 4 dangerous paths", "out of 5 total URLs", "Version Control: 1 exposed", "API Documentation: 1 exposed"}},
		// Every dangerous path is the same invitation to index it: Low, whatever the count
		{"admin_listed", SiteTests.Low, []string{"exposes 1 dangerous paths", "out of 4 total URLs", "Administrative Interface: 1 exposed", "https://shop.example/admin/login"}},
		{"several_listed", SiteTests.Low, []string{"exposes 4 dangerous paths", "out of 7 total URLs", "Backup Location: 1 exposed", "https://shop.example/backup/site-2026.zip"}},
		{"many_listed", SiteTests.Low, []string{"exposes 7 dangerous paths", "out of 9 total URLs", "Administrative Interface: 2 exposed", "API Documentation: 1 exposed"}},
		{"mass_listed", SiteTests.Low, []string{"exposes 12 dangerous paths", "out of 14 total URLs", "Administrative Interface: 4 exposed", "... and 1 more", "Backup Location: 2 exposed"}},
	}
	for _, c := range cases {
		t.Run(c.site, func(t *testing.T) {
			UnitTestKit.Expect(t, run(t, c.site), c.level, c.fragments...)
		})
	}
}

// A sitemap the server refuses to hand out exposes nothing to search engines either.
func TestForbiddenSitemapIsIgnored(t *testing.T) {
	result := run(t, "mass_listed", UnitTestKit.WithStatus("/sitemap.xml", http.StatusForbidden))
	UnitTestKit.Expect(t, result, SiteTests.None, "not accessible or does not exist")
}

// Categories are listed in alphabetical order, each with its URLs in sitemap order.
func TestDescriptionIsOrdered(t *testing.T) {
	want := "Sitemap.xml exposes 4 dangerous paths that should not be indexed by search engines (out of 5 total URLs):\n\n" +
		"• API Documentation: 1 exposed\n  - https://shop.example/api-docs/v1\n" +
		"• Administrative Interface: 1 exposed\n  - https://shop.example/admin/login\n" +
		"• Backup Location: 1 exposed\n  - /backups/2026-01-01.tar.gz\n" +
		"• Version Control: 1 exposed\n  - https://shop.example/.git/config\n"
	if got := run(t, "mixed_matches").Description; got != want {
		t.Errorf("description\n%s\nwant\n%s", got, want)
	}
}

func TestSitemapMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, run(t, "mixed_matches"))
	if metadata["sitemap_accessible"] != true || metadata["total_urls"] != float64(5) || metadata["total_dangerous"] != float64(4) {
		t.Errorf("metadata totals %v do not describe the sitemap", metadata)
	}

	paths, _ := metadata["dangerous_paths"].([]any)
	want := []map[string]any{
		{"url": "https://shop.example/.git/config", "pattern": "/.git/config", "category": "Version Control"},
		{"url": "https://shop.example/admin/login", "pattern": "/admin", "category": "Administrative Interface"},
		{"url": "https://shop.example/api-docs/v1", "pattern": "/api-docs", "category": "API Documentation"},
		// A relative <loc> is matched as it is
		{"url": "/backups/2026-01-01.tar.gz", "pattern": "/backups", "category": "Backup Location"},
	}
	if len(paths) != len(want) {
		t.Fatalf("got %d dangerous paths %v, want %d", len(paths), paths, len(want))
	}
	// Paths are reported in the order the sitemap declares them
	for i, expected := range want {
		path, _ := paths[i].(map[string]any)
		for field, value := range expected {
			if path[field] != value {
				t.Errorf("path %d %s = %v, want %v", i, field, path[field], value)
			}
		}
	}
}

func TestMissingSitemapMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, run(t, "no_sitemap"))
	if metadata["sitemap_accessible"] != false || metadata["total_urls"] != float64(0) || metadata["total_dangerous"] != float64(0) {
		t.Errorf("metadata %v does not say the sitemap is missing", metadata)
	}
	if paths, ok := metadata["dangerous_paths"].([]any); !ok || len(paths) != 0 {
		t.Errorf("dangerous_paths %v, want an empty list", metadata["dangerous_paths"])
	}
}
