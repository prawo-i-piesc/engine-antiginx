package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/DirectoryListingTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
)

// Every site serves an ordinary home page unless the scenario is a listing of the web root;
// a listing lives at <directory>/index.html, since a path ending in "/" is served from it.
// 36 directories are probed on every target (the common and sensitive ones in data.go).

// run serves sites/<name> and runs the test against the given page of it.
func run(t *testing.T, name string, page string, options ...UnitTestKit.SiteOption) SiteTests.TestResult {
	t.Helper()
	site := UnitTestKit.ServeSite(t, filepath.Join("sites", name), options...)
	return UnitTestKit.RunTarget(t, DirectoryListingTest.New(), site.URL+page)
}

func TestDirectoryListingSites(t *testing.T) {
	cases := []struct {
		site      string
		page      string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"clean", "/", SiteTests.None, []string{"No directory listing found", "none of the 36 probed directories (1 reachable)"}},
		// Pages that mention "Index of", "parent directory" or "Directory listing for" in prose
		{"lookalike", "/", SiteTests.None, []string{"No directory listing found", "(2 reachable)"}},
		// A tutorial quoting the output of dir in a <pre> block is not an IIS listing
		{"dir_tutorial", "/", SiteTests.None, []string{"No directory listing found", "(2 reachable)"}},

		// One listing in an ordinary directory, one per server format
		{"nginx_static", "/", SiteTests.Medium, []string{"1 of 36 probed directories", "/static/ (nginx, 3 entries)", "app.js.map"}},
		{"iis_files", "/", SiteTests.Medium, []string{"/files/ (IIS, 2 entries)", "price-list.xlsx"}},
		{"tomcat_docs", "/", SiteTests.Medium, []string{"/docs/ (Tomcat, 2 entries)", "runbook.txt"}},
		{"lighttpd_media", "/", SiteTests.Medium, []string{"/media/ (lighttpd, 1 entries)", "banner.png"}},
		{"jetty_downloads", "/", SiteTests.Medium, []string{"/downloads/ (Jetty, 1 entries)", "installer-1.4.2.exe"}},
		{"node_public", "/", SiteTests.Medium, []string{"/public/ (Node serve, 2 entries)", "favicon.ico"}},
		// The directory of the scanned page is probed too
		{"target_directory", "/blog/2026/post.html", SiteTests.Medium, []string{"1 of 38 probed directories", "/blog/2026/ (nginx, 2 entries)", "draft-unpublished.html"}},

		// A listing of the web root or of a sensitive directory is High
		{"apache_uploads", "/", SiteTests.High, []string{"1 of them in directories that typically hold uploads", "/uploads/ [sensitive] (Apache, 3 entries)", "passport-scan.jpg"}},
		{"generic_backup", "/", SiteTests.High, []string{"/backup/ [sensitive] (Generic, 2 entries)", "db-2026-01-01.sql.gz"}},
		// An IIS root listing has no parent link and is recognised by its <dir> links
		{"iis_root", "/", SiteTests.High, []string{"• / (IIS, 2 entries)", "aspnet_client/", "web.config.bak"}},
		{"apache_root", "/", SiteTests.High, []string{"• / (Apache, 2 entries)", "index.php.bak"}},
		{"python_root", "/", SiteTests.High, []string{"• / (Python http.server, 4 entries)", ".env", "... and 1 more"}},

		// Each listing is rated on its own: three ordinary ones stay Medium, and with the
		// root and sensitive directories among them the result stays High
		{"widespread", "/", SiteTests.Medium, []string{"3 of 36 probed directories", "/css/ (nginx", "/images/ (nginx", "/js/ (nginx"}},
		{"widespread_sensitive", "/", SiteTests.High, []string{"3 of 36 probed directories", "2 of them in directories", "/backup/ [sensitive]", "/logs/ [sensitive]", "access.log"}},
	}
	for _, c := range cases {
		t.Run(c.site, func(t *testing.T) {
			UnitTestKit.Expect(t, run(t, c.site, c.page), c.level, c.fragments...)
		})
	}
}

// A listing behind access control, or a file that only contains listing-like bytes, is not
// something a visitor can browse.
func TestUnbrowsableListingsAreIgnored(t *testing.T) {
	forbidden := run(t, "apache_uploads", "/", UnitTestKit.WithStatus("/uploads/", http.StatusForbidden))
	UnitTestKit.Expect(t, forbidden, SiteTests.None, "No directory listing found")

	download := run(t, "nginx_static", "/", UnitTestKit.WithHeader("/static/", "Content-Type", "application/octet-stream"))
	UnitTestKit.Expect(t, download, SiteTests.None, "No directory listing found")
}

func TestDirectoryListingMetadata(t *testing.T) {
	result := run(t, "widespread_sensitive", "/")
	if result.Certainty != 95 {
		t.Errorf("certainty %d, want 95 for a found listing", result.Certainty)
	}

	metadata := UnitTestKit.Metadata(t, result)
	if metadata["probed_paths"] != float64(36) || metadata["reachable_paths"] != float64(3) ||
		metadata["total_listings"] != float64(3) || metadata["sensitive_listings"] != float64(2) || metadata["root_listing"] != true {
		t.Errorf("metadata totals %v do not describe the scan", metadata)
	}

	// Listings are sorted by path whatever order the probes finished in
	listings, _ := metadata["listings"].([]any)
	want := []struct {
		path      string
		sensitive bool
		entries   []any
	}{
		{"/", false, []any{"backup/", "logs/"}},
		{"/backup/", true, []any{"site.tar.gz"}},
		{"/logs/", true, []any{"access.log", "error.log"}},
	}
	if len(listings) != len(want) {
		t.Fatalf("got %d listings %v, want %d", len(listings), listings, len(want))
	}
	for i, expected := range want {
		listing, _ := listings[i].(map[string]any)
		if listing["path"] != expected.path || listing["sensitive"] != expected.sensitive || listing["server"] != "nginx" ||
			listing["entry_count"] != float64(len(expected.entries)) || !reflect.DeepEqual(listing["entries"], expected.entries) {
			t.Errorf("listing %d = %v, want %s with %v", i, listing, expected.path, expected.entries)
		}
	}
}

// Entries leave out the parent link, the column-sorting links and absolute links that point
// outside the listed directory, whatever format names them.
func TestEntriesSkipNavigation(t *testing.T) {
	cases := []struct {
		site    string
		entries []any
	}{
		{"apache_uploads", []any{"invoice-2026-001.pdf", "passport-scan.jpg", "avatars/"}},
		{"iis_files", []any{"contracts/", "price-list.xlsx"}},
		{"jetty_downloads", []any{"installer-1.4.2.exe"}},
	}
	for _, c := range cases {
		t.Run(c.site, func(t *testing.T) {
			listings, _ := UnitTestKit.Metadata(t, run(t, c.site, "/"))["listings"].([]any)
			if len(listings) != 1 {
				t.Fatalf("got %d listings, want 1", len(listings))
			}
			if entries := listings[0].(map[string]any)["entries"]; !reflect.DeepEqual(entries, c.entries) {
				t.Errorf("entries %v, want %v", entries, c.entries)
			}
		})
	}
}

func TestNoListingCertainty(t *testing.T) {
	if result := run(t, "clean", "/"); result.Certainty != 80 {
		t.Errorf("certainty %d, want 80 when nothing was found", result.Certainty)
	}
}
