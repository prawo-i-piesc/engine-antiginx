package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"strings"
	"testing"
)

// The sitemap test shares its definition of a sensitive file with SensitiveFilesTest, so a
// path added to the shared list is flagged in a sitemap without touching this package.
func TestSensitiveFilesAreMergedIntoPatterns(t *testing.T) {
	for _, file := range SensitivePaths.Files {
		if _, ok := fetcher.DangerousPatterns[strings.ToLower(file.Path)]; !ok {
			t.Errorf("shared sensitive file %s is not in the sitemap pattern table", file.Path)
		}
	}

	// A shared location must survive the merge.
	if _, ok := fetcher.DangerousPatterns["/admin"]; !ok {
		t.Error("shared location /admin was lost when merging the shared list")
	}
}
