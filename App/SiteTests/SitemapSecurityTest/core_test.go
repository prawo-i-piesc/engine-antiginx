package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"testing"
)

// The sitemap test shares its definition of a sensitive file with SensitiveFilesTest, so a
// path added to the shared list is flagged in a sitemap without touching this package.
func TestSensitiveFilesAreMergedIntoPatterns(t *testing.T) {
	merged := withSensitiveFiles(DangerousPatterns)

	for _, file := range SensitivePaths.Files {
		if _, ok := merged[toLower(file.Path)]; !ok {
			t.Errorf("shared sensitive file %s is not in the sitemap pattern table", file.Path)
		}
	}

	// A pattern this package defines itself must survive the merge.
	if _, ok := merged["/admin"]; !ok {
		t.Error("local pattern /admin was lost when merging the shared list")
	}
}

// toLower is a tiny local copy so the test does not pull in strings just for one call.
func toLower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}
