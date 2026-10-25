package RobotsTxtSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"strings"
	"testing"
)

// robots.txt shares its definition of a sensitive file with SitemapSecurityTest and
// SensitiveFilesTest, so a path added to the shared list is recognised in robots.txt rules
// without touching this package.
func TestSharedSensitiveFilesAreInPatternTable(t *testing.T) {
	for _, file := range SensitivePaths.Files {
		if _, ok := fetcher.DangerousPatterns[strings.ToLower(file.Path)]; !ok {
			t.Errorf("shared sensitive file %s is not in the robots.txt pattern table", file.Path)
		}
	}

	// A fragment this package adds itself, and one it inherits from the sitemap test, must
	// both survive the merge.
	if _, ok := fetcher.DangerousPatterns["/wp-login"]; !ok {
		t.Error("local pattern /wp-login was lost when merging the shared list")
	}
	if _, ok := fetcher.DangerousPatterns["/admin"]; !ok {
		t.Error("inherited sitemap pattern /admin was lost when merging the shared list")
	}
}
