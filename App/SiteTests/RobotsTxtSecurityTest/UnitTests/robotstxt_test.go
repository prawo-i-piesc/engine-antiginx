package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/RobotsTxtSecurityTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"path/filepath"
	"testing"
)

// run serves sites/<name> and runs the test against its home page.
func run(t *testing.T, name string, options ...UnitTestKit.SiteOption) SiteTests.TestResult {
	t.Helper()
	site := UnitTestKit.ServeSite(t, filepath.Join("sites", name), options...)
	return UnitTestKit.RunTarget(t, RobotsTxtSecurityTest.New(), site.URL+"/")
}

func TestRobotsTxtSites(t *testing.T) {
	cases := []struct {
		site      string
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"no_robots", SiteTests.None, []string{"not accessible or does not exist"}},
		// /testimonials and /contest/ contain /test but are not development paths
		{"clean", SiteTests.None, []string{"Robots.txt is secure", "none of its 5 Allow/Disallow rules"}},
		// The Allow only narrows the Disallow above it, so it exposes nothing
		{"wordpress_default", SiteTests.Low, []string{"names 2 sensitive paths (out of 2", "Administrative Interface: 2 found", "Allow: /wp-admin/admin-ajax.php"}},
		{"admin_disclosed", SiteTests.Low, []string{"names 1 sensitive paths (out of 2", "Disallow: /admin/"}},
		{"several_disclosed", SiteTests.Medium, []string{"names 4 sensitive paths (out of 5", "Version Control: 1 found", "Backup Location: 1 found"}},
		{"many_disclosed", SiteTests.High, []string{"names 8 sensitive paths (out of 9", "Database Dump: 1 found", "Disallow: /*.sql$"}},
		{"mass_disclosed", SiteTests.Critical, []string{"names 12 sensitive paths (out of 13", "Administrative Interface: 3 found", "Server Internals: 1 found"}},
		// One sensitive rule is Low, but an Allow that invites crawlers in raises it a level
		{"allow_exposes_admin", SiteTests.Medium, []string{"names 1 sensitive paths", "1 of them are Allow rules that explicitly invite crawlers", "Allow: /admin/"}},
		{"several_with_exposure", SiteTests.High, []string{"names 5 sensitive paths", "1 of them are Allow rules", "API Documentation: 1 found"}},
	}
	for _, c := range cases {
		t.Run(c.site, func(t *testing.T) {
			UnitTestKit.Expect(t, run(t, c.site), c.level, c.fragments...)
		})
	}
}

// A robots.txt the server refuses to hand out reveals nothing, however much it lists.
func TestForbiddenRobotsTxtIsIgnored(t *testing.T) {
	result := run(t, "mass_disclosed", UnitTestKit.WithStatus("/robots.txt", http.StatusForbidden))
	UnitTestKit.Expect(t, result, SiteTests.None, "not accessible or does not exist")
}

func TestRobotsTxtMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, run(t, "several_with_exposure"))
	if metadata["robots_accessible"] != true || metadata["total_rules"] != float64(5) ||
		metadata["total_dangerous"] != float64(5) || metadata["total_exposed"] != float64(1) {
		t.Errorf("metadata totals %v do not describe the file", metadata)
	}

	rules, _ := metadata["dangerous_rules"].([]any)
	want := []map[string]any{
		{"directive": "Disallow", "path": "/admin/", "pattern": "/admin", "category": "Administrative Interface", "exposed": false},
		{"directive": "Disallow", "path": "/backup/", "pattern": "/backup", "category": "Backup Location", "exposed": false},
		{"directive": "Disallow", "path": "/.git/", "pattern": "/.git", "category": "Version Control", "exposed": false},
		{"directive": "Disallow", "path": "/api/internal/", "pattern": "/internal", "category": "Internal Area", "exposed": false},
		{"directive": "Allow", "path": "/swagger/", "pattern": "/swagger", "category": "API Documentation", "exposed": true},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d dangerous rules %v, want %d", len(rules), rules, len(want))
	}
	// Rules are reported in the order the file lists them, each under its longest matching
	// fragment (/internal beats /api)
	for i, expected := range want {
		rule, _ := rules[i].(map[string]any)
		for field, value := range expected {
			if rule[field] != value {
				t.Errorf("rule %d %s = %v, want %v", i, field, rule[field], value)
			}
		}
	}
}

func TestMissingRobotsTxtMetadata(t *testing.T) {
	metadata := UnitTestKit.Metadata(t, run(t, "no_robots"))
	if metadata["robots_accessible"] != false || metadata["total_dangerous"] != float64(0) {
		t.Errorf("metadata %v does not say the file is missing", metadata)
	}
}
