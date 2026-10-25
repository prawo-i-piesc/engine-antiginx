package SensitivePaths

import "testing"

func TestContainsPathFragmentRespectsWordBoundary(t *testing.T) {
	cases := map[string]bool{
		"/test":          true,
		"/test/":         true,
		"/test.php":      true,
		"/test2":         true,
		"/en/test-suite": true,
		"/testimonials":  false,
		"/contest":       false,
		"/latest/test":   true,
	}
	for path, want := range cases {
		if got := containsPathFragment(path, "/test"); got != want {
			t.Errorf("containsPathFragment(%q, /test) = %v, want %v", path, got, want)
		}
	}
}

func TestBestPrefersLongestPattern(t *testing.T) {
	matcher := Matcher{"/api": "API Endpoint", "/api-docs": "API Documentation"}
	pattern, category, ok := matcher.Best("/API-Docs/index.html")
	if !ok || pattern != "/api-docs" || category != "API Documentation" {
		t.Errorf("Best = %q %q %v, want /api-docs API Documentation true", pattern, category, ok)
	}
	if _, _, ok := matcher.Best("/apiary"); ok {
		t.Error("/apiary matched /api, which is followed by a letter there")
	}
}

func TestMergeLaterTableWins(t *testing.T) {
	merged := Merge(map[string]string{"/a": "first", "/b": "kept"}, map[string]string{"/a": "second"})
	if merged["/a"] != "second" || merged["/b"] != "kept" {
		t.Errorf("Merge = %v, want /a second and /b kept", merged)
	}
}
