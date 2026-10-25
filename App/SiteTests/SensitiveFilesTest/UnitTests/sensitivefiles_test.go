package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitiveFilesTest"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every fixture secret here is fake. Git refuses to store a directory named .git inside a
// repository, so a site keeps its repository fixtures in dot-git/ and stage copies the site
// into a temporary directory under the real name before it is served.
func stage(t *testing.T, name string) string {
	t.Helper()
	source := filepath.Join("sites", name)
	root := t.TempDir()
	err := filepath.WalkDir(source, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, file)
		if err != nil {
			return err
		}
		target := filepath.Join(root, strings.ReplaceAll(relative, "dot-git", ".git"))
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
	if err != nil {
		t.Fatalf("staging site %s: %v", name, err)
	}
	return root
}

// run serves sites/<name> and runs the test against its home page.
func run(t *testing.T, name string, options ...UnitTestKit.SiteOption) SiteTests.TestResult {
	t.Helper()
	site := UnitTestKit.ServeSite(t, stage(t, name), options...)
	return UnitTestKit.RunTarget(t, SensitiveFilesTest.New(), site.URL+"/")
}

// probed is the fragment naming how many files the sweep requested: the whole shared list.
var probed = fmt.Sprintf("of %d probed files", len(SensitivePaths.Files))

func TestSensitiveFilesSites(t *testing.T) {
	cases := []struct {
		name      string
		site      string
		options   []UnitTestKit.SiteOption
		level     SiteTests.ThreatLevel
		fragments []string
	}{
		{"clean", "clean", nil, SiteTests.None,
			[]string{"No sensitive file was exposed", fmt.Sprintf("none of the %d probed files", len(SensitivePaths.Files))}},
		{"dependency manifest", "dev_manifest", nil, SiteTests.Low,
			[]string{"1 " + probed + " were readable", "/package.json [Development Artifact] — readable"}},
		{"phpinfo", "server_info", nil, SiteTests.Medium,
			[]string{"/phpinfo.php [Server Information] — readable"}},
		{"environment file", "exposed_env", nil, SiteTests.High,
			[]string{"1 " + probed + " were readable", "/.env [Secrets & Configuration] — readable, 134 bytes"}},
		{"git repository", "exposed_git", nil, SiteTests.High,
			[]string{"2 " + probed + " were readable", "/.git/config [Version Control]", "/.git/HEAD [Version Control]"}},
		// Each file is its own exposure, so three readable files do not raise the level
		{"several dev artefacts", "dev_artifacts", nil, SiteTests.Low,
			[]string{"3 " + probed + " were readable", "/Dockerfile", "/composer.json", "/package.json"}},
		// The most severe file decides: High for the secrets and the dump
		{"secrets, dump and log", "full_leak", nil, SiteTests.High,
			[]string{"3 " + probed + " were readable", "/.env [Secrets & Configuration]", "/dump.sql [Database Dump]", "/error.log [Log File]"}},
		// A file behind access control exists, but is only a Low note
		{"protected files", "protected",
			[]UnitTestKit.SiteOption{
				UnitTestKit.WithStatus("/.htpasswd", http.StatusForbidden),
				UnitTestKit.WithStatus("/.git/config", http.StatusUnauthorized),
			},
			SiteTests.Low,
			[]string{"0 " + probed + " were readable, and 2 more exist but are access-controlled", "/.htpasswd [Credentials] — exists, HTTP 403", "/.git/config [Version Control] — exists, HTTP 401"}},
		// A protected repository does not drive the verdict, the readable .env does
		{"readable and protected", "exposed_env",
			[]UnitTestKit.SiteOption{UnitTestKit.WithStatus("/.git/config", http.StatusForbidden)},
			SiteTests.High,
			[]string{"1 " + probed + " were readable, and 1 more exist but are access-controlled", "/.git/config [Version Control] — exists, HTTP 403"}},
		// A catch-all page answering 200 for every path must not look like every file exposed
		{"soft 404", "spa",
			[]UnitTestKit.SiteOption{UnitTestKit.WithSoftNotFound(filepath.Join("sites", "spa", "index.html"))},
			SiteTests.None,
			[]string{"No sensitive file was exposed", "answers 200 for missing paths"}},
		// ...but a real file that differs from the catch-all page still stands out
		{"soft 404 with real file", "spa_with_env",
			[]UnitTestKit.SiteOption{UnitTestKit.WithSoftNotFound(filepath.Join("sites", "spa_with_env", "index.html"))},
			SiteTests.High,
			[]string{"1 " + probed + " were readable", "/.env [Secrets & Configuration]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			UnitTestKit.Expect(t, run(t, c.site, c.options...), c.level, c.fragments...)
		})
	}
}

func TestSensitiveFilesMetadata(t *testing.T) {
	result := run(t, "exposed_env", UnitTestKit.WithStatus("/.git/config", http.StatusForbidden))
	if result.Certainty != 95 {
		t.Errorf("certainty %d, want 95 for a found exposure", result.Certainty)
	}

	metadata := UnitTestKit.Metadata(t, result)
	if metadata["probed"] != float64(len(SensitivePaths.Files)) || metadata["soft_not_found"] != false ||
		metadata["readable_count"] != float64(1) || metadata["protected_count"] != float64(1) {
		t.Errorf("metadata totals %v do not describe the sweep", metadata)
	}
	if baseline, _ := metadata["baseline_status"].([]any); len(baseline) != 1 || baseline[0] != float64(404) {
		t.Errorf("baseline_status %v, want [404]", metadata["baseline_status"])
	}

	// Exposures are sorted by path, so /.env comes before /.git/config
	exposures, _ := metadata["exposures"].([]any)
	if len(exposures) != 2 {
		t.Fatalf("got %d exposures %v, want 2", len(exposures), exposures)
	}
	env, _ := exposures[0].(map[string]any)
	git, _ := exposures[1].(map[string]any)
	if env["path"] != "/.env" || env["status"] != float64(200) || env["protected"] != false || env["size"] != float64(134) ||
		env["category"] != SensitivePaths.CategorySecrets || !strings.HasSuffix(env["url"].(string), "/.env") {
		t.Errorf("first exposure %v does not describe the readable .env", env)
	}
	if git["path"] != "/.git/config" || git["status"] != float64(403) || git["protected"] != true {
		t.Errorf("second exposure %v does not describe the protected repository", git)
	}
}

func TestSoftNotFoundMetadata(t *testing.T) {
	result := run(t, "spa", UnitTestKit.WithSoftNotFound(filepath.Join("sites", "spa", "index.html")))
	if result.Certainty != 80 {
		t.Errorf("certainty %d, want 80 when nothing was found", result.Certainty)
	}
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["soft_not_found"] != true || metadata["readable_count"] != float64(0) {
		t.Errorf("metadata %v does not record the soft-404 server", metadata)
	}
	if exposures, _ := metadata["exposures"].([]any); len(exposures) != 0 {
		t.Errorf("soft-404 server reported exposures %v", exposures)
	}
}
