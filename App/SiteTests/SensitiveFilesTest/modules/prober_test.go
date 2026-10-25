package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testProber = Prober{
	Timeout:          2 * time.Second,
	MaxBodyBytes:     64 * 1024,
	MaxConcurrency:   4,
	SoftMatchPercent: 5,
}

var testCandidates = []Candidate{
	{"/.env", "Secrets & Configuration"},
	{"/.git/config", "Version Control"},
	{"/backup.zip", "Backup"},
	{"/phpinfo.php", "Server Information"},
}

func paths(exposures []Exposure) map[string]Exposure {
	byPath := map[string]Exposure{}
	for _, e := range exposures {
		byPath[e.Path] = e
	}
	return byPath
}

// A server that honestly 404s missing files: the clean case.
func TestSweepHardNotFoundServer(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			_, _ = w.Write([]byte("DB_PASSWORD=hunter2\n"))
		case "/.git/config":
			w.WriteHeader(http.StatusForbidden) // exists, blocked
		case "/backup.zip":
			_, _ = w.Write([]byte("PK\x03\x04 ... archive bytes ..."))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	analysis := testProber.Sweep(srv.URL, testCandidates)

	if analysis.SoftNotFound {
		t.Error("a 404ing server was taken for a soft-404 one")
	}
	if analysis.ReadableCount != 2 || analysis.ProtectedCount != 1 {
		t.Fatalf("readable=%d protected=%d; want 2 and 1 (%+v)", analysis.ReadableCount, analysis.ProtectedCount, analysis.Exposures)
	}
	byPath := paths(analysis.Exposures)
	if e := byPath["/.env"]; e.Protected || e.Category != "Secrets & Configuration" {
		t.Errorf("/.env: %+v", e)
	}
	if e := byPath["/.git/config"]; !e.Protected || e.Status != http.StatusForbidden {
		t.Errorf("/.git/config should be protected: %+v", e)
	}
	if _, found := byPath["/phpinfo.php"]; found {
		t.Error("/phpinfo.php (404) reported as exposed")
	}
}

// A server that returns its homepage with 200 for everything must not look fully exposed.
func TestSweepSoftNotFoundServer(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	homepage := strings.Repeat("<html>the same friendly 404-as-200 homepage</html>", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("SECRET_KEY=abcdef0123456789\n")) // clearly not the homepage
			return
		}
		_, _ = w.Write([]byte(homepage)) // everything else, including the real misses
	}))
	defer srv.Close()

	analysis := testProber.Sweep(srv.URL, testCandidates)

	if !analysis.SoftNotFound {
		t.Error("soft-404 server not recognised")
	}
	if analysis.ReadableCount != 1 || len(analysis.Exposures) != 1 || analysis.Exposures[0].Path != "/.env" {
		t.Fatalf("only /.env should stand out from the soft-404 page: %+v", analysis.Exposures)
	}
}

// A server that 403s everything offers no signal, so nothing should be reported.
func TestSweepForbidEverythingServer(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	analysis := testProber.Sweep(srv.URL, testCandidates)
	if len(analysis.Exposures) != 0 {
		t.Errorf("a 403-everything server produced findings: %+v", analysis.Exposures)
	}
}

func TestEvaluateThreat(t *testing.T) {
	severity := func(category string) SiteTests.ThreatLevel {
		return map[string]SiteTests.ThreatLevel{
			"Credentials":             SiteTests.Critical,
			"Secrets & Configuration": SiteTests.High,
			"Development Artifact":    SiteTests.Low,
		}[category]
	}
	grader := Grader{SeverityFor: severity, EscalationCount: 3}

	readable := func(category string) Exposure { return Exposure{Category: category} }
	protected := Exposure{Category: "Credentials", Protected: true}

	cases := []struct {
		name string
		a    Analysis
		want SiteTests.ThreatLevel
	}{
		{"nothing", Analysis{}, SiteTests.None},
		{"one secret", Analysis{Exposures: []Exposure{readable("Secrets & Configuration")}, ReadableCount: 1}, SiteTests.High},
		{"one credential", Analysis{Exposures: []Exposure{readable("Credentials")}, ReadableCount: 1}, SiteTests.Critical},
		{"protected only", Analysis{Exposures: []Exposure{protected}}, SiteTests.Low},
		{"three dev artefacts escalate", Analysis{Exposures: []Exposure{readable("Development Artifact"), readable("Development Artifact"), readable("Development Artifact")}, ReadableCount: 3}, SiteTests.Medium},
	}
	for _, c := range cases {
		if got := grader.EvaluateThreat(c.a); got != c.want {
			t.Errorf("%s: graded %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSimilarSize(t *testing.T) {
	cases := []struct {
		a, b, percent int
		want          bool
	}{
		{1000, 1000, 5, true},
		{1000, 1040, 5, true},
		{1000, 1060, 5, false},
		{0, 0, 5, true},
		{0, 100, 5, false},
	}
	for _, c := range cases {
		if got := similarSize(c.a, c.b, c.percent); got != c.want {
			t.Errorf("similarSize(%d,%d,%d) = %v, want %v", c.a, c.b, c.percent, got, c.want)
		}
	}
}
