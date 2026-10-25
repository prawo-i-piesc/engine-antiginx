package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Listing pages as the servers generate them, trimmed to the parts the signatures read.
const (
	apacheListing = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>
<table><tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th></tr>
<tr><td><a href="/">Parent Directory</a></td></tr>
<tr><td><a href="invoice-2026.pdf">invoice-2026.pdf</a></td></tr>
<tr><td><a href="db-dump.sql">db-dump.sql</a></td></tr>
</table></body></html>`

	nginxListing = `<html><head><title>Index of /</title></head><body><h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="assets/">assets/</a>                                            01-Oct-2026 10:00       -
<a href="index.bak">index.bak</a>                                         01-Oct-2026 10:00    1234
</pre><hr></body></html>`

	iisListing = `<html><head><title>example.com - /files/</title></head><body><H1>example.com - /files/</H1><hr>
<pre><A HREF="/">[To Parent Directory]</A><br><br> 10/1/2026 10:00 AM &lt;dir&gt; <A HREF="/files/sub/">sub</A><br>
 10/1/2026 10:00 AM 1234 <A HREF="/files/report.xlsx">report.xlsx</A><br></pre><hr></body></html>`

	pythonListing = `<!DOCTYPE HTML><html lang="en"><head><title>Directory listing for /</title></head>
<body><h1>Directory listing for /</h1><hr><ul><li><a href=".env">.env</a></li><li><a href="app.py">app.py</a></li></ul><hr></body></html>`

	tomcatListing = `<html><head><title>Directory Listing For [/docs/]</title></head><body><h1>Directory Listing For [/docs/]</h1>
<table><tr><td><a href="/docs/manual.pdf"><tt>manual.pdf</tt></a></td></tr></table></body></html>`

	ordinaryPage = `<html><head><title>Welcome</title></head><body><h1>Index of our products</h1><a href="/shop">Shop</a></body></html>`
)

var testSignatures = []Signature{
	{Server: "Apache", Markers: []string{"<title>index of /", "<h1>index of /", "parent directory"}},
	{Server: "nginx", Markers: []string{"<title>index of /", "<h1>index of /", `<a href="../">../</a>`}},
	{Server: "IIS", Markers: []string{"[to parent directory]"}},
	{Server: "Tomcat", Markers: []string{"<title>directory listing for [/"}},
	{Server: "Python http.server", Markers: []string{"<title>directory listing for /"}},
	{Server: "Generic", Markers: []string{"<title>index of /"}},
}

var testScanner = Scanner{
	Signatures:       testSignatures,
	Timeout:          2 * time.Second,
	MaxBodyBytes:     64 * 1024,
	MaxConcurrency:   3,
	MaxSampleEntries: 10,
}

func TestDetectRecognisesServers(t *testing.T) {
	cases := map[string]string{
		apacheListing: "Apache",
		nginxListing:  "nginx",
		iisListing:    "IIS",
		pythonListing: "Python http.server",
		tomcatListing: "Tomcat",
	}
	for body, want := range cases {
		server, ok := testScanner.Detect(body)
		if !ok || server != want {
			t.Errorf("listing for %s detected as %q (%v)", want, server, ok)
		}
	}
	if server, ok := testScanner.Detect(ordinaryPage); ok {
		t.Errorf("ordinary page detected as a %s listing", server)
	}
}

func TestExtractEntriesSkipsNavigation(t *testing.T) {
	cases := []struct {
		body, directory string
		want            []string
	}{
		{apacheListing, "/uploads/", []string{"invoice-2026.pdf", "db-dump.sql"}},
		{nginxListing, "/", []string{"assets/", "index.bak"}},
		{iisListing, "/files/", []string{"sub/", "report.xlsx"}},
		{tomcatListing, "/docs/", []string{"manual.pdf"}},
	}
	for _, c := range cases {
		if got := ExtractEntries(c.body, c.directory); !reflect.DeepEqual(got, c.want) {
			t.Errorf("entries of %s: got %v, want %v", c.directory, got, c.want)
		}
	}
}

func TestScanFindsListings(t *testing.T) {
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(ordinaryPage))
		case "/uploads/":
			_, _ = w.Write([]byte(apacheListing))
		case "/static/":
			_, _ = w.Write([]byte(nginxListing))
		case "/download.zip/":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("<title>Index of /"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	analysis := testScanner.Scan(srv.URL, []Probe{
		{Path: "/"}, {Path: "/static/"}, {Path: "/uploads/", Sensitive: true},
		{Path: "/download.zip/"}, {Path: "/missing/"},
	})

	if analysis.ProbedPaths != 5 || analysis.ReachablePaths != 3 {
		t.Errorf("probed %d, reachable %d; want 5 and 3", analysis.ProbedPaths, analysis.ReachablePaths)
	}
	if analysis.TotalListings != 2 || analysis.SensitiveCount != 1 || analysis.RootListingOpen {
		t.Fatalf("unexpected analysis: %+v", analysis)
	}
	if analysis.Listings[0].Path != "/static/" || analysis.Listings[1].Path != "/uploads/" {
		t.Errorf("listings not sorted by path: %+v", analysis.Listings)
	}
	if analysis.Listings[1].EntryCount != 2 || analysis.Listings[1].Server != "Apache" {
		t.Errorf("unexpected uploads listing: %+v", analysis.Listings[1])
	}
	if !strings.Contains(Describe(analysis), "/uploads/ [sensitive]") {
		t.Errorf("description does not flag the sensitive listing:\n%s", Describe(analysis))
	}
}

func TestEvaluateThreat(t *testing.T) {
	grader := Grader{EscalationCount: 3}
	cases := []struct {
		name     string
		analysis ListingAnalysis
		want     SiteTests.ThreatLevel
	}{
		{"nothing listed", ListingAnalysis{}, SiteTests.None},
		{"one ordinary directory", ListingAnalysis{TotalListings: 1}, SiteTests.Medium},
		{"sensitive directory", ListingAnalysis{TotalListings: 1, SensitiveCount: 1}, SiteTests.High},
		{"web root", ListingAnalysis{TotalListings: 1, RootListingOpen: true}, SiteTests.High},
		{"widespread ordinary", ListingAnalysis{TotalListings: 3}, SiteTests.High},
		{"widespread with sensitive", ListingAnalysis{TotalListings: 4, SensitiveCount: 1}, SiteTests.Critical},
	}
	for _, c := range cases {
		if got := grader.EvaluateThreat(c.analysis); got != c.want {
			t.Errorf("%s: graded %v, want %v", c.name, got, c.want)
		}
	}
}
