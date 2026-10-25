// Package UnitTestKit runs security tests against prepared data instead of live sites. Every
// test keeps its own fixtures in a UnitTests directory next to its code; this package turns
// those files into the inputs a test receives during a scan and checks what it reports.
//
// It is used only from _test.go files.
package UnitTestKit

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FixtureURLHeader is a pseudo-header a response fixture may carry to say which address the
// response was served from. It is removed before the test sees the response; without it the
// response is taken to come from DefaultURL.
const FixtureURLHeader = "X-Fixture-URL"

// DefaultURL is the address a response fixture is served from unless it names another.
const DefaultURL = "https://example.com/"

// LoadResponse reads a response fixture: a raw HTTP response exactly as it travels on the
// wire, a status line, headers, a blank line and the body. Lines may end in LF or CRLF.
// The response is returned with its request set to the fixture's address and its body read
// once, the way the scheduler hands it to Response tests.
func LoadResponse(t testing.TB, fixture string) (*http.Response, []byte) {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixture, err)
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("parsing fixture %s as an HTTP response: %v", fixture, err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading the body of fixture %s: %v", fixture, err)
	}
	response.Body = io.NopCloser(bytes.NewReader(body))

	address := response.Header.Get(FixtureURLHeader)
	response.Header.Del(FixtureURLHeader)
	if address == "" {
		address = DefaultURL
	}
	target, err := url.Parse(address)
	if err != nil {
		t.Fatalf("fixture %s names an invalid address %q: %v", fixture, address, err)
	}
	response.Request = &http.Request{Method: http.MethodGet, URL: target, Header: http.Header{}}
	return response, body
}

// RunResponse runs a test against a response fixture through the test's own Run, the path the
// scheduler takes during a scan.
func RunResponse(t testing.TB, test SiteTests.Test, fixture string) SiteTests.TestResult {
	t.Helper()
	response, body := LoadResponse(t, fixture)
	return test.Run(SiteTests.ScanContext{Target: response.Request.URL, Response: response, Body: body})
}

// RunTarget runs a test that needs only the target address, a PreResponse or a Structure test.
func RunTarget(t testing.TB, test SiteTests.Test, address string) SiteTests.TestResult {
	t.Helper()
	target, err := url.Parse(address)
	if err != nil {
		t.Fatalf("invalid target %q: %v", address, err)
	}
	return test.Run(SiteTests.ScanContext{Target: target})
}

// fixtureTime is the modification time every served fixture reports, so responses do not
// depend on when the repository was checked out.
var fixtureTime = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// SiteOption adjusts how ServeSite answers.
type SiteOption func(*site)

type site struct {
	root     string
	statuses map[string]int
	notFound string
	headers  map[string]http.Header
}

// WithStatus makes the site answer a path with a fixed status instead of its file, the way a
// server answers 401 or 403 for a file that exists but is protected.
func WithStatus(urlPath string, status int) SiteOption {
	return func(s *site) { s.statuses[urlPath] = status }
}

// WithSoftNotFound makes the site answer every missing path with 200 and the given fixture
// file, the way a single-page application or a catch-all route does.
func WithSoftNotFound(fixture string) SiteOption {
	return func(s *site) { s.notFound = fixture }
}

// WithHeader adds a response header to every answer for a path.
func WithHeader(urlPath string, name string, value string) SiteOption {
	return func(s *site) {
		if s.headers[urlPath] == nil {
			s.headers[urlPath] = http.Header{}
		}
		s.headers[urlPath].Add(name, value)
	}
}

// ServeSite serves a directory of fixtures as a website on a local address: /robots.txt is
// root/robots.txt, and a path ending in a slash is served from that directory's index.html.
// Anything else is a 404. Local addresses are normally refused by the SSRF protection, so it
// is lifted for the duration of the test.
func ServeSite(t *testing.T, root string, options ...SiteOption) *httptest.Server {
	t.Helper()
	t.Setenv(SSRF.AllowPrivateEnv, "true")

	s := &site{root: root, statuses: map[string]int{}, headers: map[string]http.Header{}}
	for _, option := range options {
		option(s)
	}

	server := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(server.Close)
	return server
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	for name, values := range s.headers[r.URL.Path] {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if status, fixed := s.statuses[r.URL.Path]; fixed {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(http.StatusText(status)))
		return
	}

	file := path.Clean("/" + r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") {
		file = path.Join(file, "index.html")
	}
	content, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file)))
	if err != nil {
		if s.notFound != "" {
			if page, readErr := os.ReadFile(s.notFound); readErr == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(page)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, file, fixtureTime, bytes.NewReader(content))
}

// Expect checks a result's threat level and that its description mentions every fragment.
func Expect(t testing.TB, result SiteTests.TestResult, level SiteTests.ThreatLevel, fragments ...string) {
	t.Helper()
	if result.ThreatLevel != level {
		t.Errorf("%s graded %v, want %v: %s", result.Name, result.ThreatLevel, level, result.Description)
	}
	for _, fragment := range fragments {
		if !strings.Contains(result.Description, fragment) {
			t.Errorf("%s description %q does not mention %q", result.Name, result.Description, fragment)
		}
	}
}

// Metadata returns a result's metadata as the JSON a report carries, so a test can check the
// fields a consumer actually receives whatever Go type the test reports them in.
func Metadata(t testing.TB, result SiteTests.TestResult) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(result.Metadata)
	if err != nil {
		t.Fatalf("metadata of %s does not serialize: %v", result.Name, err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("metadata of %s is not a JSON object: %s", result.Name, encoded)
	}
	return decoded
}
