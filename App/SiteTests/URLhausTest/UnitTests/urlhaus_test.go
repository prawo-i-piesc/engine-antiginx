package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/URLhausTest"
	"Engine-AntiGinx/App/SiteTests/URLhausTest/modules"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Environment variables the test reads its API configuration from (see its config.go).
const (
	authKeyEnv = "ANTIGINX_URLHAUS_AUTH_KEY"
	baseURLEnv = "ANTIGINX_URLHAUS_URL"
	testKey    = "unit-test-auth-key"
)

// urlhausServer is a stand-in for the URLhaus API. It answers /v1/url/ and /v1/host/ with
// prepared answer files from answers/, chosen by the URL or host asked about. An answer named
// "status:<code>" makes it fail with that HTTP status instead. Anything not listed is answered
// with no_results.json, as URLhaus answers for a clean target.
type urlhausServer struct {
	*httptest.Server
	mutex    sync.Mutex
	requests []string
	authKeys []string
}

// Requests returns the lookups received so far as "url <value>" or "host <value>".
func (s *urlhausServer) Requests() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string(nil), s.requests...)
}

func serveURLhaus(t *testing.T, answers map[string]string) *urlhausServer {
	t.Helper()
	stand := &urlhausServer{}
	stand.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var key string
		switch r.URL.Path {
		case "/v1/url/":
			key = "url " + r.PostForm.Get("url")
		case "/v1/host/":
			key = "host " + r.PostForm.Get("host")
		default:
			http.NotFound(w, r)
			return
		}
		stand.mutex.Lock()
		stand.requests = append(stand.requests, key)
		stand.authKeys = append(stand.authKeys, r.Header.Get("Auth-Key"))
		stand.mutex.Unlock()

		answer, known := answers[key]
		if !known {
			answer = "no_results.json"
		}
		if code, isStatus := strings.CutPrefix(answer, "status:"); isStatus {
			status, _ := strconv.Atoi(code)
			http.Error(w, http.StatusText(status), status)
			return
		}
		content, err := os.ReadFile(filepath.Join("answers", answer))
		if err != nil {
			t.Errorf("stand-in URLhaus cannot read answer %s: %v", answer, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	}))
	t.Cleanup(stand.Close)
	t.Setenv(baseURLEnv, stand.URL)
	t.Setenv(authKeyEnv, testKey)
	return stand
}

func urlhausMetadata(t *testing.T, result SiteTests.TestResult) modules.URLhausMetadata {
	t.Helper()
	metadata, ok := result.Metadata.(modules.URLhausMetadata)
	if !ok {
		t.Fatalf("metadata is %T, want URLhausMetadata", result.Metadata)
	}
	return metadata
}

func TestNoAuthKeyConfigured(t *testing.T) {
	stand := serveURLhaus(t, nil)
	t.Setenv(authKeyEnv, "")

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "http://malware.test/bins/mozi.m")
	UnitTestKit.Expect(t, result, SiteTests.Info, "URLhaus was not consulted", authKeyEnv)
	if metadata := urlhausMetadata(t, result); metadata.Checked || metadata.LookupError != "auth key not configured" {
		t.Errorf("metadata %+v does not say the lookup was skipped", metadata)
	}
	if requests := stand.Requests(); len(requests) != 0 {
		t.Errorf("URLhaus was asked %v without an auth key", requests)
	}
}

func TestLookups(t *testing.T) {
	answers := map[string]string{
		"url http://malware.test/bins/mozi.m":          "url_listed_online.json",
		"url http://old-malware.test/payload.exe":      "url_listed_offline.json",
		"host phishing-host.test":                      "host_malicious.json",
		"host infected-host.test":                      "host_online.json",
		"host cleaned-host.test":                       "host_offline.json",
		"host surbl-host.test":                         "host_offline_surbl.json",
		"host files.example-share.test":                "host_abused_online.json",
		"host code.example-forge.test":                 "host_abused_offline.json",
		"url http://url-unavailable.test/":             "status:503",
		"host host-unauthorized.test":                  "status:401",
		"url http://invalid-answer.test/":              "invalid_url.json",
		"url http://malformed-answer.test/":            "malformed.json",
		"url https://files.example-share.test/welcome": "no_results.json",
	}
	cases := []struct {
		name      string
		target    string
		level     SiteTests.ThreatLevel
		certainty int
		fragments []string
	}{
		{"URL listed and online", "http://malware.test/bins/mozi.m", SiteTests.Critical, 100,
			[]string{"The target URL is listed in URLhaus as malware_download, currently online", "with tags elf, mozi", "https://urlhaus.abuse.ch/url/3112045/"}},
		{"URL listed but offline", "http://old-malware.test/payload.exe", SiteTests.High, 100,
			[]string{"listed in URLhaus as malware_download, currently offline", "reported on 2025-03-02"}},
		{"host listed with a malicious blocklist status", "http://phishing-host.test/login", SiteTests.Critical, 90,
			[]string{"The host phishing-host.test has 25 URL(s) recorded in URLhaus, 1 of the listed ones still online", "also blocklisted (Spamhaus DBL: phishing_domain, SURBL: listed)", "[online] malware_download: http://phishing-host.test/b.exe", "... and 22 more"}},
		{"host listed with an online URL", "http://infected-host.test/", SiteTests.High, 90,
			[]string{"1 URL(s) recorded in URLhaus, 1 of the listed ones still online"}},
		{"host listed with offline URLs only", "http://cleaned-host.test/", SiteTests.Medium, 90,
			[]string{"1 URL(s) recorded in URLhaus, 0 of the listed ones still online", "[offline] malware_download: http://cleaned-host.test/old.exe"}},
		{"host listed offline and blocklisted by SURBL", "http://surbl-host.test/", SiteTests.High, 90,
			[]string{"also blocklisted (Spamhaus DBL: not listed, SURBL: listed)"}},
		{"abused legitimate host with an online URL", "https://files.example-share.test/welcome", SiteTests.Low, 70,
			[]string{"Spamhaus classifies the domain as abused_legit_malware", "legitimate service that was abused", "1 of the listed ones still online"}},
		{"abused legitimate host with offline URLs only", "https://code.example-forge.test/", SiteTests.Info, 70,
			[]string{"abused_legit_malware", "0 of the listed ones still online"}},
		{"nothing listed", "https://example.com/", SiteTests.None, 80,
			[]string{"Neither https://example.com/ nor its host example.com is listed in URLhaus"}},
		{"URL lookup answers an HTTP error", "http://url-unavailable.test/", SiteTests.Info, 100,
			[]string{"URLhaus could not be consulted (URL lookup failed: URLhaus answered HTTP 503)"}},
		{"host lookup answers an HTTP error", "http://host-unauthorized.test/", SiteTests.Info, 100,
			[]string{"host lookup failed: URLhaus answered HTTP 401"}},
		{"unexpected query status", "http://invalid-answer.test/", SiteTests.Info, 100,
			[]string{`URL lookup failed: URLhaus answered query_status "invalid_url"`}},
		{"unreadable answer", "http://malformed-answer.test/", SiteTests.Info, 100,
			[]string{"URL lookup failed: unreadable URLhaus answer"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serveURLhaus(t, answers)
			result := UnitTestKit.RunTarget(t, URLhausTest.New(), c.target)
			UnitTestKit.Expect(t, result, c.level, c.fragments...)
			if result.Certainty != c.certainty {
				t.Errorf("certainty %d, want %d", result.Certainty, c.certainty)
			}
		})
	}
}

func TestListedHostMetadata(t *testing.T) {
	serveURLhaus(t, map[string]string{"host phishing-host.test": "host_malicious.json"})

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "http://phishing-host.test/login")
	metadata := urlhausMetadata(t, result)
	if !metadata.Checked || metadata.URLListed || !metadata.HostListed || !metadata.MaliciousListing || metadata.AbusedLegitimate {
		t.Errorf("metadata %+v does not describe a malicious host", metadata)
	}
	if metadata.HostURLCount != 25 || metadata.HostOnlineURLs != 1 || len(metadata.HostURLs) != 3 {
		t.Errorf("host counts %d/%d/%d, want 25 recorded, 1 online, 3 reported", metadata.HostURLCount, metadata.HostOnlineURLs, len(metadata.HostURLs))
	}
	if metadata.HostURLs[0].Status != "online" {
		t.Errorf("reported URLs %+v do not start with the online one", metadata.HostURLs)
	}
}

// Credentials and the fragment never leave the engine, scheme and host are lowercased the way
// URLhaus stores them, and the configured key is sent.
func TestLookupRequest(t *testing.T) {
	stand := serveURLhaus(t, map[string]string{"url http://malware.test/bins/mozi.m": "url_listed_online.json"})

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "HTTP://admin:secret@MALWARE.test/bins/mozi.m#section")
	UnitTestKit.Expect(t, result, SiteTests.Critical)
	requests := stand.Requests()
	want := []string{"url http://malware.test/bins/mozi.m", "host malware.test"}
	if strings.Join(requests, "|") != strings.Join(want, "|") {
		t.Errorf("URLhaus was asked %v, want %v", requests, want)
	}
	for _, key := range stand.authKeys {
		if key != testKey {
			t.Errorf("request carried Auth-Key %q, want %q", key, testKey)
		}
	}
}

func TestMixedCaseHostIsFound(t *testing.T) {
	serveURLhaus(t, map[string]string{"url http://malware.test/bins/mozi.m": "url_listed_online.json"})

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "http://MALWARE.test/bins/mozi.m")
	UnitTestKit.Expect(t, result, SiteTests.Critical, "listed in URLhaus as malware_download, currently online")
}

// The path is case-sensitive, so it is sent exactly as given.
func TestPathKeepsItsCase(t *testing.T) {
	stand := serveURLhaus(t, map[string]string{"url http://malware.test/bins/mozi.m": "url_listed_online.json"})

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "http://Malware.Test/Bins/Mozi.m")
	UnitTestKit.Expect(t, result, SiteTests.None)
	if requests := stand.Requests(); len(requests) == 0 || requests[0] != "url http://malware.test/Bins/Mozi.m" {
		t.Errorf("URLhaus was asked %v, want the path unchanged", requests)
	}
}

func TestUnreachableAPI(t *testing.T) {
	stand := serveURLhaus(t, nil)
	stand.Close()

	result := UnitTestKit.RunTarget(t, URLhausTest.New(), "https://example.com/")
	UnitTestKit.Expect(t, result, SiteTests.Info, "URLhaus could not be consulted (URL lookup failed:")
}
