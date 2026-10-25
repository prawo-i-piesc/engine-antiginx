package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeURLhaus answers /v1/url/ and /v1/host/ with fixed bodies and records what it was sent.
type fakeURLhaus struct {
	urlBody, hostBody string
	status            int
	gotURL, gotHost   string
	gotKey            string
}

func (f *fakeURLhaus) start(t *testing.T) Lookup {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("URLhaus expects POST, got %s", r.Method)
		}
		_ = r.ParseForm()
		f.gotKey = r.Header.Get("Auth-Key")
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		switch r.URL.Path {
		case "/v1/url/":
			f.gotURL = r.PostForm.Get("url")
			_, _ = w.Write([]byte(f.urlBody))
		case "/v1/host/":
			f.gotHost = r.PostForm.Get("host")
			_, _ = w.Write([]byte(f.hostBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return Lookup{
		HTTPClient:       &http.Client{Timeout: 2 * time.Second},
		BaseURL:          srv.URL,
		AuthKey:          "secret-key",
		MaxResponseSize:  1024 * 1024,
		MaxReportedURLs:  2,
		AbusedLegitimate: []string{"abused_legit_malware"},
		Malicious:        []string{"botnet_cc_domain"},
	}
}

const noResults = `{"query_status":"no_results"}`

func mustURL(t *testing.T, raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCheckCleanTarget(t *testing.T) {
	fake := &fakeURLhaus{urlBody: noResults, hostBody: noResults}
	metadata := fake.start(t).Check(mustURL(t, "https://user:pass@Example.com./page?x=1#frag"))

	if !metadata.Checked || metadata.URLListed || metadata.HostListed {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if fake.gotKey != "secret-key" {
		t.Errorf("Auth-Key header = %q", fake.gotKey)
	}
	if strings.Contains(fake.gotURL, "pass") || strings.Contains(fake.gotURL, "frag") {
		t.Errorf("credentials or fragment sent to URLhaus: %q", fake.gotURL)
	}
	if fake.gotHost != "example.com" {
		t.Errorf("host sent = %q, want example.com", fake.gotHost)
	}
	if got := EvaluateThreat(metadata); got != SiteTests.None {
		t.Errorf("clean target graded %v, want None", got)
	}
}

func TestCheckListedOnlineURL(t *testing.T) {
	fake := &fakeURLhaus{
		urlBody:  `{"query_status":"ok","url":"http://bad.example/x.exe","url_status":"online","threat":"malware_download","tags":["elf","mozi"],"date_added":"2026-10-01 10:00:00 UTC","urlhaus_reference":"https://urlhaus.abuse.ch/url/1/"}`,
		hostBody: `{"query_status":"ok","url_count":"3","blacklists":{"spamhaus_dbl":"not listed","surbl":"not listed"},"urls":[{"url":"http://bad.example/a","url_status":"offline"},{"url":"http://bad.example/x.exe","url_status":"online"},{"url":"http://bad.example/b","url_status":"offline"}]}`,
	}
	metadata := fake.start(t).Check(mustURL(t, "http://bad.example/x.exe"))

	if !metadata.URLListed || metadata.URLEntry.Threat != "malware_download" {
		t.Fatalf("URL not reported as listed: %+v", metadata)
	}
	if metadata.HostURLCount != 3 || metadata.HostOnlineURLs != 1 || len(metadata.HostURLs) != 2 {
		t.Errorf("host counts: %d total, %d online, %d reported", metadata.HostURLCount, metadata.HostOnlineURLs, len(metadata.HostURLs))
	}
	if metadata.HostURLs[0].Status != "online" {
		t.Errorf("online URLs are not reported first: %+v", metadata.HostURLs)
	}
	if got := EvaluateThreat(metadata); got != SiteTests.Critical {
		t.Errorf("online listed URL graded %v, want Critical", got)
	}
	if !strings.Contains(Describe(metadata), "... and 1 more") {
		t.Errorf("description does not mention the hidden URL:\n%s", Describe(metadata))
	}
}

func TestEvaluateThreatGrades(t *testing.T) {
	offline := &URLhausEntry{Status: "offline"}
	cases := []struct {
		name     string
		metadata URLhausMetadata
		want     SiteTests.ThreatLevel
	}{
		{"not checked", URLhausMetadata{}, SiteTests.Info},
		{"offline listed URL", URLhausMetadata{Checked: true, URLListed: true, URLEntry: offline}, SiteTests.High},
		{"host with offline history", URLhausMetadata{Checked: true, HostListed: true}, SiteTests.Medium},
		{"host with online URLs", URLhausMetadata{Checked: true, HostListed: true, HostOnlineURLs: 2}, SiteTests.High},
		{"blocklisted host with online URLs", URLhausMetadata{Checked: true, HostListed: true, HostOnlineURLs: 2, MaliciousListing: true}, SiteTests.Critical},
		{"abused service, online", URLhausMetadata{Checked: true, HostListed: true, HostOnlineURLs: 5, AbusedLegitimate: true}, SiteTests.Low},
		{"abused service, offline", URLhausMetadata{Checked: true, HostListed: true, AbusedLegitimate: true}, SiteTests.Info},
	}
	for _, c := range cases {
		if got := EvaluateThreat(c.metadata); got != c.want {
			t.Errorf("%s: graded %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckAbusedLegitimateHost(t *testing.T) {
	fake := &fakeURLhaus{
		urlBody:  noResults,
		hostBody: `{"query_status":"ok","url_count":120,"blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"},"urls":[{"url":"https://files.example/a","url_status":"online"}]}`,
	}
	metadata := fake.start(t).Check(mustURL(t, "https://files.example/"))
	if !metadata.AbusedLegitimate || metadata.MaliciousListing || metadata.HostURLCount != 120 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if got := EvaluateThreat(metadata); got != SiteTests.Low {
		t.Errorf("abused legitimate host graded %v, want Low", got)
	}
}

func TestCheckFailedLookupIsNotClean(t *testing.T) {
	for name, fake := range map[string]*fakeURLhaus{
		"http error":     {status: http.StatusUnauthorized},
		"unknown status": {urlBody: `{"query_status":"unknown_auth_key"}`, hostBody: noResults},
		"broken json":    {urlBody: noResults, hostBody: `{`},
	} {
		metadata := fake.start(t).Check(mustURL(t, "https://example.com/"))
		if metadata.Checked || metadata.LookupError == "" {
			t.Errorf("%s: failed lookup reported as checked: %+v", name, metadata)
		}
		if got := EvaluateThreat(metadata); got != SiteTests.Info {
			t.Errorf("%s: graded %v, want Info", name, got)
		}
	}
}
