package SiteTests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestBaseURL(t *testing.T) {
	target, _ := url.Parse("https://example.com:8443/deep/page?q=1")
	if got := BaseURL(target); got != "https://example.com:8443" {
		t.Errorf("BaseURL = %q, want https://example.com:8443", got)
	}
}

func TestFetchLimitsBodyAndKeepsStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()

	page, err := Fetch(server.Client(), server.URL, 4)
	if err != nil {
		t.Fatal(err)
	}
	if page.Status != http.StatusTeapot || page.Header.Get("X-Probe") != "yes" || string(page.Body) != "0123" {
		t.Errorf("got %d %q %q, want 418, the header and the first 4 bytes", page.Status, page.Header.Get("X-Probe"), page.Body)
	}
}

func TestFetchFailedRequestIsEmptyPage(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()

	page, err := Fetch(&http.Client{Timeout: time.Second}, server.URL, 1024)
	if err == nil || page.Status != 0 || page.Body != nil {
		t.Errorf("got %+v, %v; want an empty page and an error", page, err)
	}
}

func TestProbeAllKeepsInputOrderAndBoundsConcurrency(t *testing.T) {
	var running, peak atomic.Int32
	items := []int{5, 1, 4, 2, 3, 6}
	results := ProbeAll(items, 2, func(item int) (int, bool) {
		current := running.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(time.Duration(item) * time.Millisecond)
		running.Add(-1)
		return item * 10, item%2 == 0
	})

	want := []int{40, 20, 60}
	if len(results) != len(want) {
		t.Fatalf("got %v, want %v", results, want)
	}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("got %v, want %v", results, want)
		}
	}
	if peak.Load() > 2 {
		t.Errorf("%d probes ran at once, want at most 2", peak.Load())
	}
}

func TestCountThresholdsGrade(t *testing.T) {
	thresholds := CountThresholds{LowMax: 2, MediumMax: 5, HighMax: 10}
	cases := map[int]ThreatLevel{0: None, 1: Low, 2: Low, 3: Medium, 5: Medium, 6: High, 10: High, 11: Critical}
	for count, want := range cases {
		if got := thresholds.Grade(count); got != want {
			t.Errorf("Grade(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestExampleLines(t *testing.T) {
	if got := ExampleLines([]string{"a", "b", "c", "d"}, 9, 2); got != "  - a\n  - b\n  ... and 7 more\n" {
		t.Errorf("sampled list rendered as %q", got)
	}
	if got := ExampleLines([]string{"a"}, 1, 3); got != "  - a\n" {
		t.Errorf("short list rendered as %q", got)
	}
}

func TestDescribeGroupsSortsCategories(t *testing.T) {
	got := DescribeGroups(map[string][]string{"Beta": {"x"}, "Alpha": {"p", "q", "r", "s"}}, "found", 3)
	want := "• Alpha: 4 found\n  - p\n  - q\n  - r\n  ... and 1 more\n• Beta: 1 found\n  - x\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}
