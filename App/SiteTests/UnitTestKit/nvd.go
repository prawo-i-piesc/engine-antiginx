package UnitTestKit

import (
	"Engine-AntiGinx/App/CVE"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
)

// NVDServer is a stand-in for the NVD CVE API that answers searches with prepared response
// files and remembers what it was asked.
type NVDServer struct {
	*httptest.Server
	mutex    sync.Mutex
	searches []string
	requests []*http.Request
}

// Searches returns the searches received so far, in arrival order: the CPE match string of a
// version lookup, or the keywords of a keyword search.
func (s *NVDServer) Searches() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string(nil), s.searches...)
}

// Requests returns the requests received so far, for checking their parameters and headers.
func (s *NVDServer) Requests() []*http.Request {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]*http.Request(nil), s.requests...)
}

// ServeNVD starts a stand-in NVD API and points every CVE client created during the test at
// it. A search is keyed by its virtualMatchString (cpe:2.3:a:vendor:product:version) or, for a
// keyword search, its keywordSearch value; a key found in responses is answered with that
// fixture file, any other search with fallback. A fixture named "" answers with status 503, as
// an overloaded NVD does.
func ServeNVD(t *testing.T, responses map[string]string, fallback string) *NVDServer {
	t.Helper()
	nvd := &NVDServer{}
	nvd.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := searchKey(r.URL.Query())
		nvd.mutex.Lock()
		nvd.searches = append(nvd.searches, key)
		nvd.requests = append(nvd.requests, r.Clone(r.Context()))
		nvd.mutex.Unlock()

		fixture, known := responses[key]
		if !known {
			fixture = fallback
		}
		if fixture == "" {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		content, err := os.ReadFile(fixture)
		if err != nil {
			t.Errorf("stand-in NVD cannot read fixture %s: %v", fixture, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	}))
	t.Cleanup(nvd.Close)
	t.Setenv(CVE.BaseURLEnv, nvd.URL)
	t.Setenv(CVE.APIKeyEnv, "")
	return nvd
}

// searchKey names what a CVE API request searches for.
func searchKey(query url.Values) string {
	if match := query.Get("virtualMatchString"); match != "" {
		return match
	}
	return query.Get("keywordSearch")
}
