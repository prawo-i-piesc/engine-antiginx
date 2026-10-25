package UnitTestKit

import (
	"Engine-AntiGinx/App/CVE"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

// NVDServer is a stand-in for the NVD CVE API that answers keyword searches with prepared
// response files and remembers what it was asked.
type NVDServer struct {
	*httptest.Server
	mutex    sync.Mutex
	searches []string
}

// Searches returns the keyword searches received so far, in arrival order.
func (s *NVDServer) Searches() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string(nil), s.searches...)
}

// ServeNVD starts a stand-in NVD API and points every CVE client created during the test at
// it. A search for one of the responses' keys is answered with that fixture file; any other
// search gets fallback. A fixture named "" answers with status 503, as an overloaded NVD does.
func ServeNVD(t *testing.T, responses map[string]string, fallback string) *NVDServer {
	t.Helper()
	nvd := &NVDServer{}
	nvd.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyword := r.URL.Query().Get("keywordSearch")
		nvd.mutex.Lock()
		nvd.searches = append(nvd.searches, keyword)
		nvd.mutex.Unlock()

		fixture, known := responses[keyword]
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
	return nvd
}
