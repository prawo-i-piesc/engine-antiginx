package ServerHeaderTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// offline replaces the NVD lookup for the duration of a test with a fixed grade per
// technology, so no test reaches the network.
func offline(t *testing.T, grades map[string]SiteTests.ThreatLevel) {
	original := cveThreat
	cveThreat = func(technology string) SiteTests.ThreatLevel { return grades[technology] }
	t.Cleanup(func() { cveThreat = original })
}

// run grades a response carrying the given headers.
func run(headers map[string]string) SiteTests.TestResult {
	header := http.Header{}
	for name, value := range headers {
		header.Set(name, value)
	}
	return New().RunTest(SiteTests.ResponseTestParams{Response: &http.Response{Header: header}})
}

func TestNoDisclosure(t *testing.T) {
	offline(t, nil)
	result := run(nil)
	if result.ThreatLevel != SiteTests.None || !strings.Contains(result.Description, "No server technology information") {
		t.Errorf("clean response gave %v: %q", result.ThreatLevel, result.Description)
	}
}

func TestBaseLevelFollowsExposureCount(t *testing.T) {
	offline(t, nil)
	cases := []struct {
		headers map[string]string
		want    SiteTests.ThreatLevel
	}{
		{map[string]string{"X-Cache": "HIT"}, SiteTests.Info},
		{map[string]string{"X-Cache": "HIT", "X-Served-By": "cache-1", "X-Framework": "custom"}, SiteTests.Low},
		{map[string]string{"X-Cache": "HIT", "X-Served-By": "a", "X-Framework": "b", "X-Varnish": "1", "X-Runtime": "0.1"}, SiteTests.Medium},
	}
	for _, c := range cases {
		if got := run(c.headers).ThreatLevel; got != c.want {
			t.Errorf("%d exposed headers graded %v, want %v", len(c.headers), got, c.want)
		}
	}
}

func TestCommonServersAreHigh(t *testing.T) {
	offline(t, nil)
	if got := run(map[string]string{"Server": "nginx/1.18.0"}).ThreatLevel; got != SiteTests.High {
		t.Errorf("nginx disclosure graded %v, want High", got)
	}
}

func TestCVEGradeRaisesLevel(t *testing.T) {
	offline(t, map[string]SiteTests.ThreatLevel{"PHP": SiteTests.Critical})
	if got := run(map[string]string{"X-Powered-By": "PHP/7.2.1"}).ThreatLevel; got != SiteTests.Critical {
		t.Errorf("PHP with critical CVEs graded %v, want Critical", got)
	}
}

func TestDescriptionCountsHeaders(t *testing.T) {
	offline(t, nil)
	result := run(map[string]string{"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1", "X-Cache": "HIT"})
	if !strings.HasPrefix(result.Description, "3 headers expose server information") {
		t.Errorf("description %q does not start with the header count", result.Description)
	}
	if !strings.Contains(result.Description, "Detected technologies: Nginx, PHP") {
		t.Errorf("description %q lacks the technologies in header order", result.Description)
	}
}

func TestMetadataIsOrderedAndSerializes(t *testing.T) {
	offline(t, nil)
	result := run(map[string]string{"X-Cache": "HIT", "Server": "Apache/2.4.1", "X-Powered-By": "PHP/8.1"})
	analysis := result.Metadata.(*ServerHeaderAnalysis)
	if !slices.Equal(analysis.ExposedHeaders, []string{"Server", "X-Powered-By", "X-Cache"}) {
		t.Errorf("exposed headers %v, want them in read order", analysis.ExposedHeaders)
	}
	if analysis.TechnologyStack["Apache"] != "2.4.1" {
		t.Errorf("technology stack %v lacks the Apache version", analysis.TechnologyStack)
	}

	encoded, err := json.Marshal(result.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"exposed_headers":["Server"`, `"total_exposures":3`, `"technology_stack":{`, `"header_details":{`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("metadata %s lacks %s", encoded, key)
		}
	}
}
