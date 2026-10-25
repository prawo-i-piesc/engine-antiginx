package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/PhishingURLTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// urlCase is one prepared URL from urls.json and the verdict the test should reach on it.
type urlCase struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Level     string   `json:"level"`
	Fragments []string `json:"fragments"`
}

func loadURLCases(t *testing.T) []urlCase {
	t.Helper()
	raw, err := os.ReadFile("urls.json")
	if err != nil {
		t.Fatalf("reading urls.json: %v", err)
	}
	cases := []urlCase{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parsing urls.json: %v", err)
	}
	return cases
}

func parseLevel(t *testing.T, name string) SiteTests.ThreatLevel {
	t.Helper()
	for level := SiteTests.None; level <= SiteTests.Critical; level++ {
		if level.String() == name {
			return level
		}
	}
	t.Fatalf("unknown threat level %q", name)
	return SiteTests.None
}

func TestPhishingURLFixtures(t *testing.T) {
	for _, c := range loadURLCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			result := UnitTestKit.RunTarget(t, PhishingURLTest.New(), c.URL)
			UnitTestKit.Expect(t, result, parseLevel(t, c.Level), c.Fragments...)
		})
	}
}

func TestPhishingURLRedactsSecrets(t *testing.T) {
	result := UnitTestKit.RunTarget(t, PhishingURLTest.New(), "https://admin:hunter2@example.com/login?password=hunter2&token=abc123&lang=en")
	UnitTestKit.Expect(t, result, SiteTests.Critical)
	if strings.Contains(result.Description, "hunter2") || strings.Contains(result.Description, "abc123") {
		t.Errorf("description leaks a secret: %s", result.Description)
	}
	metadata := UnitTestKit.Metadata(t, result)
	if got, want := metadata["url"], "https://[REDACTED]@example.com/login?lang=en&password=[REDACTED]&token=[REDACTED]"; got != want {
		t.Errorf("reported url %v, want %v", got, want)
	}
}

func TestPhishingURLLookalikeMetadata(t *testing.T) {
	result := UnitTestKit.RunTarget(t, PhishingURLTest.New(), "https://аррle.com/")
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["is_suspicious"] != true || metadata["host"] != "аррle.com" {
		t.Errorf("metadata %v does not flag the host", metadata)
	}
	domain, _ := metadata["domain_analysis"].(map[string]any)
	if domain["matched_brand"] != "apple" || domain["matched_legitimate_domain"] != "apple.com" || domain["homograph_char_count"] != float64(3) {
		t.Errorf("domain analysis %v does not describe the homograph", domain)
	}
}

func TestPhishingURLCleanMetadata(t *testing.T) {
	result := UnitTestKit.RunTarget(t, PhishingURLTest.New(), "https://example.com/")
	if result.Certainty != 100 {
		t.Errorf("certainty %d, want 100 for a clean URL", result.Certainty)
	}
	metadata := UnitTestKit.Metadata(t, result)
	if metadata["is_suspicious"] != false {
		t.Errorf("metadata %v flags a clean URL", metadata)
	}
}

func TestPhishingURLWithoutTarget(t *testing.T) {
	result := PhishingURLTest.New().Run(SiteTests.ScanContext{})
	UnitTestKit.Expect(t, result, SiteTests.Info, "Target URL is unavailable")
}

// mea.com is one edit away from both me.com (apple) and ea.com (ea). Brands are compared in
// sorted order, so it is attributed to apple on every run, not to whichever brand the map
// iteration visits first.
func TestLookalikeOfTwoBrandsIsDeterministic(t *testing.T) {
	for run := 0; run < 100; run++ {
		result := UnitTestKit.RunTarget(t, PhishingURLTest.New(), "https://mea.com/")
		domain, _ := UnitTestKit.Metadata(t, result)["domain_analysis"].(map[string]any)
		if domain["matched_brand"] != "apple" || domain["matched_legitimate_domain"] != "me.com" {
			t.Fatalf("run %d matched %v (%v), want apple (me.com)", run, domain["matched_brand"], domain["matched_legitimate_domain"])
		}
	}
}
