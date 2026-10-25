package UnitTests

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/BotProtectionTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

// serveBlockPage answers every request with a fixture page and a non-200 status, the way a
// protection layer answers a request it refuses. ServeSite can only pair a fixed status with
// its own text, so the block page needs a server of its own.
func serveBlockPage(t *testing.T, fixture string, status int, headers map[string]string) *httptest.Server {
	t.Helper()
	t.Setenv(SSRF.AllowPrivateEnv, "true")
	page, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixture, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(page)
	}))
	t.Cleanup(server.Close)
	return server
}

func probeMetadata(t *testing.T, result SiteTests.TestResult) BotProtectionTest.BotProtectionScanMetadata {
	t.Helper()
	metadata, ok := result.Metadata.(BotProtectionTest.BotProtectionScanMetadata)
	if !ok {
		t.Fatalf("metadata is %T, want BotProtectionScanMetadata", result.Metadata)
	}
	return metadata
}

func TestUnprotectedSite(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), site.URL+"/")
	UnitTestKit.Expect(t, result, SiteTests.Info, "status 200", "no bot protection, CDN or WAF layer was identified")
	metadata := probeMetadata(t, result)
	if !metadata.Reachable || metadata.Blocked || metadata.StatusCode != 200 || len(metadata.Presence) != 0 || len(metadata.Challenge) != 0 {
		t.Errorf("metadata %+v does not describe an unprotected site", metadata)
	}
	if result.Certainty != 100 {
		t.Errorf("certainty %d, want 100", result.Certainty)
	}
}

// Challenge wording on an ordinary page served with 200 is content, not a challenge.
func TestChallengeWordingOnOrdinaryPage(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), site.URL+"/mentions-captcha/")
	UnitTestKit.Expect(t, result, SiteTests.Info, "no bot protection, CDN or WAF layer was identified")
}

func TestSiteBehindCDN(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site",
		UnitTestKit.WithHeader("/behind-cdn/", "CF-RAY", "8f1a2b3c4d5e6f70-WAW"),
		UnitTestKit.WithHeader("/behind-cdn/", "Server", "cloudflare"),
	)

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), site.URL+"/behind-cdn/")
	UnitTestKit.Expect(t, result, SiteTests.Low, "served through a bot protection, CDN or WAF layer (Cloudflare)", "status 200", "Content was returned normally")
	metadata := probeMetadata(t, result)
	if metadata.Blocked || !slices.Contains(metadata.Presence, "Cloudflare Ray ID: 8f1a2b3c4d5e6f70-WAW") || !slices.Contains(metadata.Presence, "Cloudflare Server") {
		t.Errorf("metadata %+v does not describe the CDN", metadata)
	}
	if result.Certainty != 45 {
		t.Errorf("certainty %d, want 45", result.Certainty)
	}
}

// The challenge platform script is embedded in healthy pages too, so it shows presence only.
func TestChallengePlatformScriptOnHealthyPage(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), site.URL+"/challenge-platform-script/")
	UnitTestKit.Expect(t, result, SiteTests.Low, "(Cloudflare)", "Content was returned normally")
	metadata := probeMetadata(t, result)
	if metadata.Blocked || !slices.Equal(metadata.Presence, []string{"Cloudflare Challenge Platform"}) {
		t.Errorf("metadata %+v does not describe presence only", metadata)
	}
}

func TestChallengeServedWith200(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), site.URL+"/challenge/")
	UnitTestKit.Expect(t, result, SiteTests.Low,
		"answered the probe with status 200 and served a challenge",
		"Cloudflare Browser Verification", "Cloudflare Interstitial",
		"cannot reach the origin")
	metadata := probeMetadata(t, result)
	if !metadata.Blocked || metadata.StatusCode != 200 {
		t.Errorf("metadata %+v does not describe a challenge", metadata)
	}
}

func TestBlockPageWithErrorStatus(t *testing.T) {
	server := serveBlockPage(t, "block.html", http.StatusForbidden, nil)

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), server.URL+"/")
	UnitTestKit.Expect(t, result, SiteTests.Low,
		"status 403", "(unidentified vendor)",
		"Content contains: access denied", "Content contains: suspicious activity", "Content contains: security check")
	metadata := probeMetadata(t, result)
	if !metadata.Blocked || metadata.StatusCode != 403 || len(metadata.Presence) != 0 {
		t.Errorf("metadata %+v does not describe a block page", metadata)
	}
}

func TestMitigationHeaderNamesVendor(t *testing.T) {
	server := serveBlockPage(t, "block.html", http.StatusForbidden, map[string]string{
		"CF-Mitigated": "challenge",
		"CF-RAY":       "8f1a2b3c4d5e6f70-WAW",
	})

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), server.URL+"/")
	UnitTestKit.Expect(t, result, SiteTests.Low, "status 403", "(Cloudflare)", "Cloudflare Mitigation")
	if metadata := probeMetadata(t, result); !metadata.Blocked {
		t.Errorf("metadata %+v does not describe a block", metadata)
	}
}

func TestUnreachableTarget(t *testing.T) {
	server := UnitTestKit.ServeSite(t, "site")
	address := server.URL + "/"
	server.Close()

	result := UnitTestKit.RunTarget(t, BotProtectionTest.New(), address)
	UnitTestKit.Expect(t, result, SiteTests.Info, "could not be reached", "probe request failed")
	if metadata := probeMetadata(t, result); metadata.Reachable {
		t.Errorf("metadata %+v claims the target was reached", metadata)
	}
}
