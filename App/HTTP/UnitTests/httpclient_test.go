package UnitTests

import (
	HttpClient "Engine-AntiGinx/App/HTTP"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// get fetches a page and returns either the response or the HttpError the client panicked
// with, which is how it reports every failure.
func get(t *testing.T, address string) (response *http.Response, failure *HttpClient.HttpError) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			httpError, ok := recovered.(HttpClient.HttpError)
			if !ok {
				t.Fatalf("client panicked with %T, want HttpError: %v", recovered, recovered)
			}
			failure = &httpError
		}
	}()
	return HttpClient.CreateHttpWrapper().Get(address), nil
}

func TestFetchesOrdinaryPage(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	response, failure := get(t, site.URL+"/")
	if failure != nil {
		t.Fatalf("ordinary page failed: %+v", failure)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	// The client reads the body to inspect it and must hand it on intact
	if !strings.Contains(string(body), "Welcome to the example shop") {
		t.Errorf("body not handed on intact: %q", body)
	}
}

// CDN fingerprints are present on every proxied site, healthy ones included, so they are not
// a reason to refuse the page.
func TestFetchesPageBehindCDN(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site", UnitTestKit.WithHeader("/behind-cdn/", "CF-RAY", "8f1a2b3c4d5e6f70-WAW"))

	if _, failure := get(t, site.URL+"/behind-cdn/"); failure != nil {
		t.Fatalf("healthy page behind a CDN refused: %+v", failure)
	}
}

func TestChallengeServedWith200IsRefused(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")

	_, failure := get(t, site.URL+"/challenge/")
	if failure == nil || failure.Code != 300 {
		t.Fatalf("challenge page gave %+v, want code 300", failure)
	}
	if !slices.Contains(failure.Protections, "Cloudflare Browser Verification") {
		t.Errorf("protections %v do not name the challenge", failure.Protections)
	}
}

func TestErrorStatusIsReported(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site", UnitTestKit.WithStatus("/gone", http.StatusNotFound))

	_, failure := get(t, site.URL+"/gone")
	if failure == nil || failure.Code != 102 || failure.IsRetryable {
		t.Fatalf("404 gave %+v, want non-retryable code 102", failure)
	}
	if !strings.Contains(failure.Message, "404") {
		t.Errorf("message %q does not carry the status", failure.Message)
	}
}

// A block page names the protection behind the refusal, so the report can say why the scan
// could not proceed.
func TestBlockPageNamesProtection(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site",
		UnitTestKit.WithHeader("/blocked/", "CF-Mitigated", "challenge"),
		UnitTestKit.WithHeader("/blocked/", "Server", "cloudflare"))

	response, failure := get(t, site.URL+"/blocked/")
	if failure == nil {
		t.Fatalf("mitigated response accepted: %d", response.StatusCode)
	}
	if !slices.Contains(failure.Protections, "Cloudflare Mitigation") {
		t.Errorf("protections %v do not name the mitigation", failure.Protections)
	}
}

func TestUnreachableServerIsRetryable(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")
	address := site.URL + "/"
	site.Close()

	_, failure := get(t, address)
	if failure == nil || failure.Code != 101 || !failure.IsRetryable {
		t.Fatalf("unreachable server gave %+v, want retryable code 101", failure)
	}
}

func TestInvalidAddressIsRejected(t *testing.T) {
	_, failure := get(t, "http://exa mple.com/")
	if failure == nil || failure.Code != 100 {
		t.Fatalf("invalid address gave %+v, want code 100", failure)
	}
}

// The SSRF protection is on unless a test lifts it, so a scan cannot be pointed at the
// machine running it.
func TestLocalAddressRefusedByDefault(t *testing.T) {
	site := UnitTestKit.ServeSite(t, "site")
	t.Setenv("ANTIGINX_ALLOW_PRIVATE_TARGETS", "")

	if _, failure := get(t, site.URL+"/"); failure == nil {
		t.Fatal("local address fetched with the SSRF protection on")
	}
}
