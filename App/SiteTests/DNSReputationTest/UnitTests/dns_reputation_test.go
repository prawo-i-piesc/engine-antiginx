package UnitTests

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/DNSReputationTest"
	"Engine-AntiGinx/App/SiteTests/UnitTestKit"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// rdapEnv names the variable the test reads its RDAP entry point from (see its config.go).
const rdapEnv = "ANTIGINX_RDAP_URL"

// outageDomain is the domain the stand-in RDAP service fails for with a server error.
const outageDomain = "outage.invalid"

// relativeDate is how an RDAP fixture writes a date relative to the moment it is served,
// {{days:-5}} meaning five days ago, so that registration ages do not drift as time passes.
var relativeDate = regexp.MustCompile(`\{\{days:(-?\d+)\}\}`)

// rdapServer is a stand-in for the RDAP bootstrap service. A lookup of /domain/<name> is
// answered with rdap/<name>.json, any other object with 404, which is how RDAP reports an
// object it holds no record for.
type rdapServer struct {
	*httptest.Server
	mutex   sync.Mutex
	queries []string
}

func (s *rdapServer) Queries() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]string(nil), s.queries...)
}

func serveRDAP(t *testing.T) *rdapServer {
	t.Helper()
	stand := &rdapServer{}
	stand.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stand.mutex.Lock()
		stand.queries = append(stand.queries, r.URL.Path)
		stand.mutex.Unlock()

		name, isDomain := strings.CutPrefix(r.URL.Path, "/domain/")
		if !isDomain || strings.ContainsAny(name, `/\`) {
			http.NotFound(w, r)
			return
		}
		if name == outageDomain {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		content, err := os.ReadFile(filepath.Join("rdap", name+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		now := time.Now().UTC()
		rendered := relativeDate.ReplaceAllStringFunc(string(content), func(token string) string {
			days, _ := strconv.Atoi(relativeDate.FindStringSubmatch(token)[1])
			return now.AddDate(0, 0, days).Format(time.RFC3339)
		})
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(rendered))
	}))
	t.Cleanup(stand.Close)
	t.Setenv(rdapEnv, stand.URL)
	return stand
}

func reputationMetadata(t *testing.T, result SiteTests.TestResult) DNSReputationTest.DNSReputationMetadata {
	t.Helper()
	metadata, ok := result.Metadata.(DNSReputationTest.DNSReputationMetadata)
	if !ok {
		t.Fatalf("metadata is %T, want DNSReputationMetadata", result.Metadata)
	}
	return metadata
}

func indicatorCodes(metadata DNSReputationTest.DNSReputationMetadata) []string {
	codes := []string{}
	for _, indicator := range metadata.Indicators {
		codes = append(codes, indicator.Code)
	}
	slices.Sort(codes)
	return codes
}

// Every target here is a name under the reserved .invalid top level domain, which never
// resolves, so each also carries the hostname-does-not-resolve observation (Medium). The
// registration record then decides whether the verdict stays at Medium or is escalated.
func TestRegistrationRecords(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		level     SiteTests.ThreatLevel
		codes     []string
		fragments []string
	}{
		{"very recently registered", "fresh.invalid", SiteTests.Critical,
			[]string{"domain-registered-days-ago", "hostname-does-not-resolve", "minimum-registration-period"},
			[]string{"registered 5 day(s) ago", "bought for the shortest period"}},
		{"registered within the quarter", "recent.invalid", SiteTests.High,
			[]string{"domain-registered-recently", "hostname-does-not-resolve", "minimum-registration-period"},
			[]string{"registered 45 day(s) ago and has no established history"}},
		{"registered within the year", "young.invalid", SiteTests.Medium,
			[]string{"domain-registered-within-a-year", "hostname-does-not-resolve"},
			[]string{"registered 200 day(s) ago, which is young"}},
		{"long established", "established.invalid", SiteTests.Medium,
			[]string{"hostname-does-not-resolve"},
			[]string{"The domain established.invalid is registered through Example Registrar, Inc. (US), was created on", "(3650 day(s) ago)", "held by its current holder for 3650 day(s)"}},
		{"established but changed holder recently", "transferred.invalid", SiteTests.High,
			[]string{"domain-changed-holder-recently", "hostname-does-not-resolve"},
			[]string{"is 3650 day(s) old but changed holder 20 day(s) ago"}},
		{"established but record modified recently", "modified.invalid", SiteTests.Medium,
			[]string{"hostname-does-not-resolve", "registration-recently-modified"},
			[]string{"was modified 3 day(s) ago"}},
		{"registration expired", "expired.invalid", SiteTests.High,
			[]string{"hostname-does-not-resolve", "registration-expired"},
			[]string{"can be re-registered by anyone"}},
		{"registration expires soon", "expiring.invalid", SiteTests.Medium,
			[]string{"hostname-does-not-resolve", "registration-expires-soon"},
			[]string{"is not being held for the long term"}},
		{"suspended by the registry", "suspended.invalid", SiteTests.Critical,
			[]string{"hostname-does-not-resolve", "registration-recently-modified", "registration-suspended"},
			[]string{"under status client hold, server hold"}},
		{"registration date withheld", "undated.invalid", SiteTests.Medium,
			[]string{"hostname-does-not-resolve", "registration-date-withheld"},
			[]string{"publishes no registration date"}},
		{"no registration record", "unknown.invalid", SiteTests.Medium,
			[]string{"hostname-does-not-resolve", "registration-data-unavailable"},
			[]string{"No registration record is published for unknown.invalid", "(rdap: object not found)"}},
		{"registration service failing", outageDomain, SiteTests.Medium,
			[]string{"hostname-does-not-resolve", "registration-data-unavailable"},
			[]string{"registration service answered with status 500"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serveRDAP(t)
			result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "https://"+c.host+"/")
			UnitTestKit.Expect(t, result, c.level, append(c.fragments, "The hostname "+c.host+" does not currently resolve")...)

			metadata := reputationMetadata(t, result)
			if codes := indicatorCodes(metadata); !slices.Equal(codes, c.codes) {
				t.Errorf("indicators %v, want %v", codes, c.codes)
			}
			if metadata.Resolution.Resolved {
				t.Errorf("%s resolved to %v", c.host, metadata.Resolution.IPv4Addresses)
			}
		})
	}
}

func TestRegistrationMetadata(t *testing.T) {
	serveRDAP(t)

	result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "https://www.suspended.invalid/login")
	metadata := reputationMetadata(t, result)
	registration := metadata.Registration
	if metadata.Host != "www.suspended.invalid" || metadata.RegistrableDomain != "suspended.invalid" {
		t.Errorf("host %q / domain %q, want www.suspended.invalid / suspended.invalid", metadata.Host, metadata.RegistrableDomain)
	}
	if !registration.Resolved || registration.Source != "RDAP" || registration.Domain != "suspended.invalid" || registration.TLD != "invalid" {
		t.Errorf("registration %+v does not describe the record", registration)
	}
	if registration.Registrar != "Example Registrar, Inc." || registration.RegistrarCountry != "US" || registration.RegistrarIANAId != "9999" {
		t.Errorf("registrar %q (%q, %q) not read from the record", registration.Registrar, registration.RegistrarCountry, registration.RegistrarIANAId)
	}
	if !slices.Equal(registration.Statuses, []string{"client hold", "server hold"}) {
		t.Errorf("statuses %v not normalized", registration.Statuses)
	}
	if !slices.Equal(registration.Nameservers, []string{"ns1.example-dns.test", "ns2.example-dns.test"}) {
		t.Errorf("nameservers %v not normalized", registration.Nameservers)
	}
	if registration.AgeDays != 3650 {
		t.Errorf("age %d days, want 3650", registration.AgeDays)
	}
	// The registration record answered, the DNS did not
	if result.Certainty != 75 {
		t.Errorf("certainty %d, want 75 with one source missing", result.Certainty)
	}
}

func TestNeitherSourceAnswers(t *testing.T) {
	serveRDAP(t)

	result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "https://unknown.invalid/")
	if result.Certainty != 55 {
		t.Errorf("certainty %d, want 55 with both sources missing", result.Certainty)
	}
}

// localhost resolves from the hosts file to loopback, and every name under it does too (RFC
// 6761), so it is never reported as a wildcard zone. What remains is the loopback address and
// the absent mail policy of a name that was never meant to carry mail. The hosts file decides
// whether localhost also has the IPv6 loopback address: each address is its own High
// observation, and two of them escalate the verdict to Critical.
func TestLoopbackTarget(t *testing.T) {
	serveRDAP(t)

	result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "http://localhost:8080/")
	metadata := reputationMetadata(t, result)
	if !metadata.Resolution.Resolved || !metadata.Registration.Resolved {
		t.Fatalf("resolution %v / registration %v, want both resolved", metadata.Resolution.Resolved, metadata.Registration.Resolved)
	}
	if metadata.Resolution.WildcardDNS {
		t.Error("localhost reported as a wildcard zone")
	}
	if len(metadata.Networks) == 0 || len(metadata.Networks) > 2 {
		t.Fatalf("inspected %d addresses, want the IPv4 and at most the IPv6 loopback address", len(metadata.Networks))
	}
	for _, network := range metadata.Networks {
		if network.Public || network.Scope != "loopback address" {
			t.Errorf("address %s reported public=%v scope=%q, want a loopback address", network.Address, network.Public, network.Scope)
		}
	}

	want := []string{"no-dmarc-policy", "no-mail-exchangers", "no-spf-policy"}
	for range metadata.Networks {
		want = append(want, "non-public-address")
	}
	slices.Sort(want)
	if codes := indicatorCodes(metadata); !slices.Equal(codes, want) {
		t.Errorf("indicators %v, want %v", codes, want)
	}

	level := SiteTests.High
	if len(metadata.Networks) == 2 {
		level = SiteTests.Critical
	}
	UnitTestKit.Expect(t, result, level,
		"The domain localhost is registered through Example Registrar, Inc. (US)", "(3650 day(s) ago)",
		"It resolves to", "the hostname resolves to 127.0.0.1, an address in the loopback address")
	if result.Certainty != 90 {
		t.Errorf("certainty %d, want 90 with both sources answering", result.Certainty)
	}
}

// Names under .localhost are loopback by definition as well, so the wildcard probe is skipped.
func TestLoopbackSubdomainIsNoWildcard(t *testing.T) {
	serveRDAP(t)

	result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "http://shop.localhost/")
	metadata := reputationMetadata(t, result)
	if metadata.Resolution.WildcardDNS || slices.Contains(indicatorCodes(metadata), "wildcard-dns-zone") {
		t.Errorf("shop.localhost reported as a wildcard zone: %v", indicatorCodes(metadata))
	}
}

// A loopback address is never looked up in the address registry.
func TestNonPublicAddressNotLookedUp(t *testing.T) {
	stand := serveRDAP(t)

	UnitTestKit.RunTarget(t, DNSReputationTest.New(), "http://localhost/")
	for _, query := range stand.Queries() {
		if strings.HasPrefix(query, "/ip/") {
			t.Errorf("non-public address looked up as %s", query)
		}
	}
}

func TestTargetWithoutHostname(t *testing.T) {
	result := UnitTestKit.RunTarget(t, DNSReputationTest.New(), "file:///etc/hosts")
	UnitTestKit.Expect(t, result, SiteTests.Info, "carries no hostname")

	result = DNSReputationTest.New().Run(SiteTests.ScanContext{})
	UnitTestKit.Expect(t, result, SiteTests.Info, "Target URL is unavailable")
}
