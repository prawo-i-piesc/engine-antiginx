package DNSReputationTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/DNSReputationTest/modules"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// The metadata types keep the names they are reported under while living beside the code that
// populates them.
type (
	DNSReputationMetadata  = modules.DNSReputationMetadata
	DomainRegistrationInfo = modules.DomainRegistrationInfo
	DomainResolutionInfo   = modules.DomainResolutionInfo
	MailAuthenticationInfo = modules.MailAuthenticationInfo
	AddressNetworkInfo     = modules.AddressNetworkInfo
	DNSIndicator           = modules.DNSIndicator
)

// newCollector wires the datasets in data.go and the budgets in config.go into the acquisition
// stage, so the stage itself knows nothing about which suffixes or providers this engine
// happens to track today.
func newCollector() *modules.Collector {
	return &modules.Collector{
		Resolver:     net.DefaultResolver,
		HTTPClient:   &http.Client{Timeout: rdapLookupTimeout},
		RDAPBaseURL:  configuredRDAPBaseURL(),
		RDAPTimeout:  rdapLookupTimeout,
		DNSTimeout:   dnsLookupTimeout,
		MaxAddresses: maxInspectedAddresses,
		Now:          time.Now,
		Names: modules.Names{
			PublicSuffixes:   multiLabelPublicSuffixes,
			ManagedServices:  managedServiceSuffixes,
			FreeDNSProviders: freeDNSProviderSuffixes,
			DynamicMarkers:   dynamicReverseNameMarkers,
			ReservedRanges:   reservedAddressRanges,
		},
	}
}

// configuredRDAPBaseURL returns the RDAP entry point, honouring the environment override.
func configuredRDAPBaseURL() string {
	if configured := strings.TrimSpace(os.Getenv(rdapBaseURLEnvVar)); configured != "" {
		return strings.TrimSuffix(configured, "/")
	}
	return defaultRDAPBaseURL
}

// New creates a new PreResponseTest that analyses a target's domain registration, DNS
// configuration and address reputation.
func New() *SiteTests.PreResponseTest {
	return &SiteTests.PreResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.PreResponseTestParams) SiteTests.TestResult {
			if params.Target == nil {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   dnsReputationCleanCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    DNSReputationMetadata{Indicators: []DNSIndicator{}},
					Description: "Target URL is unavailable, so no registration or DNS analysis could be performed.",
				}
			}

			host := strings.ToLower(strings.TrimSuffix(params.Target.Hostname(), "."))
			if host == "" {
				return SiteTests.TestResult{
					Name:        TestName,
					Certainty:   dnsReputationCleanCertainty,
					ThreatLevel: SiteTests.Info,
					Metadata:    DNSReputationMetadata{Indicators: []DNSIndicator{}},
					Description: "The target carries no hostname, so no registration or DNS analysis could be performed.",
				}
			}

			metadata := newCollector().Collect(host)
			metadata.Indicators = evaluateDNSIndicators(metadata)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   evaluateDNSReputationCertainty(metadata),
				ThreatLevel: evaluateDNSReputationThreatLevel(metadata.Indicators),
				Metadata:    metadata,
				Description: buildDNSReputationDescription(metadata),
			}
		},
	}
}

// evaluateDNSIndicators derives every phishing relevant observation from the collected
// evidence.
func evaluateDNSIndicators(metadata DNSReputationMetadata) []DNSIndicator {
	indicators := []DNSIndicator{}
	indicators = append(indicators, evaluateRegistrationIndicators(metadata.Registration)...)
	indicators = append(indicators, evaluateResolutionIndicators(metadata.Resolution)...)
	indicators = append(indicators, evaluateMailIndicators(metadata.Resolution, metadata.MailAuthentication)...)
	indicators = append(indicators, evaluateNetworkIndicators(metadata.Networks)...)
	indicators = append(indicators, evaluateJurisdictionIndicators(metadata)...)

	sort.SliceStable(indicators, func(first int, second int) bool {
		return indicators[first].Severity > indicators[second].Severity
	})
	return indicators
}

// evaluateRegistrationIndicators reads the registration record for the two properties that
// matter most about a phishing domain: how new it is, and how new its holder is.
func evaluateRegistrationIndicators(registration DomainRegistrationInfo) []DNSIndicator {
	indicators := []DNSIndicator{}

	if !registration.Resolved {
		detail := "no registration record could be retrieved for the domain, so its age and holder are unknown"
		if registration.LookupError != "" {
			detail += " (" + registration.LookupError + ")"
		}
		return append(indicators, DNSIndicator{Code: "registration-data-unavailable", Detail: detail, Severity: SiteTests.Info})
	}

	switch {
	case registration.AgeDays < 0:
		indicators = append(indicators, DNSIndicator{
			Code:     "registration-date-withheld",
			Detail:   "the registry publishes no registration date, so the domain's age could not be established",
			Severity: SiteTests.Info,
		})
	case registration.AgeDays < freshRegistrationDays:
		indicators = append(indicators, DNSIndicator{
			Code:     "domain-registered-days-ago",
			Detail:   fmt.Sprintf("the domain was registered %d day(s) ago, the age band the large majority of phishing domains are used in", registration.AgeDays),
			Severity: SiteTests.High,
		})
	case registration.AgeDays < recentRegistrationDays:
		indicators = append(indicators, DNSIndicator{
			Code:     "domain-registered-recently",
			Detail:   fmt.Sprintf("the domain was registered %d day(s) ago and has no established history", registration.AgeDays),
			Severity: SiteTests.Medium,
		})
	case registration.AgeDays < youngRegistrationDays:
		indicators = append(indicators, DNSIndicator{
			Code:     "domain-registered-within-a-year",
			Detail:   fmt.Sprintf("the domain was registered %d day(s) ago, which is young for a site presenting itself as established", registration.AgeDays),
			Severity: SiteTests.Low,
		})
	}

	if registration.AgeDays >= youngRegistrationDays && registration.TenureDays >= 0 && registration.TenureDays < recentTransferDays {
		indicators = append(indicators, DNSIndicator{
			Code:     "domain-changed-holder-recently",
			Detail:   fmt.Sprintf("the domain is %d day(s) old but changed holder %d day(s) ago, the pattern of an aged domain acquired for its reputation", registration.AgeDays, registration.TenureDays),
			Severity: SiteTests.Medium,
		})
	}

	if registration.AgeDays >= youngRegistrationDays && registration.LastChangedDaysAgo >= 0 && registration.LastChangedDaysAgo < recentModificationDays {
		indicators = append(indicators, DNSIndicator{
			Code:     "registration-recently-modified",
			Detail:   fmt.Sprintf("the registration record of this established domain was modified %d day(s) ago", registration.LastChangedDaysAgo),
			Severity: SiteTests.Low,
		})
	}

	switch {
	case registration.DaysUntilExpiry < 0 && registration.Expires != nil:
		indicators = append(indicators, DNSIndicator{
			Code:     "registration-expired",
			Detail:   fmt.Sprintf("the registration expired on %s and the domain can be re-registered by anyone once it is released", registration.Expires.Format("2006-01-02")),
			Severity: SiteTests.Medium,
		})
	case registration.DaysUntilExpiry >= 0 && registration.DaysUntilExpiry < expiringSoonDays:
		indicators = append(indicators, DNSIndicator{
			Code:     "registration-expires-soon",
			Detail:   fmt.Sprintf("the registration lapses in %d day(s), so the domain is not being held for the long term", registration.DaysUntilExpiry),
			Severity: SiteTests.Low,
		})
	}

	if registration.RegistrationPeriodDays > 0 && registration.RegistrationPeriodDays <= minimumRegistrationDays &&
		registration.AgeDays >= 0 && registration.AgeDays < youngRegistrationDays/2 {
		indicators = append(indicators, DNSIndicator{
			Code:     "minimum-registration-period",
			Detail:   "the domain was bought for the shortest period the registry sells, which is what disposable infrastructure is bought for",
			Severity: SiteTests.Low,
		})
	}

	if suspended := suspendedStatuses(registration.Statuses); len(suspended) > 0 {
		indicators = append(indicators, DNSIndicator{
			Code:     "registration-suspended",
			Detail:   fmt.Sprintf("the registry holds the domain under status %s, which is how a domain is taken out of service, commonly after an abuse report", strings.Join(suspended, ", ")),
			Severity: SiteTests.High,
		})
	}

	if isAbuseProneTopLevelDomain(registration.TLD) {
		indicators = append(indicators, DNSIndicator{
			Code:     "abuse-prone-namespace",
			Detail:   fmt.Sprintf("the domain is registered in .%s, one of the namespaces whose registration terms make it a fixture of published abuse rankings; this describes the namespace, not this domain", registration.TLD),
			Severity: SiteTests.Low,
		})
	}

	return indicators
}

// suspendedStatuses returns the EPP status codes that mean the registry has taken the domain
// out of normal service, which registrars apply after an abuse complaint and registries apply
// when a registration is being wound down.
func suspendedStatuses(statuses []string) []string {
	markers := []string{"hold", "pending delete", "pendingdelete", "redemption", "inactive"}

	matched := []string{}
	for _, status := range statuses {
		for _, marker := range markers {
			if strings.Contains(status, marker) {
				matched = append(matched, status)
				break
			}
		}
	}
	return matched
}

// evaluateResolutionIndicators reads what the zone says about how the site is published.
func evaluateResolutionIndicators(resolution DomainResolutionInfo) []DNSIndicator {
	indicators := []DNSIndicator{}

	switch resolution.HostingServiceKind {
	case serviceKindTunnel:
		indicators = append(indicators, DNSIndicator{
			Code:     "ephemeral-tunnel-hostname",
			Detail:   fmt.Sprintf("the hostname was handed out by the tunnelling service %s, which exposes a private machine under a name that stops working as soon as its operator disconnects", resolution.HostingService),
			Severity: SiteTests.High,
		})
	case serviceKindDynamicDNS:
		indicators = append(indicators, DNSIndicator{
			Code:     "dynamic-dns-hostname",
			Detail:   fmt.Sprintf("the hostname was handed out by the dynamic DNS provider %s, so it is not a registered domain and its holder is not recorded anywhere public", resolution.HostingService),
			Severity: SiteTests.Medium,
		})
	case serviceKindFreeHosting:
		indicators = append(indicators, DNSIndicator{
			Code:     "free-hosting-hostname",
			Detail:   fmt.Sprintf("the hostname belongs to the self service platform %s, so the registration data describes the platform and says nothing about who published this page", resolution.HostingService),
			Severity: SiteTests.Low,
		})
	}

	if resolution.AliasedToService != "" {
		indicators = append(indicators, DNSIndicator{
			Code:     "content-served-from-self-service-platform",
			Detail:   fmt.Sprintf("the hostname is an alias for %s, so its content is published through the self service platform %s", resolution.CanonicalName, resolution.AliasedToService),
			Severity: SiteTests.Low,
		})
	}

	// A hostname handed out by a platform is naturally served by that platform's own
	// nameservers, so reporting both would charge the target twice for one fact and
	// escalate the verdict on the strength of a single observation.
	providers := []string{}
	for _, provider := range resolution.NameserverProviders {
		if provider != resolution.HostingService {
			providers = append(providers, provider)
		}
	}
	if len(providers) > 0 {
		indicators = append(indicators, DNSIndicator{
			Code:     "free-dns-provider",
			Detail:   fmt.Sprintf("the zone is served by %s, a provider that hands out DNS hosting for free and without verifying who is asking", strings.Join(providers, ", ")),
			Severity: SiteTests.Medium,
		})
	}

	if resolution.WildcardDNS {
		indicators = append(indicators, DNSIndicator{
			Code:     "wildcard-dns-zone",
			Detail:   "a subdomain that was never configured still resolves, so the zone answers for every possible name, which is how kits give each recipient their own hostname",
			Severity: SiteTests.Medium,
		})
	}

	if !resolution.Resolved {
		detail := "the hostname does not resolve to any address"
		if resolution.LookupError != "" {
			detail += " (" + resolution.LookupError + ")"
		}
		indicators = append(indicators, DNSIndicator{
			Code:     "hostname-does-not-resolve",
			Detail:   detail + ", which is the state a reported phishing domain is left in after it is taken down",
			Severity: SiteTests.Medium,
		})
	}

	if len(resolution.Nameservers) == 1 {
		indicators = append(indicators, DNSIndicator{
			Code:     "single-nameserver",
			Detail:   fmt.Sprintf("the zone is served by a single nameserver (%s), below the redundancy an operated domain is normally given", resolution.Nameservers[0]),
			Severity: SiteTests.Info,
		})
	}

	return indicators
}

// evaluateMailIndicators reads the domain's mail policy as evidence of intent.
func evaluateMailIndicators(resolution DomainResolutionInfo, mail MailAuthenticationInfo) []DNSIndicator {
	indicators := []DNSIndicator{}
	if resolution.HostingServiceKind != "" || !resolution.Resolved {
		return indicators
	}

	if mail.SPFAllowsAnySender {
		indicators = append(indicators, DNSIndicator{
			Code:     "spf-authorises-any-sender",
			Detail:   "the SPF record ends in a catch-all that authorises every sender, leaving the domain as spoofable as one with no record while appearing configured",
			Severity: SiteTests.Medium,
		})
	} else if !mail.SPFPresent {
		indicators = append(indicators, DNSIndicator{
			Code:     "no-spf-policy",
			Detail:   "the domain publishes no SPF record, so anyone can send mail claiming to come from it",
			Severity: SiteTests.Low,
		})
	}

	if !mail.DMARCPresent {
		indicators = append(indicators, DNSIndicator{
			Code:     "no-dmarc-policy",
			Detail:   "the domain publishes no DMARC record, so nothing instructs receivers to reject mail that forges it",
			Severity: SiteTests.Low,
		})
	} else if mail.DMARCPolicy == "none" {
		indicators = append(indicators, DNSIndicator{
			Code:     "dmarc-policy-not-enforced",
			Detail:   "the DMARC record declares p=none, which monitors forgery of the domain without asking anyone to stop it",
			Severity: SiteTests.Info,
		})
	}

	if !mail.MailExchangersPresent {
		indicators = append(indicators, DNSIndicator{
			Code:     "no-mail-exchangers",
			Detail:   "the domain publishes no mail exchanger, so it was never set up to receive mail",
			Severity: SiteTests.Info,
		})
	}

	return indicators
}

// evaluateNetworkIndicators reads the addresses the hostname points at, and the networks
// behind them.
func evaluateNetworkIndicators(networks []AddressNetworkInfo) []DNSIndicator {
	indicators := []DNSIndicator{}
	if len(networks) == 0 {
		return indicators
	}

	inspected := 0
	withoutReverseName := 0
	organizations := map[string]bool{}

	for _, network := range networks {
		if !network.Public {
			indicators = append(indicators, DNSIndicator{
				Code:     "non-public-address",
				Detail:   fmt.Sprintf("the hostname resolves to %s, an address in the %s that no visitor on the internet can reach", network.Address, network.Scope),
				Severity: SiteTests.High,
			})
			continue
		}

		inspected++
		if network.DynamicReverseName {
			indicators = append(indicators, DNSIndicator{
				Code:     "address-in-access-network",
				Detail:   fmt.Sprintf("%s names itself %s, the naming convention access providers use for dynamically assigned consumer addresses rather than for hosting", network.Address, strings.Join(network.ReverseNames, ", ")),
				Severity: SiteTests.Medium,
			})
		}
		if len(network.ReverseNames) == 0 {
			withoutReverseName++
		}
		if network.Organization != "" {
			organizations[strings.ToLower(network.Organization)] = true
		}
		if network.LookupError == "" && network.Organization != "" && !network.AbusePublished {
			indicators = append(indicators, DNSIndicator{
				Code:     "network-without-abuse-contact",
				Detail:   fmt.Sprintf("the block holding %s is allocated to %s and publishes no abuse contact, so a report about content hosted there has nowhere to go", network.Address, network.Organization),
				Severity: SiteTests.Info,
			})
		}
	}

	if inspected > 0 && withoutReverseName == inspected {
		indicators = append(indicators, DNSIndicator{
			Code:     "no-reverse-dns",
			Detail:   "none of the resolved addresses has a reverse name, which is worth noting next to the other observations but is by itself as common on content delivery networks as it is on rented virtual machines",
			Severity: SiteTests.Info,
		})
	}

	if len(organizations) >= multiNetworkThreshold {
		indicators = append(indicators, DNSIndicator{
			Code:     "addresses-across-multiple-operators",
			Detail:   fmt.Sprintf("the inspected addresses are spread across %d unrelated network operators, the shape of a fast-flux setup as well as of a large content delivery network", len(organizations)),
			Severity: SiteTests.Low,
		})
	}

	return indicators
}

// evaluateJurisdictionIndicators compares where the domain is registered with where it is
// hosted.
func evaluateJurisdictionIndicators(metadata DNSReputationMetadata) []DNSIndicator {
	registrantCountry := strings.ToUpper(metadata.Registration.RegistrantCountry)
	if registrantCountry == "" {
		return []DNSIndicator{}
	}

	hostingCountries := []string{}
	for _, network := range metadata.Networks {
		if network.Country == "" {
			continue
		}
		if network.Country == registrantCountry {
			return []DNSIndicator{}
		}
		hostingCountries = append(hostingCountries, network.Country)
	}
	if len(hostingCountries) == 0 {
		return []DNSIndicator{}
	}

	return []DNSIndicator{{
		Code:     "registration-and-hosting-countries-differ",
		Detail:   fmt.Sprintf("the domain is registered to a holder in %s but is served from %s", registrantCountry, strings.Join(SiteTests.UniqueStrings(hostingCountries), ", ")),
		Severity: SiteTests.Info,
	}}
}

// evaluateDNSReputationThreatLevel converts the observations into the reported classification.
func evaluateDNSReputationThreatLevel(indicators []DNSIndicator) SiteTests.ThreatLevel {
	severities := make([]SiteTests.ThreatLevel, 0, len(indicators))
	significant := 0

	for _, indicator := range indicators {
		severities = append(severities, indicator.Severity)
		if indicator.Severity >= SiteTests.Medium {
			significant++
		}
	}

	highest := SiteTests.HighestThreatLevel(severities...)
	if significant >= 2 {
		return SiteTests.EscalateThreatLevel(highest)
	}
	return highest
}

// evaluateDNSReputationCertainty reports how much confidence the verdict deserves.
func evaluateDNSReputationCertainty(metadata DNSReputationMetadata) int {
	gaps := 0
	if !metadata.Registration.Resolved {
		gaps++
	}
	if !metadata.Resolution.Resolved {
		gaps++
	}

	switch {
	case gaps == 0 && len(metadata.Indicators) == 0:
		return dnsReputationCleanCertainty
	case gaps == 0:
		return dnsReputationDerivedCertainty
	case gaps == 1:
		return dnsReputationPartialCertainty
	default:
		return dnsReputationSparseCertainty
	}
}

// buildDNSReputationDescription renders the operator facing explanation of the finding.
func buildDNSReputationDescription(metadata DNSReputationMetadata) string {
	sections := []string{
		describeRegistration(metadata),
		describeResolution(metadata),
	}

	if len(metadata.Indicators) == 0 {
		sections = append(sections, "No phishing indicator was derived from the registration data, the zone or the address reputation of this target.")
		return strings.Join(sections, " ")
	}

	findings := make([]string, 0, len(metadata.Indicators))
	for _, indicator := range metadata.Indicators {
		findings = append(findings, fmt.Sprintf("  - [%s] %s: %s", indicator.Severity, indicator.Code, indicator.Detail))
	}

	return strings.Join(sections, " ") + fmt.Sprintf("\n%d observation(s) relevant to phishing:\n", len(metadata.Indicators)) + strings.Join(findings, "\n")
}

// describeRegistration renders the registration facts as a sentence.
func describeRegistration(metadata DNSReputationMetadata) string {
	registration := metadata.Registration
	if !registration.Resolved {
		return fmt.Sprintf("No registration record is published for %s, so the domain's age, registrar and holder could not be established.", metadata.RegistrableDomain)
	}

	sentence := fmt.Sprintf("The domain %s is registered", registration.Domain)
	if registration.Registrar != "" {
		sentence += " through " + registration.Registrar
		if registration.RegistrarCountry != "" {
			sentence += " (" + registration.RegistrarCountry + ")"
		}
	} else {
		sentence += ", through an unnamed registrar,"
	}

	if registration.Registered != nil {
		sentence += fmt.Sprintf(", was created on %s (%d day(s) ago)", registration.Registered.Format("2006-01-02"), registration.AgeDays)
	}
	if registration.TenureDays >= 0 {
		sentence += fmt.Sprintf(" and has been held by its current holder for %d day(s)", registration.TenureDays)
	}
	if registration.Expires != nil {
		sentence += fmt.Sprintf(", with the current registration period running until %s", registration.Expires.Format("2006-01-02"))
	}
	sentence += "."

	// Without this caveat the sentence reads as the age of the scanned site, when for a
	// hostname handed out by a platform it is the age of the platform's own domain — the
	// difference between "this site has existed for eleven years" and "the company that
	// gave somebody this hostname has".
	if metadata.Resolution.HostingService != "" {
		sentence += fmt.Sprintf(
			" That record describes %s, the platform %s was handed out by, and says nothing about who publishes this page or since when.",
			metadata.Resolution.HostingService, metadata.Host,
		)
	}

	return sentence
}

// describeResolution renders where the hostname points as a sentence.
func describeResolution(metadata DNSReputationMetadata) string {
	resolution := metadata.Resolution
	if !resolution.Resolved {
		return fmt.Sprintf("The hostname %s does not currently resolve to any address.", metadata.Host)
	}

	addresses := len(resolution.IPv4Addresses) + len(resolution.IPv6Addresses)
	sentence := fmt.Sprintf("It resolves to %d address(es)", addresses)

	operators := []string{}
	for _, network := range metadata.Networks {
		operator := network.Organization
		if operator == "" {
			operator = network.Network
		}
		if operator == "" {
			continue
		}
		if network.Country != "" {
			operator += " (" + network.Country + ")"
		}
		operators = append(operators, operator)
	}
	if len(operators) > 0 {
		sentence += ", hosted by " + strings.Join(SiteTests.UniqueStrings(operators), ", ")
	}
	if len(resolution.Nameservers) > 0 {
		sentence += fmt.Sprintf(", and its zone is served by %s", strings.Join(resolution.Nameservers, ", "))
	}

	return sentence + "."
}

// --------------------------------------------------------------------------
// Evidence acquisition: DNS and RDAP
// --------------------------------------------------------------------------
//
// This section gathers everything the verdict is built from and never decides
// anything itself, so the evaluation above stays a pure function of the collected
// facts and can be exercised without touching the network.
//
// Two independent sources are queried, both of them free to use at any volume:
//
//   - RDAP (Registration Data Access Protocol), the successor of WHOIS, answers
//     who registered the domain, through which registrar, when, until when and
//     when the registration was last transferred or modified. The same protocol
//     answers which organisation the resolved IP addresses are allocated to.
//   - The DNS itself answers where the hostname points: address records, the
//     canonical name it is aliased to, the nameservers serving the zone, the mail
//     exchangers, the SPF and DMARC policies and the reverse names of every
//     resolved address.
//
// Every lookup is bounded by its own timeout and every failure is recorded in the
// metadata rather than propagated, because a scan of an unreachable or heavily
// filtered target must still produce a report. No function here panics.

// isAbuseProneTopLevelDomain reports whether a top level domain is one of those whose
// registration terms make it a standing fixture of published abuse rankings.
func isAbuseProneTopLevelDomain(tld string) bool {
	return abuseProneTopLevelDomains[strings.ToLower(strings.TrimPrefix(tld, "."))]
}
