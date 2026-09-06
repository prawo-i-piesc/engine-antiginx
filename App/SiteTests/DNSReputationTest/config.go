package DNSReputationTest

import "time"

// Identity of the test.
const (
	TestId          = "dns-reputation"
	TestName        = "DNS and Domain Registration Analysis"
	TestDescription = "Analyses where and when the domain was registered, how long it has been held by its current holder, which networks it resolves into and how the zone, its mail policy and those networks are configured"
	TestCategory    = "Phishing"
)

// Certainty levels reported by the test, expressed as the confidence that the verdict
// describes the target rather than the completeness of the lookup.
const (
	dnsReputationCleanCertainty   = 100 // Both sources answered and neither found anything
	dnsReputationDerivedCertainty = 90  // Both sources answered and the verdict is derived from them
	dnsReputationPartialCertainty = 75  // One of the two sources could not be consulted
	dnsReputationSparseCertainty  = 55  // Neither source could be consulted
)

// Day thresholds separating the registration age bands.
const (
	freshRegistrationDays   = 30  // Registered within the last month
	recentRegistrationDays  = 90  // Registered within the last quarter
	youngRegistrationDays   = 365 // Registered within the last year
	recentTransferDays      = 60  // Changed holder within the last two months
	recentModificationDays  = 14  // Registration record modified within the last fortnight
	expiringSoonDays        = 30  // Registration lapses within the next month
	minimumRegistrationDays = 366 // Bought for the shortest period a registry sells
	multiNetworkThreshold   = 3   // Distinct operators among the inspected addresses
)

// Timeouts and budgets applied to the intelligence gathering stage.
const (
	dnsLookupTimeout      = 4 * time.Second // Budget for one batch of DNS queries
	rdapLookupTimeout     = 6 * time.Second // Budget for one RDAP request, redirects included
	maxInspectedAddresses = 4               // Resolved addresses inspected in depth
)

// rdapBaseURLEnvVar lets a deployment redirect registration lookups at an internal mirror or
// at a registry endpoint, without rebuilding the engine.
const rdapBaseURLEnvVar = "ANTIGINX_RDAP_URL"

// defaultRDAPBaseURL is the bootstrap aggregator queried for registration data.
const defaultRDAPBaseURL = "https://rdap.org"
