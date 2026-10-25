package URLhausTest

import "time"

// Identity of the test.
const (
	TestId          = "urlhaus"
	TestName        = "URLhaus Malicious URL Lookup"
	TestDescription = "Checks the target URL and its host against URLhaus, the abuse.ch database of URLs distributing malware"
	TestCategory    = "Phishing"
)

// Certainty levels reported by the test, as confidence that the verdict describes the target.
const (
	listedURLCertainty         = 100 // The exact URL is in the database
	listedHostCertainty        = 90  // The host is in the database, the URL itself is not
	abusedServiceCertainty     = 70  // The host is a legitimate service that was abused
	cleanCertainty             = 80  // Not listed, but a single blocklist cannot prove a site safe
	lookupUnavailableCertainty = 100 // Nothing was looked up, and the result says exactly that
)

// Lookup limits.
const (
	lookupTimeout   = 8 * time.Second // Budget for one URLhaus request
	maxResponseSize = 2 * 1024 * 1024 // Bytes of a URLhaus answer that are read
	maxReportedURLs = 10              // Listed URLs of the host copied into the metadata
)

// authKeyEnvVar names the variable holding the abuse.ch Auth-Key, free from
// https://auth.abuse.ch/. Without it the test reports that no lookup was made.
const authKeyEnvVar = "ANTIGINX_URLHAUS_AUTH_KEY"

// baseURLEnvVar lets a deployment point the lookups at a mirror, and tests at a local server.
const baseURLEnvVar = "ANTIGINX_URLHAUS_URL"

// defaultBaseURL is the public URLhaus API.
const defaultBaseURL = "https://urlhaus-api.abuse.ch"
