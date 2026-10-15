package CacheControlTest

// Identity of the test.
const (
	TestId          = "cache-control"
	TestName        = "Cache-Control Analysis"
	TestDescription = "Checks whether a page that sets a session cookie or contains a password field can be stored in a shared cache, and whether Pragma: no-cache is the only protection against caching"
	TestCategory    = "App-Configuration"
)

// Confidence in the verdict.
const (
	cacheFactCertainty    = 100 // Headers are read straight from the response
	cacheContentCertainty = 85  // A password field is found by scanning markup, not by rendering it
)

// maxScannedBody caps how much of the page is searched for password fields.
const maxScannedBody = 2 * 1024 * 1024
