package XContentTypeOptionsTest

// Identity of the test.
const (
	TestId          = "x-content-type-options"
	TestName        = "X-Content-Type-Options Header Analysis"
	TestDescription = "Checks for X-Content-Type-Options header to prevent MIME type sniffing attacks"
	TestCategory    = "Headers"
)

// missingDescription explains the verdict when the response carries no X-Content-Type-Options header.
const missingDescription = "Missing X-Content-Type-Options header - browsers may MIME-sniff content leading to potential XSS vulnerabilities"

// Certainty reported when the header is present; an absent header is always reported with
// full certainty.
const Certainty = 100
