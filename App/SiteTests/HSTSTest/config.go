package HSTSTest

// Identity of the test.
const (
	TestId          = "hsts"
	TestName        = "HSTS Header Analysis"
	TestDescription = "Checks for HTTP Strict Transport Security header presence and configuration"
	TestCategory    = "Encryption"
)

// missingDescription explains the verdict when the response carries no Strict-Transport-Security header.
const missingDescription = "Missing HSTS header - site vulnerable to protocol downgrade attacks and man-in-the-middle attacks"

// Certainty reported when the header is present; an absent header is always reported with
// full certainty.
const Certainty = 95
