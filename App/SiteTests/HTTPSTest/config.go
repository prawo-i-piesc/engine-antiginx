package HTTPSTest

// Identity of the test.
const (
	TestId          = "https"
	TestName        = "HTTPS Protocol Verification"
	TestDescription = "Verifies if the website communication is secured with HTTPS protocol"
	TestCategory    = "Encryption"
)

// detectionCertainty is reported for every verdict this test produces.
const detectionCertainty = 100

// secureScheme is the URL scheme that satisfies the test.
const secureScheme = "https"
