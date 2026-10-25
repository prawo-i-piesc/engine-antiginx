package XFrameTest

// Identity of the test.
const (
	TestId          = "xframe"
	TestName        = "X-Frame-Options & CSP Frame Protection Analysis"
	TestDescription = "Analyzes X-Frame-Options header and CSP frame-ancestors directive to assess clickjacking protection and iframe embedding policies"
	TestCategory    = "Headers"
)

// Certainty reported with every result; the verdict is read straight from the headers.
const Certainty = 100
