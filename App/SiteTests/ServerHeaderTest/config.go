package ServerHeaderTest

// Identity of the test.
const (
	TestId          = "serv-h-a"
	TestName        = "Server Technology Disclosure Analysis"
	TestDescription = "Analyzes HTTP headers for information disclosure about server technology, frameworks, and hosting services"
	TestCategory    = "App-Configuration"
)

// Certainty reported with every result. Disclosure is read straight from the headers, but
// recognising a technology from a header value is pattern matching.
const Certainty = 95
