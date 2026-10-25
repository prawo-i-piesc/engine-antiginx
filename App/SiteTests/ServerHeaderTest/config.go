package ServerHeaderTest

// Identity of the test.
const (
	TestId          = "serv-h-a"
	TestName        = "Server Technology Disclosure Analysis"
	TestDescription = "Analyzes HTTP headers for information disclosure about server technology, frameworks, and hosting services"
	TestCategory    = "App-Configuration"
)

// Certainty reported with every result. Disclosure is read straight from the headers, and CVEs
// are attributed through NVD's own affected-version data; recognising a technology from a
// header value remains pattern matching.
const Certainty = 95

// Exposure counts at which disclosure alone is graded Low and Medium.
const (
	lowExposureCount    = 3
	mediumExposureCount = 5
)

// maxReportedCVEs is how many CVEs per release the metadata lists, most severe first.
const maxReportedCVEs = 5
