package RobotsTxtSecurityTest

import "time"

// Identity of the test.
const (
	TestId          = "robots-txt"
	TestName        = "Robots.txt Security Analysis"
	TestDescription = "Analyzes robots.txt for rules that reveal or expose sensitive application paths"
	TestCategory    = "App-Configuration"
)

// Retrieval limits.
const (
	// FetchTimeout bounds the whole robots.txt request, redirects included.
	FetchTimeout = 30 * time.Second
	// MaxBodyBytes is how much of the file is read; Google stops parsing at 500 KiB as well.
	MaxBodyBytes = 500 * 1024
)

// Certainty reported with every result. Matching is by path fragment, so a hit is very
// likely, but not certain, to point at something sensitive.
const Certainty = 90
