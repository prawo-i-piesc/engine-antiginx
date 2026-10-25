package SitemapSecurityTest

import "time"

// Identity of the test.
const (
	TestId          = "sitemap"
	TestName        = "Sitemap Security Analysis"
	TestDescription = "Analyzes sitemap.xml for dangerous paths that should not be exposed to search engines"
	TestCategory    = "App-Configuration"
)

// Retrieval limits.
const (
	// FetchTimeout bounds the whole sitemap.xml request, redirects included.
	FetchTimeout = 30 * time.Second
	// MaxBodyBytes is how much of the sitemap is read; the protocol caps a sitemap at 50 MiB,
	// but the paths worth reporting show up long before that.
	MaxBodyBytes = 10 * 1024 * 1024
)

// Thresholds on the number of dangerous paths, each the highest count graded at that level.
const (
	LowMaxPaths    = 2
	MediumMaxPaths = 5
	HighMaxPaths   = 10
)

// Certainty reported with every result. Matching is by path fragment, so a hit is very
// likely, but not certain, to point at something sensitive.
const Certainty = 90
