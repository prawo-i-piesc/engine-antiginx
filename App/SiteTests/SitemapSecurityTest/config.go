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
	// FetchTimeout bounds the whole sitemap request, redirects included.
	FetchTimeout = 30 * time.Second
	// MaxBodyBytes is how much of the sitemap is read. The sitemap protocol caps a file at
	// 50 MiB uncompressed, but the URLs that matter sit in the first few, and a bound keeps a
	// hostile target from streaming an endless body.
	MaxBodyBytes = 10 * 1024 * 1024
)
