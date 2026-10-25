// Package SitemapSecurityTest implements the Sitemap Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest/modules"
)

// fetcher wires the pattern table and the limits from config.go into the retrieval stage:
// this package's own fragments for dangerous locations, plus every file from the shared
// SensitivePaths list, so a sensitive file a sitemap declares is flagged by the same
// definition SensitiveFilesTest probes the server with.
var fetcher = modules.Fetcher{
	DangerousPatterns: withSensitiveFiles(DangerousPatterns),
	Timeout:           FetchTimeout,
	MaxBodyBytes:      MaxBodyBytes,
}

// withSensitiveFiles returns the dangerous-pattern table extended with the shared sensitive
// files. A local fragment already present is kept, since this package's wording is more
// specific than the shared category.
func withSensitiveFiles(patterns map[string]string) map[string]string {
	merged := SensitivePaths.AsPatterns()
	for pattern, category := range patterns {
		merged[pattern] = category
	}
	return merged
}

// New creates a new security test that analyzes sitemap.xml for dangerous path exposure
// vulnerabilities.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			// Fetch sitemap.xml
			analysis := fetcher.Analyze(SiteTests.BaseURL(params.Target))

			// Determine threat level based on dangerous paths found
			threatLevel := modules.EvaluateThreat(analysis)

			// Generate description
			description := modules.Describe(analysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   90,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}
