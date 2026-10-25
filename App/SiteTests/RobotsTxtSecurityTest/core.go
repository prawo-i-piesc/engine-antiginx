// Package RobotsTxtSecurityTest implements the Robots.txt Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package RobotsTxtSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/RobotsTxtSecurityTest/modules"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
)

// fetcher wires the pattern table into the retrieval stage, in rising order of specificity:
// the shared SensitivePaths files (the same list SitemapSecurityTest and SensitiveFilesTest
// use), then the shared dangerous-location fragments, then this package's own additions,
// with the later tables winning on a shared key.
var fetcher = modules.Fetcher{
	DangerousPatterns: SensitivePaths.Merge(SensitivePaths.AsPatterns(), SensitivePaths.Locations, extraPatterns),
	Timeout:           FetchTimeout,
	MaxBodyBytes:      MaxBodyBytes,
}

// New creates a new security test that analyzes robots.txt for rules revealing or exposing
// sensitive application paths.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			// Fetch and parse robots.txt
			analysis := fetcher.Analyze(SiteTests.BaseURL(params.Target))

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   Certainty,
				ThreatLevel: modules.EvaluateThreat(analysis),
				Metadata:    analysis,
				Description: modules.Describe(analysis),
			}
		},
	}
}
