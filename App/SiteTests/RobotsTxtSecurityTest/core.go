// Package RobotsTxtSecurityTest implements the Robots.txt Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package RobotsTxtSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/RobotsTxtSecurityTest/modules"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest"
)

// fetcher wires the pattern table into the retrieval stage, in rising order of specificity:
// the shared SensitivePaths files (the same list SitemapSecurityTest and SensitiveFilesTest
// use), then the sitemap's dangerous-location fragments, then this package's own additions,
// with the later tables winning on a shared key.
var fetcher = modules.Fetcher{
	DangerousPatterns: mergePatterns(SensitivePaths.AsPatterns(), SitemapSecurityTest.DangerousPatterns, extraPatterns),
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
			// Extract base URL from the target
			baseUrl := params.Target.Scheme + "://" + params.Target.Host

			// Fetch and parse robots.txt
			analysis := fetcher.Analyze(baseUrl)

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

// mergePatterns copies the tables into one, later tables overriding earlier ones.
func mergePatterns(tables ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, table := range tables {
		for pattern, category := range table {
			merged[pattern] = category
		}
	}
	return merged
}
