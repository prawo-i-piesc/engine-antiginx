// Package RobotsTxtSecurityTest implements the Robots.txt Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package RobotsTxtSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/RobotsTxtSecurityTest/modules"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest"
)

// fetcher wires the sitemap pattern table, extended by this package's own, into the
// retrieval stage.
var fetcher = modules.Fetcher{
	DangerousPatterns: mergePatterns(SitemapSecurityTest.DangerousPatterns, extraPatterns),
	Timeout:           FetchTimeout,
	MaxBodyBytes:      MaxBodyBytes,
}

// grader carries the thresholds from config.go into the judgement stage.
var grader = modules.Grader{
	LowMax:    LowMaxRules,
	MediumMax: MediumMaxRules,
	HighMax:   HighMaxRules,
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
				ThreatLevel: grader.EvaluateThreat(analysis),
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
