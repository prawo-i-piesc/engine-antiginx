// Package SitemapSecurityTest implements the Sitemap Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest/modules"
)

// fetcher wires the pattern table into the retrieval stage: every file from the shared
// SensitivePaths list, so a sensitive file a sitemap declares is flagged by the same
// definition SensitiveFilesTest probes the server with, then this package's own fragments
// for dangerous locations, which win on a shared key since their wording is more specific.
var fetcher = modules.Fetcher{
	Matcher:      SensitivePaths.Matcher(SensitivePaths.Merge(SensitivePaths.AsPatterns(), DangerousPatterns)),
	Timeout:      FetchTimeout,
	MaxBodyBytes: MaxBodyBytes,
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
			// Extract base URL from the target
			baseUrl := params.Target.Scheme + "://" + params.Target.Host

			analysis := fetcher.Analyze(baseUrl)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   90,
				ThreatLevel: modules.EvaluateThreat(analysis),
				Metadata:    analysis,
				Description: modules.Describe(analysis),
			}
		},
	}
}
