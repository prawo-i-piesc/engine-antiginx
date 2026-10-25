// Package SitemapSecurityTest implements the Sitemap Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest/modules"
)

// fetcher wires the pattern table and the limits from config.go into the retrieval stage:
// every file from the shared SensitivePaths list, so a sensitive file a sitemap declares is
// flagged by the same definition SensitiveFilesTest probes the server with, then the shared
// dangerous-location fragments, whose more specific wording wins on a shared key.
var fetcher = modules.Fetcher{
	DangerousPatterns: SensitivePaths.Merge(SensitivePaths.AsPatterns(), SensitivePaths.Locations),
	Timeout:           FetchTimeout,
	MaxBodyBytes:      MaxBodyBytes,
}

// grader carries the thresholds from config.go into the judgement stage.
var grader = modules.Grader{Thresholds: SiteTests.CountThresholds{
	LowMax:    LowMaxPaths,
	MediumMax: MediumMaxPaths,
	HighMax:   HighMaxPaths,
}}

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
