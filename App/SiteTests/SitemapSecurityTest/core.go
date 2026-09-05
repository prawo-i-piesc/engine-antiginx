// Package SitemapSecurityTest implements the Sitemap Security Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package SitemapSecurityTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SitemapSecurityTest/modules"
)

// fetcher wires the pattern table owned by this package into the retrieval stage.
var fetcher = modules.Fetcher{DangerousPatterns: dangerousPatterns}

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

			// Fetch sitemap.xml
			analysis := fetcher.Analyze(baseUrl)

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
