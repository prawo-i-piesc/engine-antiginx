// Package SensitiveFilesTest implements the Sensitive File Exposure security test: a small
// targeted dirbuster that requests a shared list of known-sensitive files from the server.
// See README.md for what it checks, how it grades and what it reports.
package SensitiveFilesTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitiveFilesTest/modules"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
)

// prober carries the limits from config.go into the sweep stage.
var prober = modules.Prober{
	Timeout:          probeTimeout,
	MaxBodyBytes:     maxBodyBytes,
	MaxConcurrency:   maxConcurrency,
	SoftMatchPercent: softMatchPercent,
}

// grader wires the category-to-severity map from data.go and the escalation threshold from
// config.go into the judgement stage.
var grader = modules.Grader{SeverityFor: severityFor, EscalationCount: escalationCount}

// candidates is the shared sensitive-files list converted into what the prober requests. It
// is built once: the list does not change between scans.
var candidates = buildCandidates()

// New creates a new security test that requests known sensitive files from the target.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			analysis := prober.Sweep(SiteTests.BaseURL(params.Target), candidates)

			certainty := noExposureCertainty
			if len(analysis.Exposures) > 0 {
				certainty = exposureFoundCertainty
			}

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   certainty,
				ThreatLevel: grader.EvaluateThreat(analysis),
				Metadata:    analysis,
				Description: modules.Describe(analysis),
			}
		},
	}
}

// buildCandidates converts the shared SensitivePaths list into the prober's candidates.
func buildCandidates() []modules.Candidate {
	list := make([]modules.Candidate, 0, len(SensitivePaths.Files))
	for _, file := range SensitivePaths.Files {
		list = append(list, modules.Candidate{Path: file.Path, Category: file.Category})
	}
	return list
}
