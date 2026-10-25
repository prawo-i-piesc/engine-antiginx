// Package DirectoryListingTest implements the Directory Listing Detection security test.
// See README.md for what it checks, how it grades and what it reports.
package DirectoryListingTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/DirectoryListingTest/modules"
	"path"
	"strings"
)

// scanner wires the signatures from data.go and the limits from config.go into the probe stage.
var scanner = modules.Scanner{
	Signatures:       listingSignatures,
	Timeout:          probeTimeout,
	MaxBodyBytes:     maxBodyBytes,
	MaxConcurrency:   maxConcurrency,
	MaxSampleEntries: maxSampleEntries,
}

// grader carries the escalation threshold from config.go into the judgement stage.
var grader = modules.Grader{EscalationCount: escalationCount}

// New creates a new security test that checks whether the target serves directory listings.
func New() *SiteTests.StructureTest {
	return &SiteTests.StructureTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.StructureTestParams) SiteTests.TestResult {
			// Extract base URL from the target
			baseUrl := params.Target.Scheme + "://" + params.Target.Host

			analysis := scanner.Scan(baseUrl, probes(params.Target.Path))

			certainty := noListingCertainty
			if analysis.TotalListings > 0 {
				certainty = listingFoundCertainty
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

// probes lists the directories to request: the common and sensitive ones, plus every
// directory on the way to the scanned page, since that is where its own files are.
func probes(targetPath string) []modules.Probe {
	list := []modules.Probe{}
	seen := map[string]bool{}
	add := func(directory string, sensitive bool) {
		if !seen[directory] {
			seen[directory] = true
			list = append(list, modules.Probe{Path: directory, Sensitive: sensitive})
		}
	}

	for _, directory := range commonDirectories {
		add(directory, false)
	}
	for _, directory := range sensitiveDirectories {
		add(directory, true)
	}

	directory := targetPath
	if !strings.HasSuffix(directory, "/") {
		directory = path.Dir(directory)
	}
	for directory != "" && directory != "/" && directory != "." {
		add(strings.TrimSuffix(directory, "/")+"/", false)
		directory = path.Dir(strings.TrimSuffix(directory, "/"))
	}

	return list
}
