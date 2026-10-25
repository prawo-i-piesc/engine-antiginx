// Package ServerHeaderTest implements the Server Technology Disclosure Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package ServerHeaderTest

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest/modules"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// technologyDetector wires the signature tables owned by this package into the detection
// stage, so the algorithm in modules stays free of any particular vendor's name.
var technologyDetector = modules.TechnologyDetector{
	Signatures:    technologySignatures,
	DirectHeaders: directTechnologyHeaders,
}

// ServerHeaderAnalysis represents the comprehensive analysis results of HTTP headers for
// server technology information disclosure.
type ServerHeaderAnalysis struct {
	ExposedHeaders  []string          `json:"exposed_headers"`  // Headers that disclosed anything, in the order they are read
	Technologies    []string          `json:"technologies"`     // Technologies recognised in them, without repeats
	TotalExposures  int               `json:"total_exposures"`  // How many headers disclosed anything
	HeaderDetails   map[string]string `json:"header_details"`   // Each exposed header mapped to its value
	TechnologyStack map[string]string `json:"technology_stack"` // Each technology mapped to its version, or "detected"

	// Vulnerabilities holds the NVD lookup of every disclosed release with a known CPE product,
	// in the order the technologies were found
	Vulnerabilities []ReleaseVulnerabilities `json:"vulnerabilities"`
	// Unattributed lists the technologies disclosed without a release number, or without a
	// CPE product to look them up by, so that no CVE can be said to affect them
	Unattributed []string `json:"unattributed"`
}

// ReleaseVulnerabilities is what NVD records against one disclosed release.
type ReleaseVulnerabilities struct {
	Technology   string        `json:"technology"`
	Version      string        `json:"version"`
	CPE          string        `json:"cpe"`
	CVECount     int           `json:"cve_count"`
	TotalResults int           `json:"total_results"`
	Unscored     int           `json:"unscored"`
	MaxSeverity  string        `json:"max_severity"` // CVSS rating of the most severe CVE, "" when none is scored
	RiskLevel    string        `json:"risk_level"`   // MaxSeverity, or UNSCORED / NONE, see CVE.VulnerabilityAssessment
	MaxScore     float64       `json:"max_score"`
	MostSevere   []CVEOverview `json:"most_severe"` // The most severe CVEs, at most maxReportedCVEs
	LookupError  string        `json:"lookup_error,omitempty"`
}

// CVEOverview is one CVE as the report shows it.
type CVEOverview struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	CVSSVersion string  `json:"cvss_version"`
	ScoredBy    string  `json:"scored_by"`
}

// lookupRelease asks NVD which CVEs affect one release. Tests point it at a local stand-in
// through CVE.BaseURLEnv.
var lookupRelease = func(technology string, version string) (*CVE.VulnerabilityAssessment, error) {
	return CVE.NewCVEClient().AssessTechnologyVulnerabilities(technology, version)
}

// New creates a new security test that analyzes HTTP response headers for server technology
// information disclosure vulnerabilities.
func New() *SiteTests.ResponseTest {
	return &SiteTests.ResponseTest{
		Id:          TestId,
		Name:        TestName,
		Description: TestDescription,
		Category:    TestCategory,
		RunTest: func(params SiteTests.ResponseTestParams) SiteTests.TestResult {
			analysis := analyzeServerHeaders(params.Response.Header)
			assessVulnerabilities(analysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   Certainty,
				ThreatLevel: evaluateServerExposureThreatLevel(analysis),
				Metadata:    analysis,
				Description: generateServerExposureDescription(analysis),
			}
		},
	}
}

// analyzeServerHeaders examines HTTP headers for technology disclosure patterns and constructs
// a comprehensive analysis of exposed information.
func analyzeServerHeaders(headers http.Header) *ServerHeaderAnalysis {
	analysis := &ServerHeaderAnalysis{
		ExposedHeaders:  []string{},
		Technologies:    []string{},
		HeaderDetails:   map[string]string{},
		TechnologyStack: map[string]string{},
		Vulnerabilities: []ReleaseVulnerabilities{},
		Unattributed:    []string{},
	}

	// Read in the fixed header order, so the report does not depend on map order
	technologies := []string{}
	for _, headerName := range exposureHeaderNames {
		headerValue := headers.Get(headerName)
		if headerValue == "" {
			continue
		}
		analysis.ExposedHeaders = append(analysis.ExposedHeaders, headerName)
		analysis.HeaderDetails[headerName] = headerValue

		detectedTech := technologyDetector.Detect(headerName, headerValue)
		names := make([]string, 0, len(detectedTech))
		for tech := range detectedTech {
			names = append(names, tech)
		}
		sort.Strings(names)
		for _, tech := range names {
			technologies = append(technologies, tech)
			if version := detectedTech[tech]; version != "" {
				analysis.TechnologyStack[tech] = version
			} else {
				analysis.TechnologyStack[tech] = "detected"
			}
		}
	}

	analysis.TotalExposures = len(analysis.ExposedHeaders)
	analysis.Technologies = SiteTests.UniqueStrings(technologies)
	return analysis
}

// assessVulnerabilities looks up every disclosed release that has a CPE product in NVD. A CVE
// is only attributed to a release NVD records as affected, so a technology disclosed without a
// release number gets no CVEs at all rather than every CVE ever filed against it.
func assessVulnerabilities(analysis *ServerHeaderAnalysis) {
	for _, technology := range analysis.Technologies {
		version := analysis.TechnologyStack[technology]
		if _, known := CVE.ProductFor(technology); !known || !CVE.IsReleaseVersion(version) {
			analysis.Unattributed = append(analysis.Unattributed, technology)
			continue
		}

		release := ReleaseVulnerabilities{Technology: technology, Version: version, MostSevere: []CVEOverview{}}
		assessment, err := lookupRelease(technology, version)
		if err != nil {
			release.LookupError = err.Error()
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, release)
			continue
		}

		release.CPE = assessment.CPE
		release.CVECount = assessment.CVECount
		release.TotalResults = assessment.TotalResults
		release.Unscored = assessment.Unscored
		release.MaxSeverity = assessment.MaxSeverity
		release.RiskLevel = assessment.RiskLevel
		release.MaxScore = assessment.MaxScore
		release.MostSevere = mostSevere(assessment.CVEs, maxReportedCVEs)
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, release)
	}
}

// mostSevere returns up to limit CVEs, most severe first, then highest score, then by ID.
func mostSevere(cves []CVE.CVEResult, limit int) []CVEOverview {
	sorted := append([]CVE.CVEResult(nil), cves...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return CVE.MoreSevere(sorted[i].Severity, sorted[j].Severity)
		}
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		return sorted[i].ID < sorted[j].ID
	})

	overview := []CVEOverview{}
	for _, cve := range sorted[:min(len(sorted), limit)] {
		overview = append(overview, CVEOverview{
			ID:          cve.ID,
			Severity:    cve.Severity,
			Score:       cve.Score,
			CVSSVersion: cve.CVSSVersion,
			ScoredBy:    cve.ScoredBy,
		})
	}
	return overview
}

// evaluateServerExposureThreatLevel grades the response by the worse of two things: what the
// headers disclose, and the CVSS rating of the most severe CVE NVD records against a
// disclosed release.
func evaluateServerExposureThreatLevel(analysis *ServerHeaderAnalysis) SiteTests.ThreatLevel {
	releaseDisclosed := false
	for _, technology := range analysis.Technologies {
		if CVE.IsReleaseVersion(analysis.TechnologyStack[technology]) {
			releaseDisclosed = true
		}
	}
	level := modules.DisclosureThreat(analysis.TotalExposures, releaseDisclosed, lowExposureCount, mediumExposureCount)

	for _, release := range analysis.Vulnerabilities {
		if release.LookupError != "" {
			continue
		}
		level = SiteTests.HighestThreatLevel(level, modules.MapCVEThreat(release.RiskLevel))
	}
	return level
}

// generateServerExposureDescription creates a human-readable description of server header
// information disclosure findings and of the CVEs affecting the disclosed releases.
func generateServerExposureDescription(analysis *ServerHeaderAnalysis) string {
	if analysis.TotalExposures == 0 {
		return "No server technology information disclosed in headers - good security practice"
	}

	description := ""
	if analysis.TotalExposures == 1 {
		description = "1 header exposes server information"
	} else {
		description = strconv.Itoa(analysis.TotalExposures) + " headers expose server information"
	}
	if len(analysis.Technologies) > 0 {
		description += ". Detected technologies: " + strings.Join(analysis.Technologies, ", ")
	}
	description += "."

	for _, release := range analysis.Vulnerabilities {
		description += " " + describeRelease(release)
	}
	if len(analysis.Unattributed) > 0 {
		description += " No release number that NVD can be searched by is disclosed for " +
			strings.Join(analysis.Unattributed, ", ") + ", so no CVE is attributed to it."
	}
	return description
}

// describeRelease states what NVD records against one release, quoting the CVSS rating of the
// most severe CVE and naming the CVEs that carry it.
func describeRelease(release ReleaseVulnerabilities) string {
	name := release.Technology + " " + release.Version
	switch {
	case release.LookupError != "":
		return "The NVD lookup for " + name + " failed, so its known vulnerabilities could not be checked."
	case release.CVECount == 0:
		return "NVD records no CVE affecting " + name + "."
	case release.MaxSeverity == CVE.SeverityUnscored:
		return fmt.Sprintf("NVD records %d CVE(s) affecting %s, none of them scored with CVSS yet.", release.CVECount, name)
	}

	ids := []string{}
	for _, cve := range release.MostSevere {
		if cve.Severity == release.MaxSeverity {
			ids = append(ids, cve.ID)
		}
	}
	text := fmt.Sprintf("NVD records %d CVE(s) affecting %s; the most severe are rated %s (CVSS base score %.1f): %s.",
		release.CVECount, name, release.MaxSeverity, release.MaxScore, strings.Join(ids, ", "))
	if release.Unscored > 0 {
		text += fmt.Sprintf(" %d more are not scored yet.", release.Unscored)
	}
	return text
}
