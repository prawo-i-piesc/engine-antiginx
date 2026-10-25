// Package ServerHeaderTest implements the Server Technology Disclosure Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package ServerHeaderTest

import (
	"Engine-AntiGinx/App/CVE"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest/modules"
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
}

// cveThreat grades the known vulnerabilities of one technology. It queries the NVD, so tests
// replace it to stay offline.
var cveThreat = func(technology string) SiteTests.ThreatLevel {
	assessment, err := CVE.NewCVEClient().AssessTechnologyVulnerabilities(technology, "")
	if err != nil || assessment.CVECount == 0 {
		return SiteTests.None
	}
	return modules.MapCVEThreat(*assessment)
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

// evaluateServerExposureThreatLevel calculates the security threat level based on server
// header information disclosure and known vulnerabilities.
func evaluateServerExposureThreatLevel(analysis *ServerHeaderAnalysis) SiteTests.ThreatLevel {
	totalExposures := analysis.TotalExposures
	technologies := analysis.Technologies

	// Base threat level assessment
	baseThreatLevel := SiteTests.None
	if totalExposures >= 5 {
		baseThreatLevel = SiteTests.Medium
	} else if totalExposures >= 3 {
		baseThreatLevel = SiteTests.Low
	} else if totalExposures > 0 {
		baseThreatLevel = SiteTests.Info
	}

	// Enhanced threat assessment with CVE vulnerability analysis
	if len(technologies) > 0 {
		highestThreatLevel := baseThreatLevel

		// Assess CVE vulnerabilities for each detected technology
		for _, tech := range technologies {
			highestThreatLevel = SiteTests.HighestThreatLevel(highestThreatLevel, cveThreat(tech))
		}

		// Additional heuristic-based threat level enhancement
		for _, tech := range technologies {
			lowerTech := strings.ToLower(tech)

			// High-risk technologies or configurations
			if strings.Contains(lowerTech, "debug") ||
				strings.Contains(lowerTech, "test") ||
				strings.Contains(lowerTech, "dev") {
				if SiteTests.Critical > highestThreatLevel {
					highestThreatLevel = SiteTests.Critical
				}
			}

			// Medium-risk patterns
			if strings.Contains(lowerTech, "apache") ||
				strings.Contains(lowerTech, "nginx") ||
				strings.Contains(lowerTech, "iis") {
				if SiteTests.High > highestThreatLevel {
					highestThreatLevel = SiteTests.High
				}
			}
		}

		return highestThreatLevel
	}

	return baseThreatLevel
}

// generateServerExposureDescription creates a human-readable description of server header
// information disclosure findings.
func generateServerExposureDescription(analysis *ServerHeaderAnalysis) string {
	totalExposures := analysis.TotalExposures
	technologies := analysis.Technologies

	if totalExposures == 0 {
		return "No server technology information disclosed in headers - good security practice"
	}

	description := ""
	if totalExposures == 1 {
		description = "1 header exposes server information"
	} else {
		description = strconv.Itoa(totalExposures) + " headers expose server information"
	}

	if len(technologies) > 0 {
		description += ". Detected technologies: " + strings.Join(technologies, ", ")
	}

	return description
}
