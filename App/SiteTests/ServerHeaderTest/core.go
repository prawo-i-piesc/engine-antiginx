// Package ServerHeaderTest implements the Server Technology Disclosure Analysis security test.
// See README.md for what it checks, how it grades and what it reports.
package ServerHeaderTest

import (
	"Engine-AntiGinx/App/CVE"
	helpers "Engine-AntiGinx/App/Helpers"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/ServerHeaderTest/modules"
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
	exposed_headers  []string
	technologies     []string
	total_exposures  int
	header_details   map[string]string
	technology_stack map[string]string
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
			// Headers that commonly reveal server technology information
			exposureHeaders := make(map[string]string, len(exposureHeaderNames))
			for _, name := range exposureHeaderNames {
				exposureHeaders[name] = params.Response.Header.Get(name)
			}

			// Analyze the collected headers
			analysis := analyzeServerHeaders(exposureHeaders)

			// Determine threat level based on exposure
			threatLevel := evaluateServerExposureThreatLevel(analysis)

			// Generate description
			description := generateServerExposureDescription(analysis)

			return SiteTests.TestResult{
				Name:        TestName,
				Certainty:   95,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// analyzeServerHeaders examines HTTP headers for technology disclosure patterns and constructs
// a comprehensive analysis of exposed information.
func analyzeServerHeaders(headers map[string]string) *ServerHeaderAnalysis {
	analysis := &ServerHeaderAnalysis{
		exposed_headers:  []string{},
		technologies:     []string{},
		total_exposures:  0,
		header_details:   map[string]string{},
		technology_stack: map[string]string{},
	}

	var exposedHeaders []string
	var technologies []string
	var techStack = make(map[string]string)
	var headerDetails = make(map[string]string)

	for headerName, headerValue := range headers {
		if headerValue != "" {
			exposedHeaders = append(exposedHeaders, headerName)
			headerDetails[headerName] = headerValue

			detectedTech := technologyDetector.Detect(headerName, headerValue)
			for tech, version := range detectedTech {
				technologies = append(technologies, tech)
				if version != "" {
					techStack[tech] = version
				} else {
					techStack[tech] = "detected"
				}
			}
		}
	}

	// Calculate total exposures
	totalExposures := len(exposedHeaders)

	analysis.exposed_headers = exposedHeaders
	analysis.technologies = helpers.RemoveDuplicates(technologies)
	analysis.total_exposures = totalExposures
	analysis.header_details = headerDetails
	analysis.technology_stack = techStack
	return analysis
}

// evaluateServerExposureThreatLevel calculates the security threat level based on server
// header information disclosure and known vulnerabilities.
func evaluateServerExposureThreatLevel(analysis *ServerHeaderAnalysis) SiteTests.ThreatLevel {
	totalExposures := analysis.total_exposures
	technologies := analysis.technologies

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
		cveClient := CVE.NewCVEClient()
		highestThreatLevel := baseThreatLevel

		for _, tech := range technologies {
			// Assess CVE vulnerabilities for detected technology
			assessment, err := cveClient.AssessTechnologyVulnerabilities(tech, "")
			if err == nil && assessment.CVECount > 0 {
				// Map CVE severity to our threat levels
				cveLevel := modules.MapCVEThreat(*assessment)
				if cveLevel > highestThreatLevel {
					highestThreatLevel = cveLevel
				}
			}
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
	totalExposures := analysis.total_exposures
	technologies := analysis.technologies

	if totalExposures == 0 {
		return "No server technology information disclosed in headers - good security practice"
	}

	description := ""
	if totalExposures == 1 {
		description = "1 header exposes server information"
	} else {
		description = string(rune(totalExposures)) + " headers expose server information"
	}

	if len(technologies) > 0 {
		description += ". Detected technologies: " + strings.Join(technologies, ", ")
	}

	return description
}
