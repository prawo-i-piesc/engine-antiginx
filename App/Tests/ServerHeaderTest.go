package Tests

import (
	"Engine-AntiGinx/App/CVE"
	helpers "Engine-AntiGinx/App/Helpers"
	"strings"
)

type ServerHeaderAnalysis struct {
	exposed_headers  []string
	technologies     []string
	total_exposures  int
	header_details   map[string]string
	technology_stack map[string]string
}

// NewServerHeaderTest creates a new test to check for server technology information disclosure
func NewServerHeaderTest() *ResponseTest {
	return &ResponseTest{
		Id:          "server-header-analysis",
		Name:        "Server Technology Disclosure Analysis",
		Description: "Analyzes HTTP headers for information disclosure about server technology, frameworks, and hosting services",
		RunTest: func(params ResponseTestParams) TestResult {
			// Headers that commonly reveal server technology information
			exposureHeaders := map[string]string{
				"Server":              params.Response.Header.Get("Server"),
				"X-Powered-By":        params.Response.Header.Get("X-Powered-By"),
				"X-AspNet-Version":    params.Response.Header.Get("X-AspNet-Version"),
				"X-AspNetMvc-Version": params.Response.Header.Get("X-AspNetMvc-Version"),
				"X-Framework":         params.Response.Header.Get("X-Framework"),
				"X-Generator":         params.Response.Header.Get("X-Generator"),
				"X-Drupal-Cache":      params.Response.Header.Get("X-Drupal-Cache"),
				"X-Mod-Pagespeed":     params.Response.Header.Get("X-Mod-Pagespeed"),
				"X-Varnish":           params.Response.Header.Get("X-Varnish"),
				"X-Served-By":         params.Response.Header.Get("X-Served-By"),
				"X-Cache":             params.Response.Header.Get("X-Cache"),
				"X-Runtime":           params.Response.Header.Get("X-Runtime"),
			}

			// Analyze the collected headers
			analysis := analyzeServerHeaders(exposureHeaders)

			// Determine threat level based on exposure
			threatLevel := evaluateServerExposureThreatLevel(analysis)

			// Generate description
			description := generateServerExposureDescription(analysis)

			return TestResult{
				Name:        "Server Technology Disclosure Analysis",
				Certainty:   95,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// analyzeServerHeaders examines headers for technology disclosure patterns
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

			detectedTech := detectTechnologies(headerName, headerValue)
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

func detectTechnologies(headerName string, headerValue string) map[string]string {
	technologies := make(map[string]string)
	valueLower := strings.ToLower(headerValue)

	switch strings.ToLower(headerName) {
	case "server":
		// Common web servers
		if strings.Contains(valueLower, "apache") {
			technologies["Apache"] = extractVersion(headerValue, "apache")
		}
		if strings.Contains(valueLower, "nginx") {
			technologies["Nginx"] = extractVersion(headerValue, "nginx")
		}
		if strings.Contains(valueLower, "iis") {
			technologies["Microsoft IIS"] = extractVersion(headerValue, "iis")
		}
		if strings.Contains(valueLower, "cloudflare") {
			technologies["Cloudflare"] = ""
		}
		if strings.Contains(valueLower, "gunicorn") {
			technologies["Gunicorn"] = extractVersion(headerValue, "gunicorn")
		}
		if strings.Contains(valueLower, "uvicorn") {
			technologies["Uvicorn"] = extractVersion(headerValue, "uvicorn")
		}

	case "x-powered-by":
		// Application frameworks
		if strings.Contains(valueLower, "express") {
			technologies["Express.js"] = ""
		}
		if strings.Contains(valueLower, "django") {
			technologies["Django"] = ""
		}
		if strings.Contains(valueLower, "asp.net") {
			technologies["ASP.NET"] = extractVersion(headerValue, "asp.net")
		}
		if strings.Contains(valueLower, "php") {
			technologies["PHP"] = extractVersion(headerValue, "php")
		}
		if strings.Contains(valueLower, "laravel") {
			technologies["Laravel"] = ""
		}
		if strings.Contains(valueLower, "rails") {
			technologies["Ruby on Rails"] = ""
		}
		if strings.Contains(valueLower, "flask") {
			technologies["Flask"] = ""
		}
		if strings.Contains(valueLower, "spring") {
			technologies["Spring Framework"] = ""
		}

	case "x-aspnet-version":
		technologies["ASP.NET"] = headerValue

	case "x-aspnetmvc-version":
		technologies["ASP.NET MVC"] = headerValue

	case "x-generator":
		if strings.Contains(valueLower, "drupal") {
			technologies["Drupal"] = extractVersion(headerValue, "drupal")
		}
		if strings.Contains(valueLower, "wordpress") {
			technologies["WordPress"] = extractVersion(headerValue, "wordpress")
		}

	case "x-drupal-cache":
		technologies["Drupal"] = ""

	case "x-mod-pagespeed":
		technologies["Google PageSpeed"] = headerValue

	case "x-varnish":
		technologies["Varnish Cache"] = ""

	case "x-runtime":
		// Usually indicates Ruby on Rails or similar
		technologies["Dynamic Runtime"] = headerValue
	}

	return technologies
}

// extractVersion attempts to extract version information from header values
func extractVersion(headerValue, technology string) string {
	valueLower := strings.ToLower(headerValue)
	techLower := strings.ToLower(technology)

	// Find the technology name in the header value
	index := strings.Index(valueLower, techLower)
	if index == -1 {
		return ""
	}

	// Look for version pattern after the technology name
	remaining := headerValue[index+len(techLower):]

	// Common version patterns: /1.2.3, -1.2.3, 1.2.3, v1.2.3
	versionStart := -1
	for i, char := range remaining {
		if char >= '0' && char <= '9' {
			versionStart = i
			break
		}
		if char == '/' || char == '-' || char == 'v' || char == 'V' {
			if i+1 < len(remaining) && remaining[i+1] >= '0' && remaining[i+1] <= '9' {
				versionStart = i + 1
				break
			}
		}
	}

	if versionStart == -1 {
		return ""
	}

	// Extract version string
	versionEnd := versionStart
	for i := versionStart; i < len(remaining); i++ {
		char := remaining[i]
		if (char >= '0' && char <= '9') || char == '.' || char == '-' {
			versionEnd = i + 1
		} else {
			break
		}
	}

	if versionEnd > versionStart {
		return remaining[versionStart:versionEnd]
	}

	return ""
}

func evaluateServerExposureThreatLevel(analysis *ServerHeaderAnalysis) ThreatLevel {
	totalExposures := analysis.total_exposures
	technologies := analysis.technologies

	// Base threat level assessment
	baseThreatLevel := None
	if totalExposures >= 5 {
		baseThreatLevel = Medium
	} else if totalExposures >= 3 {
		baseThreatLevel = Low
	} else if totalExposures > 0 {
		baseThreatLevel = Info
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
				cveLevel := mapCVEThreatLevel(*assessment)
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
				if Critical > highestThreatLevel {
					highestThreatLevel = Critical
				}
			}

			// Medium-risk patterns
			if strings.Contains(lowerTech, "apache") ||
				strings.Contains(lowerTech, "nginx") ||
				strings.Contains(lowerTech, "iis") {
				if High > highestThreatLevel {
					highestThreatLevel = High
				}
			}
		}

		return highestThreatLevel
	}

	return baseThreatLevel
}

// mapCVEThreatLevel maps CVE assessment results to our ThreatLevel enum
func mapCVEThreatLevel(assessment CVE.VulnerabilityAssessment) ThreatLevel {
	// High severity vulnerabilities take precedence
	if assessment.HighSeverity > 0 {
		return Critical
	}

	// Medium vulnerabilities assessment
	if assessment.MediumSeverity > 5 {
		return High
	} else if assessment.MediumSeverity > 0 {
		return Medium
	}

	// Low vulnerabilities in high quantity
	if assessment.LowSeverity > 10 {
		return Medium
	} else if assessment.LowSeverity > 0 {
		return Low
	}

	// Any CVE presence indicates some risk
	if assessment.CVECount > 0 {
		return Info
	}

	return None
}

// generateServerExposureDescription creates a human-readable description
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
