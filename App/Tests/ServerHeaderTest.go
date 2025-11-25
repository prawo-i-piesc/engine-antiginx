// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # ServerHeaderTest Module
//
// This module analyzes HTTP response headers to identify information disclosure
// vulnerabilities where servers expose technology stack details. Such exposure
// provides attackers with reconnaissance data useful for targeted attacks.
//
// Security Context:
//
// Information disclosure through HTTP headers violates the principle of security
// through obscurity and assists attackers in:
//   - Identifying specific software versions with known vulnerabilities
//   - Crafting targeted exploits for detected technologies
//   - Mapping the technology stack for attack surface analysis
//   - Accelerating reconnaissance phases of security assessments
//
// Analyzed Headers:
//   - Server: Web server type and version (Apache, Nginx, IIS)
//   - X-Powered-By: Application framework (PHP, Express, Django)
//   - X-AspNet-Version: ASP.NET framework version
//   - X-AspNetMvc-Version: ASP.NET MVC version
//   - X-Framework: Custom framework identifiers
//   - X-Generator: Content management systems (WordPress, Drupal)
//   - X-Drupal-Cache: Drupal CMS indicator
//   - X-Mod-Pagespeed: Google PageSpeed module
//   - X-Varnish: Varnish Cache presence
//   - X-Served-By: CDN or hosting service information
//   - X-Cache: Caching layer details
//   - X-Runtime: Application runtime information
//
// CVE Integration:
//
// This test integrates with the NIST NVD (National Vulnerability Database) to:
//   - Query known vulnerabilities for detected technologies
//   - Assess severity based on CVSS scores
//   - Elevate threat levels when high-severity CVEs exist
//   - Provide contextual vulnerability intelligence
//
// Threat Assessment Algorithm:
//
//	Base Level (by exposure count):
//	  0 exposures  → None
//	  1-2 exposures → Info
//	  3-4 exposures → Low
//	  5+ exposures  → Medium
//
//	CVE Enhancement:
//	  High severity CVE present    → Critical
//	  6+ medium severity CVEs       → High
//	  1-5 medium severity CVEs      → Medium
//	  11+ low severity CVEs         → Medium
//	  1-10 low severity CVEs        → Low
//
//	Heuristic Enhancement:
//	  Debug/test/dev identifiers    → Critical
//	  Common web servers exposed    → High
//
// Best Practices:
//
// To mitigate information disclosure:
//   - Remove or customize Server headers
//   - Disable X-Powered-By and version headers
//   - Use reverse proxies to normalize header output
//   - Implement header security policies
//   - Regular security audits of exposed headers
package Tests

import (
	"Engine-AntiGinx/App/CVE"
	helpers "Engine-AntiGinx/App/Helpers"
	"strings"
)

// ServerHeaderAnalysis represents the comprehensive analysis results of HTTP headers
// for server technology information disclosure.
//
// This structure aggregates data about exposed headers, detected technologies,
// and their potential security implications. It serves as metadata for test results
// and provides detailed insights for security reporting.
//
// Fields:
//   - exposed_headers: List of header names that revealed information
//   - technologies: Detected technology stack components (deduplicated)
//   - total_exposures: Count of headers exposing information
//   - header_details: Map of header names to their actual values
//   - technology_stack: Map of detected technologies to their versions
//
// Example structure:
//
//	{
//	    exposed_headers: ["Server", "X-Powered-By"],
//	    technologies: ["Nginx", "PHP"],
//	    total_exposures: 2,
//	    header_details: {
//	        "Server": "nginx/1.18.0",
//	        "X-Powered-By": "PHP/7.4.3"
//	    },
//	    technology_stack: {
//	        "Nginx": "1.18.0",
//	        "PHP": "7.4.3"
//	    }
//	}
type ServerHeaderAnalysis struct {
	exposed_headers  []string
	technologies     []string
	total_exposures  int
	header_details   map[string]string
	technology_stack map[string]string
}

// NewServerHeaderTest creates a new security test that analyzes HTTP response headers
// for server technology information disclosure vulnerabilities.
//
// This test examines 12 common HTTP headers that frequently expose sensitive information
// about the server technology stack, frameworks, and hosting infrastructure. It performs
// technology detection, version extraction, and CVE vulnerability assessment.
//
// Test Workflow:
//
//  1. Extract Target Headers: Collect values from 12 predefined headers
//  2. Analyze Headers: Identify exposed headers and detect technologies
//  3. CVE Assessment: Query NIST NVD for known vulnerabilities
//  4. Threat Evaluation: Calculate threat level based on exposure and CVEs
//  5. Generate Report: Create human-readable description
//
// Detected Technologies:
//
// Web Servers:
//   - Apache, Nginx, Microsoft IIS, Cloudflare, Gunicorn, Uvicorn
//
// Application Frameworks:
//   - Express.js, Django, ASP.NET, PHP, Laravel, Ruby on Rails,
//     Flask, Spring Framework
//
// Content Management Systems:
//   - Drupal, WordPress
//
// Infrastructure:
//   - Google PageSpeed, Varnish Cache, Dynamic Runtime
//
// Security Impact:
//
// Information disclosure enables:
//   - Vulnerability scanning with version-specific exploit databases
//   - Targeted attack preparation based on known weaknesses
//   - Technology stack fingerprinting
//   - Reduced attacker reconnaissance time
//
// The test assigns higher threat levels when:
//   - Multiple headers expose information (5+ = Medium)
//   - Technologies have known high-severity CVEs (Critical)
//   - Debug/test/dev indicators present (Critical)
//   - Common web servers revealed (High)
//
// Certainty:
//
// This test reports 95% certainty as header analysis is highly reliable,
// but some false positives may occur from customized or obfuscated headers.
//
// Returns:
//   - *ResponseTest: Configured test instance ready for execution
//
// Example:
//
//	// Create the server header test
//	headerTest := NewServerHeaderTest()
//
//	// Execute against target (via Runner)
//	params := ResponseTestParams{
//	    Response: httpResponse,
//	    Url:      "https://example.com",
//	}
//	result := headerTest.Run(params)
//
//	// No exposure (secure)
//	// result.ThreatLevel = None
//	// result.Description = "No server technology information disclosed..."
//
//	// Multiple exposures (insecure)
//	// result.ThreatLevel = High
//	// result.Description = "5 headers expose server information. Detected: Apache/2.4.41, PHP/7.4.3..."
//	// result.Metadata = ServerHeaderAnalysis{...}
//
// CVE Integration Example:
//
//	// If Apache 2.4.41 is detected and has known CVEs:
//	// - Query NVD API for "Apache" vulnerabilities
//	// - Assess severity levels (High/Medium/Low)
//	// - Elevate threat level to Critical if high-severity CVEs found
//
// Related Tests:
//   - HTTPSTest: Validates encrypted connections
//   - HSTSTest: Checks HTTP Strict Transport Security enforcement
func NewServerHeaderTest() *ResponseTest {
	return &ResponseTest{
		Id:          "serv-h-a",
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

// analyzeServerHeaders examines HTTP headers for technology disclosure patterns
// and constructs a comprehensive analysis of exposed information.
//
// This function processes the collected headers to identify:
//   - Which headers expose information
//   - What technologies are revealed
//   - Version information when available
//   - Overall exposure count
//
// The analysis involves:
//  1. Filtering out empty headers
//  2. Recording exposed header names
//  3. Detecting technologies from header values
//  4. Extracting version information
//  5. Building technology stack mapping
//  6. Deduplicating technology entries
//
// Technology Detection:
//
// For each non-empty header, the function calls detectTechnologies() which uses
// pattern matching to identify specific software, frameworks, and services.
//
// Parameters:
//   - headers: Map of header names to their values from HTTP response
//
// Returns:
//   - *ServerHeaderAnalysis: Comprehensive analysis structure with:
//   - exposed_headers: List of header names containing information
//   - technologies: Deduplicated list of detected technologies
//   - total_exposures: Count of exposed headers
//   - header_details: Original header name-value pairs
//   - technology_stack: Technology-to-version mapping
//
// Example:
//
//	headers := map[string]string{
//	    "Server": "nginx/1.18.0",
//	    "X-Powered-By": "PHP/7.4.3",
//	    "X-Cache": "",  // Empty, will be filtered
//	}
//
//	analysis := analyzeServerHeaders(headers)
//	// analysis.exposed_headers = ["Server", "X-Powered-By"]
//	// analysis.technologies = ["Nginx", "PHP"]
//	// analysis.total_exposures = 2
//	// analysis.technology_stack = {"Nginx": "1.18.0", "PHP": "7.4.3"}
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

// detectTechnologies identifies specific technologies and their versions from HTTP header values.
//
// This function uses pattern matching and heuristics to recognize common web servers,
// application frameworks, content management systems, and infrastructure components
// based on the header name and value.
//
// Detection Strategy:
//
// The function employs a switch-case approach for each header type:
//   - Server: Detects web servers (Apache, Nginx, IIS, Cloudflare, etc.)
//   - X-Powered-By: Identifies frameworks (Express, Django, PHP, Laravel, etc.)
//   - X-AspNet-Version: Captures ASP.NET version directly
//   - X-AspNetMvc-Version: Captures ASP.NET MVC version directly
//   - X-Generator: Detects CMS (Drupal, WordPress)
//   - Other headers: Various specialized detections
//
// Version Extraction:
//
// When possible, versions are extracted using the extractVersion() function
// which parses patterns like "nginx/1.18.0" or "PHP/7.4.3".
//
// Recognized Technologies:
//
// Web Servers:
//   - Apache, Nginx, Microsoft IIS, Cloudflare, Gunicorn, Uvicorn
//
// Frameworks:
//   - Express.js, Django, ASP.NET, PHP, Laravel, Ruby on Rails,
//     Flask, Spring Framework
//
// CMS:
//   - Drupal, WordPress
//
// Infrastructure:
//   - Google PageSpeed, Varnish Cache, Dynamic Runtime
//
// Parameters:
//   - headerName: The HTTP header name (e.g., "Server", "X-Powered-By")
//   - headerValue: The actual value of the header
//
// Returns:
//   - map[string]string: Map of detected technologies to their versions
//   - Keys are technology names (e.g., "Nginx", "PHP")
//   - Values are versions if detected, or empty string/generic indicator
//
// Example:
//
//	// Web server detection
//	tech := detectTechnologies("Server", "nginx/1.18.0 (Ubuntu)")
//	// Returns: {"Nginx": "1.18.0"}
//
//	// Framework detection
//	tech := detectTechnologies("X-Powered-By", "PHP/7.4.3")
//	// Returns: {"PHP": "7.4.3"}
//
//	// Multiple technologies in one header
//	tech := detectTechnologies("Server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f")
//	// Returns: {"Apache": "2.4.41"}
//
//	// Version-less detection
//	tech := detectTechnologies("X-Powered-By", "Express")
//	// Returns: {"Express.js": ""}
//
// Note:
//
// Case-insensitive matching is used to handle variations in header formatting.
// Not all technologies can have versions extracted; some return empty strings.
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

// extractVersion attempts to extract version information from HTTP header values
// using pattern recognition for common version formatting conventions.
//
// This function parses header values to isolate version numbers following
// technology names, handling various separator styles and formats commonly
// used in HTTP headers.
//
// Supported Version Patterns:
//   - Slash separator: "nginx/1.18.0"
//   - Hyphen separator: "PHP-7.4.3"
//   - Direct placement: "Apache 2.4.41"
//   - Version prefix: "v1.18.0" or "V1.18.0"
//
// Algorithm:
//
//  1. Convert to lowercase for case-insensitive matching
//  2. Locate the technology name within the header value
//  3. Examine characters after the technology name
//  4. Identify version start (first digit or after separator)
//  5. Extract consecutive version characters (digits, dots, hyphens)
//  6. Return the isolated version string
//
// Version Character Rules:
//   - Digits (0-9): Valid version characters
//   - Dots (.): Valid separators (1.18.0)
//   - Hyphens (-): Valid for pre-release versions (1.0.0-beta)
//   - Any other character: Terminates version extraction
//
// Parameters:
//   - headerValue: The complete HTTP header value (e.g., "nginx/1.18.0 (Ubuntu)")
//   - technology: The technology name to locate (e.g., "nginx")
//
// Returns:
//   - string: Extracted version number, or empty string if not found
//
// Example:
//
//	// Standard slash format
//	version := extractVersion("nginx/1.18.0 (Ubuntu)", "nginx")
//	// Returns: "1.18.0"
//
//	// Hyphen separator
//	version := extractVersion("PHP-7.4.3", "PHP")
//	// Returns: "7.4.3"
//
//	// Version prefix
//	version := extractVersion("Apache v2.4.41", "Apache")
//	// Returns: "2.4.41"
//
//	// Direct placement
//	version := extractVersion("IIS 10.0", "IIS")
//	// Returns: "10.0"
//
//	// No version found
//	version := extractVersion("Cloudflare", "Cloudflare")
//	// Returns: ""
//
//	// Complex header
//	version := extractVersion("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f", "Apache")
//	// Returns: "2.4.41"
//
// Note:
//
// This function uses case-insensitive matching for robustness. It only
// extracts the first version number encountered after the technology name.
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

// evaluateServerExposureThreatLevel calculates the security threat level based on
// server header information disclosure and known vulnerabilities.
//
// This function implements a sophisticated threat assessment algorithm that combines:
//   - Quantitative exposure analysis (number of headers revealing information)
//   - CVE vulnerability assessment from NIST NVD database
//   - Heuristic pattern matching for high-risk configurations
//
// Three-Layer Assessment:
//
// Layer 1: Base Threat (Exposure Count)
//   - 0 exposures  → None: No information disclosed
//   - 1-2 exposures → Info: Minimal disclosure
//   - 3-4 exposures → Low: Moderate disclosure
//   - 5+ exposures  → Medium: Extensive disclosure
//
// Layer 2: CVE Enhancement (Vulnerability Database)
//   - Query NIST NVD for each detected technology
//   - Assess CVE severity levels (High/Medium/Low)
//   - Map CVE severity to threat levels:
//   - High severity CVE present → Critical
//   - 6+ medium severity CVEs → High
//   - 1-5 medium severity CVEs → Medium
//   - 11+ low severity CVEs → Medium
//   - 1-10 low severity CVEs → Low
//
// Layer 3: Heuristic Enhancement (Risk Patterns)
//   - Debug/test/dev identifiers → Critical
//   - Common web servers (Apache/Nginx/IIS) → High
//
// Priority Logic:
//
// The function uses maximum threat level logic - if any layer identifies
// a higher threat, that level becomes the final assessment. This ensures
// critical vulnerabilities are never downgraded.
//
// CVE Integration:
//
// For each detected technology, the function:
//  1. Creates CVE client instance
//  2. Queries NIST NVD API with technology name
//  3. Receives vulnerability assessment with severity counts
//  4. Maps CVE severity to our ThreatLevel enum
//  5. Updates threat level if higher than current assessment
//
// Parameters:
//   - analysis: ServerHeaderAnalysis containing exposure and technology data
//
// Returns:
//   - ThreatLevel: Final calculated threat level (None/Info/Low/Medium/High/Critical)
//
// Example:
//
//	// Minimal exposure, no CVEs
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 1,
//	    technologies: []string{"Cloudflare"},
//	}
//	level := evaluateServerExposureThreatLevel(analysis)
//	// Returns: Info
//
//	// Multiple exposures with vulnerable technology
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 5,
//	    technologies: []string{"Apache", "PHP"},  // Has known CVEs
//	}
//	level := evaluateServerExposureThreatLevel(analysis)
//	// Returns: Critical (due to CVE assessment)
//
//	// Debug environment exposed
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 2,
//	    technologies: []string{"Express-debug"},
//	}
//	level := evaluateServerExposureThreatLevel(analysis)
//	// Returns: Critical (heuristic match)
//
// Security Context:
//
// The threat level indicates:
//   - Critical: Immediate remediation required (CVE High or debug exposed)
//   - High: Significant risk (common servers or multiple medium CVEs)
//   - Medium: Moderate risk (multiple exposures or some CVEs)
//   - Low: Minor risk (few exposures, low-severity CVEs)
//   - Info: Informational (minimal exposure, no vulnerabilities)
//   - None: Secure configuration (no disclosure)
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

// mapCVEThreatLevel maps CVE vulnerability assessment results from the NIST NVD
// database to the Engine-AntiGinx ThreatLevel enumeration.
//
// This function translates CVSS (Common Vulnerability Scoring System) severity
// classifications into our internal threat level system, enabling consistent
// risk assessment across different vulnerability sources.
//
// CVSS to ThreatLevel Mapping:
//
// High Severity CVEs:
//   - Any high-severity vulnerability → Critical
//   - Rationale: High-severity CVEs (CVSS 7.0-10.0) indicate serious
//     vulnerabilities requiring immediate attention
//
// Medium Severity CVEs:
//   - 6+ medium-severity vulnerabilities → High
//   - 1-5 medium-severity vulnerabilities → Medium
//   - Rationale: Multiple medium vulnerabilities (CVSS 4.0-6.9) compound
//     risk and warrant elevated threat levels
//
// Low Severity CVEs:
//   - 11+ low-severity vulnerabilities → Medium
//   - 1-10 low-severity vulnerabilities → Low
//   - Rationale: Large numbers of low-severity issues (CVSS 0.1-3.9)
//     indicate poor maintenance and potential security debt
//
// No Vulnerabilities:
//   - CVE count > 0 but no severity classified → Info
//   - CVE count = 0 → None
//   - Rationale: Presence in CVE database warrants awareness
//
// Priority Logic:
//
// The function uses a cascading if-else structure that prioritizes higher
// severity findings. Once a match is found, lower severity checks are skipped.
//
// Parameters:
//   - assessment: VulnerabilityAssessment structure from CVE client containing:
//   - CVECount: Total number of CVEs found
//   - HighSeverity: Count of high-severity vulnerabilities
//   - MediumSeverity: Count of medium-severity vulnerabilities
//   - LowSeverity: Count of low-severity vulnerabilities
//
// Returns:
//   - ThreatLevel: Mapped threat level (None/Info/Low/Medium/High/Critical)
//
// Example:
//
//	// High severity vulnerability present
//	assessment := CVE.VulnerabilityAssessment{
//	    CVECount: 8,
//	    HighSeverity: 2,
//	    MediumSeverity: 4,
//	    LowSeverity: 2,
//	}
//	level := mapCVEThreatLevel(assessment)
//	// Returns: Critical
//
//	// Multiple medium severity vulnerabilities
//	assessment := CVE.VulnerabilityAssessment{
//	    CVECount: 7,
//	    HighSeverity: 0,
//	    MediumSeverity: 7,
//	    LowSeverity: 0,
//	}
//	level := mapCVEThreatLevel(assessment)
//	// Returns: High
//
//	// Many low severity vulnerabilities
//	assessment := CVE.VulnerabilityAssessment{
//	    CVECount: 15,
//	    HighSeverity: 0,
//	    MediumSeverity: 0,
//	    LowSeverity: 15,
//	}
//	level := mapCVEThreatLevel(assessment)
//	// Returns: Medium
//
//	// No vulnerabilities found
//	assessment := CVE.VulnerabilityAssessment{
//	    CVECount: 0,
//	    HighSeverity: 0,
//	    MediumSeverity: 0,
//	    LowSeverity: 0,
//	}
//	level := mapCVEThreatLevel(assessment)
//	// Returns: None
//
// Security Standards Alignment:
//
// CVSS Severity Ranges:
//   - None: 0.0
//   - Low: 0.1-3.9
//   - Medium: 4.0-6.9
//   - High: 7.0-8.9
//   - Critical: 9.0-10.0
//
// Related Functions:
//   - evaluateServerExposureThreatLevel(): Uses this function for CVE assessment
//   - CVE.AssessTechnologyVulnerabilities(): Provides assessment data
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

// generateServerExposureDescription creates a human-readable description of
// server header information disclosure findings.
//
// This function synthesizes the analysis results into clear, concise descriptions
// suitable for security reports, console output, and API responses. It provides
// context about the exposure scope and identified technologies.
//
// Description Format:
//
// No Exposure:
//   - "No server technology information disclosed in headers - good security practice"
//
// With Exposure:
//   - Pattern: "{count} header(s) expose server information. Detected technologies: {tech_list}"
//   - Single: "1 header exposes server information. Detected technologies: Nginx"
//   - Multiple: "5 headers expose server information. Detected technologies: Apache, PHP, OpenSSL"
//
// Description Components:
//
//  1. Exposure Count: Quantifies how many headers reveal information
//  2. Technology List: Comma-separated list of detected technologies
//  3. Grammar: Proper singular/plural handling ("header" vs "headers")
//
// Parameters:
//   - analysis: ServerHeaderAnalysis containing exposure and technology data
//
// Returns:
//   - string: Human-readable description of findings
//
// Example:
//
//	// No exposure scenario
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 0,
//	    technologies: []string{},
//	}
//	desc := generateServerExposureDescription(analysis)
//	// Returns: "No server technology information disclosed in headers - good security practice"
//
//	// Single exposure
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 1,
//	    technologies: []string{"Cloudflare"},
//	}
//	desc := generateServerExposureDescription(analysis)
//	// Returns: "1 header exposes server information. Detected technologies: Cloudflare"
//
//	// Multiple exposures
//	analysis := &ServerHeaderAnalysis{
//	    total_exposures: 3,
//	    technologies: []string{"Apache", "PHP", "OpenSSL"},
//	}
//	desc := generateServerExposureDescription(analysis)
//	// Returns: "3 headers expose server information. Detected technologies: Apache, PHP, OpenSSL"
//
// Usage Context:
//
// These descriptions appear in:
//   - TestResult.Description field for test results
//   - CLI reporter output for console display
//   - Backend reporter API payloads
//   - Security audit reports
//   - Log files and monitoring systems
//
// Note:
//
// The description provides high-level summary information. Detailed header
// values and version information are available in the ServerHeaderAnalysis
// metadata structure.
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
