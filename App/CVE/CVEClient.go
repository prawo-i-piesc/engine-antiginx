// Package CVE provides functionality for querying and analyzing Common Vulnerabilities and Exposures (CVE)
// from the NIST National Vulnerability Database (NVD). It enables security assessment of detected technologies
// by checking for known vulnerabilities and calculating risk levels based on CVSS scores.
package CVE

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CVEClient handles communication with CVE databases, specifically the NIST NVD API.
// It provides methods for searching vulnerabilities and assessing security risks
// for specific technologies and versions.
type CVEClient struct {
	httpClient *http.Client
	baseURL    string
}

// CVEResult represents a single CVE vulnerability entry with essential information
// including severity rating, CVSS score, and publication dates.
type CVEResult struct {
	ID          string    `json:"id"`          // CVE identifier (e.g., "CVE-2024-1234")
	Description string    `json:"description"` // Human-readable vulnerability description
	Severity    string    `json:"severity"`    // Severity level: LOW, MEDIUM, HIGH, or CRITICAL
	Score       float64   `json:"score"`       // CVSS base score (0.0-10.0)
	Published   time.Time `json:"published"`   // Original publication date
	Modified    time.Time `json:"modified"`    // Last modification date
	References  []string  `json:"references"`  // External reference URLs
}

// VulnerabilityAssessment contains comprehensive analysis results for a specific technology and version.
// It aggregates CVE data, categorizes vulnerabilities by severity, and provides an overall risk assessment.
type VulnerabilityAssessment struct {
	Technology     string      `json:"technology"`      // Technology name (e.g., "nginx", "Apache")
	Version        string      `json:"version"`         // Technology version (e.g., "1.21.0")
	CVECount       int         `json:"cve_count"`       // Total number of CVEs found
	HighSeverity   int         `json:"high_severity"`   // Count of HIGH/CRITICAL severity CVEs
	MediumSeverity int         `json:"medium_severity"` // Count of MEDIUM severity CVEs
	LowSeverity    int         `json:"low_severity"`    // Count of LOW severity CVEs
	MaxScore       float64     `json:"max_score"`       // Highest CVSS score among all CVEs
	CVEs           []CVEResult `json:"cves"`            // Complete list of CVE entries
	RiskLevel      string      `json:"risk_level"`      // Overall risk: NONE, LOW, MEDIUM, HIGH, or CRITICAL
}

// NVDResponse represents the structure of NIST NVD API response (CVE API 2.0).
// This structure maps the JSON response from the National Vulnerability Database,
// including pagination information and vulnerability details with CVSS metrics.
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"` // Number of results in current page
	StartIndex      int `json:"startIndex"`     // Starting index for pagination
	TotalResults    int `json:"totalResults"`   // Total number of matching results
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
			Published time.Time `json:"published"`
			Modified  time.Time `json:"lastModified"`
			Metrics   struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore string `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// NewCVEClient creates a new CVE client instance configured to communicate with the NIST NVD API.
// The client is initialized with a 30-second timeout for HTTP requests and uses the official
// NVD CVE API 2.0 endpoint.
//
// Returns:
//   - *CVEClient: A ready-to-use CVE client instance
//
// Example:
//
//	client := NewCVEClient()
//	assessment, err := client.AssessTechnologyVulnerabilities("nginx", "1.21.0")
func NewCVEClient() *CVEClient {
	return &CVEClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// AssessTechnologyVulnerabilities checks for CVEs affecting a specific technology and version.
// It performs a comprehensive vulnerability assessment by querying the NVD database,
// analyzing the results, and calculating an overall risk level.
//
// The method normalizes technology names for better search accuracy and aggregates
// vulnerability data including severity counts and CVSS scores.
//
// Parameters:
//   - technology: Technology name (e.g., "nginx", "Apache", "PHP")
//   - version: Technology version string (e.g., "1.21.0", "2.4.41")
//
// Returns:
//   - *VulnerabilityAssessment: Complete assessment with CVEs and risk analysis
//   - error: Error if the search or analysis fails
//
// Example:
//
//	client := NewCVEClient()
//	assessment, err := client.AssessTechnologyVulnerabilities("nginx", "1.21.0")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d CVEs with risk level: %s\n", assessment.CVECount, assessment.RiskLevel)
func (c *CVEClient) AssessTechnologyVulnerabilities(technology, version string) (*VulnerabilityAssessment, error) {
	// Normalize technology name for search
	normalizedTech := normalizeTechnologyName(technology)

	// Search for CVEs
	cves, err := c.searchCVEs(normalizedTech, version)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVEs: %w", err)
	}

	// Analyze the results
	assessment := c.analyzeCVEs(technology, version, cves)

	return assessment, nil
}

// searchCVEs performs the actual search against the NVD database using the CVE API 2.0.
// It constructs an HTTP request with appropriate headers, executes the search,
// and parses the JSON response into CVEResult structures.
//
// Parameters:
//   - technology: Normalized technology name
//   - version: Technology version string
//
// Returns:
//   - []CVEResult: List of matching CVE entries
//   - error: Error if the request fails or response cannot be parsed
func (c *CVEClient) searchCVEs(technology, version string) ([]CVEResult, error) {
	// Build search query
	query := buildSearchQuery(technology, version)

	// Make request to NVD API
	requestURL := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=100", c.baseURL, url.QueryEscape(query))

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AntiGinx-CVE-Client/1.0")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert to our format
	cves := c.convertNVDToCVEResults(nvdResp)

	return cves, nil
}

// buildSearchQuery creates an optimized search query for the NVD API by combining
// technology name and version. If version is not available or set to "detected",
// it searches only by technology name.
//
// Parameters:
//   - technology: Technology name to search for
//   - version: Technology version (optional, can be empty or "detected")
//
// Returns:
//   - string: Formatted search query for the NVD API
func buildSearchQuery(technology, version string) string {
	query := technology

	// Add version if available
	if version != "" && version != "detected" {
		query += " " + version
	}

	return query
}

// normalizeTechnologyName standardizes technology names to match how they appear
// in the NVD database. This improves search accuracy by mapping common technology
// names to their official NVD identifiers.
//
// Parameters:
//   - technology: Original technology name (e.g., "Apache", "Nginx")
//
// Returns:
//   - string: Normalized technology name for NVD search (e.g., "apache http server", "nginx")
//
// Supported technologies include web servers (Apache, Nginx, IIS), frameworks
// (Django, Laravel, Spring), and content management systems (WordPress, Drupal).
func normalizeTechnologyName(technology string) string {
	techMap := map[string]string{
		"Apache":           "apache http server",
		"Nginx":            "nginx",
		"Microsoft IIS":    "internet information services",
		"Express.js":       "express",
		"Django":           "django",
		"ASP.NET":          "asp.net",
		"PHP":              "php",
		"Laravel":          "laravel",
		"Ruby on Rails":    "ruby on rails",
		"Flask":            "flask",
		"Spring Framework": "spring framework",
		"Gunicorn":         "gunicorn",
		"Uvicorn":          "uvicorn",
		"WordPress":        "wordpress",
		"Drupal":           "drupal",
		"Varnish Cache":    "varnish",
	}

	if normalized, exists := techMap[technology]; exists {
		return normalized
	}

	return strings.ToLower(technology)
}

// convertNVDToCVEResults converts NVD API response to our internal CVEResult format.
// It extracts essential information including CVE ID, description, CVSS scores,
// and severity ratings. Prefers CVSS v3.1 metrics over v2 when available.
//
// Parameters:
//   - nvdResp: Raw NVD API response structure
//
// Returns:
//   - []CVEResult: Converted list of CVE entries in simplified format
func (c *CVEClient) convertNVDToCVEResults(nvdResp NVDResponse) []CVEResult {
	var cves []CVEResult

	for _, vuln := range nvdResp.Vulnerabilities {
		cve := CVEResult{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
			Modified:  vuln.CVE.Modified,
		}

		// Extract description
		for _, desc := range vuln.CVE.Description.DescriptionData {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// Extract CVSS score and severity
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			cvss := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData
			cve.Score = cvss.BaseScore
			cve.Severity = strings.ToUpper(cvss.BaseSeverity)
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			// Fallback to CVSS v2 if v3.1 not available
			cve.Severity = "MEDIUM" // Default for v2
		}

		cves = append(cves, cve)
	}

	return cves
}

// analyzeCVEs performs comprehensive analysis on the CVE results to create a
// VulnerabilityAssessment. It categorizes CVEs by severity, finds the maximum
// CVSS score, and determines an overall risk level.
//
// Parameters:
//   - technology: Technology name being assessed
//   - version: Technology version being assessed
//   - cves: List of CVE entries to analyze
//
// Returns:
//   - *VulnerabilityAssessment: Complete assessment with aggregated statistics and risk level
func (c *CVEClient) analyzeCVEs(technology, version string, cves []CVEResult) *VulnerabilityAssessment {
	assessment := &VulnerabilityAssessment{
		Technology: technology,
		Version:    version,
		CVEs:       cves,
		CVECount:   len(cves),
	}

	// Count severities and find max score
	var maxScore float64
	for _, cve := range cves {
		if cve.Score > maxScore {
			maxScore = cve.Score
		}

		switch cve.Severity {
		case "HIGH", "CRITICAL":
			assessment.HighSeverity++
		case "MEDIUM":
			assessment.MediumSeverity++
		case "LOW":
			assessment.LowSeverity++
		}
	}

	assessment.MaxScore = maxScore

	// Determine risk level
	assessment.RiskLevel = c.determineRiskLevel(assessment)

	return assessment
}

// determineRiskLevel calculates overall risk based on CVE analysis using a weighted
// approach that considers both the number and severity of vulnerabilities.
//
// Risk levels are determined as follows:
//   - CRITICAL: Any HIGH/CRITICAL severity CVE present
//   - HIGH: 3 or more MEDIUM severity CVEs
//   - MEDIUM: Any MEDIUM severity CVE or 5+ LOW severity CVEs
//   - LOW: Any CVEs present that don't meet higher thresholds
//   - NONE: No CVEs found
//
// Parameters:
//   - assessment: VulnerabilityAssessment with severity counts
//
// Returns:
//   - string: Risk level classification (NONE, LOW, MEDIUM, HIGH, or CRITICAL)
func (c *CVEClient) determineRiskLevel(assessment *VulnerabilityAssessment) string {
	if assessment.HighSeverity > 0 {
		return "CRITICAL"
	} else if assessment.MediumSeverity >= 3 {
		return "HIGH"
	} else if assessment.MediumSeverity > 0 || assessment.LowSeverity >= 5 {
		return "MEDIUM"
	} else if assessment.CVECount > 0 {
		return "LOW"
	}
	return "NONE"
}

// GetThreatLevelFromAssessment converts CVE risk level to the Tests package ThreatLevel enum.
// This function provides integration between CVE assessment results and the test framework's
// threat classification system.
//
// Mapping:
//   - CRITICAL → 5 (Critical threat)
//   - HIGH → 4 (High threat)
//   - MEDIUM → 3 (Medium threat)
//   - LOW → 2 (Low threat)
//   - NONE → 0 (No threat)
//   - default → 1 (Info level)
//
// Parameters:
//   - assessment: VulnerabilityAssessment containing the risk level
//
// Returns:
//   - int: ThreatLevel value compatible with Tests.ThreatLevel enum
func GetThreatLevelFromAssessment(assessment *VulnerabilityAssessment) int {
	switch assessment.RiskLevel {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 0
	default:
		return 1
	}
}
