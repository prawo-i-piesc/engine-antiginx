// Package CVE queries NVD and summarizes matching vulnerabilities for a technology.
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

// CVEClient queries the NVD CVE API.
type CVEClient struct {
	httpClient *http.Client
	baseURL    string
}

// CVEResult holds the selected fields of an NVD vulnerability.
type CVEResult struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
}

// VulnerabilityAssessment aggregates CVEs and risk for a technology and version.
type VulnerabilityAssessment struct {
	Technology     string      `json:"technology"`
	Version        string      `json:"version"`
	CVECount       int         `json:"cve_count"`
	HighSeverity   int         `json:"high_severity"`
	MediumSeverity int         `json:"medium_severity"`
	LowSeverity    int         `json:"low_severity"`
	MaxScore       float64     `json:"max_score"`
	CVEs           []CVEResult `json:"cves"`
	RiskLevel      string      `json:"risk_level"`
}

// NVDResponse maps the NVD CVE API response fields used by this client.
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
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

// NewCVEClient creates a client for the NVD CVE API.
func NewCVEClient() *CVEClient {
	return &CVEClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// AssessTechnologyVulnerabilities searches NVD and summarizes matching CVEs.
func (c *CVEClient) AssessTechnologyVulnerabilities(technology, version string) (*VulnerabilityAssessment, error) {

	normalizedTech := normalizeTechnologyName(technology)

	cves, err := c.searchCVEs(normalizedTech, version)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVEs: %w", err)
	}

	assessment := c.analyzeCVEs(technology, version, cves)

	return assessment, nil
}

// searchCVEs fetches and converts one page of keyword search results.
func (c *CVEClient) searchCVEs(technology, version string) ([]CVEResult, error) {

	query := buildSearchQuery(technology, version)

	requestURL := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=100", c.baseURL, url.QueryEscape(query))

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AntiGinx-CVE-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("CVEClient \nWarning: Failed to close response channel: %s", err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	cves := c.convertNVDToCVEResults(nvdResp)

	return cves, nil
}

// buildSearchQuery appends a version unless it is empty or "detected".
func buildSearchQuery(technology, version string) string {
	query := technology

	if version != "" && version != "detected" {
		query += " " + version
	}

	return query
}

// normalizeTechnologyName maps known names to search terms; otherwise it lowercases the input.
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

// convertNVDToCVEResults selects the fields used by the assessment.
func (c *CVEClient) convertNVDToCVEResults(nvdResp NVDResponse) []CVEResult {
	var cves []CVEResult

	for _, vuln := range nvdResp.Vulnerabilities {
		cve := CVEResult{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
			Modified:  vuln.CVE.Modified,
		}

		for _, desc := range vuln.CVE.Description.DescriptionData {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

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

// analyzeCVEs counts severities, records the maximum score and assigns risk.
func (c *CVEClient) analyzeCVEs(technology, version string, cves []CVEResult) *VulnerabilityAssessment {
	assessment := &VulnerabilityAssessment{
		Technology: technology,
		Version:    version,
		CVEs:       cves,
		CVECount:   len(cves),
	}

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

	assessment.RiskLevel = c.determineRiskLevel(assessment)

	return assessment
}

// determineRiskLevel classifies the assessment by severity counts.
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

// GetThreatLevelFromAssessment maps risk labels to numeric threat levels.
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
