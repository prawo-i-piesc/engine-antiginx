// Package CVE queries NVD and summarizes matching vulnerabilities for a technology.
package CVE

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

// NVDResponse maps the NVD CVE API 2.0 response fields used by this client.
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`    // NVD timestamps carry no zone, see parseNVDTime
			LastModified string `json:"lastModified"` // Same format as Published
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
				CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdMetric is one CVSS scoring of a vulnerability. CVSS 3.x and 4.0 put the severity inside
// cvssData; CVSS 2.0 puts it beside it.
type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// nvdTimeLayouts are the timestamp formats NVD uses, newest first.
var nvdTimeLayouts = []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano}

// parseNVDTime reads an NVD timestamp, which is UTC written without a zone, and returns the
// zero time for one it cannot read rather than failing the whole response.
func parseNVDTime(value string) time.Time {
	for _, layout := range nvdTimeLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// defaultBaseURL is the public NVD CVE API endpoint.
const defaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// BaseURLEnv names the environment variable that redirects lookups at an NVD mirror, and tests
// at a local server serving prepared responses.
const BaseURLEnv = "ANTIGINX_NVD_URL"

// NewCVEClient creates a client for the NVD CVE API, honouring the BaseURLEnv override.
func NewCVEClient() *CVEClient {
	baseURL := defaultBaseURL
	if configured := strings.TrimSpace(os.Getenv(BaseURLEnv)); configured != "" {
		baseURL = strings.TrimSuffix(configured, "/")
	}
	return &CVEClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
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

// convertNVDToCVEResults selects the fields used by the assessment. The newest CVSS version a
// vulnerability was scored under decides its score and severity.
func (c *CVEClient) convertNVDToCVEResults(nvdResp NVDResponse) []CVEResult {
	var cves []CVEResult

	for _, vuln := range nvdResp.Vulnerabilities {
		cve := CVEResult{
			ID:        vuln.CVE.ID,
			Published: parseNVDTime(vuln.CVE.Published),
			Modified:  parseNVDTime(vuln.CVE.LastModified),
		}

		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		metrics := vuln.CVE.Metrics
		for _, scored := range [][]nvdMetric{metrics.CVSSMetricV40, metrics.CVSSMetricV31, metrics.CVSSMetricV30, metrics.CVSSMetricV2} {
			if len(scored) == 0 {
				continue
			}
			cve.Score = scored[0].CVSSData.BaseScore
			severity := scored[0].CVSSData.BaseSeverity
			if severity == "" {
				severity = scored[0].BaseSeverity
			}
			cve.Severity = strings.ToUpper(severity)
			break
		}

		for _, reference := range vuln.CVE.References {
			cve.References = append(cve.References, reference.URL)
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
