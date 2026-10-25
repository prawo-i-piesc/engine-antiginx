// Package CVE queries NVD for the vulnerabilities of a technology and rates them with CVSS.
package CVE

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// CVEClient queries the NVD CVE API.
type CVEClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// CVEResult holds the selected fields of an NVD vulnerability.
type CVEResult struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Status      string    `json:"status"`       // NVD vulnStatus: Analyzed, Modified, Awaiting Analysis, Deferred…
	Severity    string    `json:"severity"`     // CVSS qualitative rating of Score, "" when unscored
	Score       float64   `json:"score"`        // CVSS base score
	CVSSVersion string    `json:"cvss_version"` // CVSS version Score was computed under
	Vector      string    `json:"vector"`       // CVSS vector string
	ScoredBy    string    `json:"scored_by"`    // Who assessed it: NVD (nvd@nist.gov) or the publishing CNA
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
}

// Ways a CVE search can be matched to a technology.
const (
	MatchedByCPE     = "cpe"     // Against NVD's affected-version data for one release
	MatchedByKeyword = "keyword" // Against descriptions; says nothing about which release is affected
)

// VulnerabilityAssessment summarizes the CVEs found for a technology. Each CVE keeps its own
// CVSS rating: CVSS defines no way to combine several, so the assessment is rated by the most
// severe CVE and the counts are reported beside it, not folded into it.
type VulnerabilityAssessment struct {
	Technology       string      `json:"technology"`
	Version          string      `json:"version"`
	MatchedBy        string      `json:"matched_by"`    // MatchedByCPE or MatchedByKeyword
	CPE              string      `json:"cpe,omitempty"` // The match string queried, for a CPE match
	TotalResults     int         `json:"total_results"` // What NVD reports matching, which may exceed CVECount
	CVECount         int         `json:"cve_count"`     // CVEs received and not rejected
	CriticalSeverity int         `json:"critical_severity"`
	HighSeverity     int         `json:"high_severity"`
	MediumSeverity   int         `json:"medium_severity"`
	LowSeverity      int         `json:"low_severity"`
	Unscored         int         `json:"unscored"` // CVEs NVD has not scored yet
	MaxScore         float64     `json:"max_score"`
	MaxSeverity      string      `json:"max_severity"` // Rating of the most severe CVE
	CVEs             []CVEResult `json:"cves"`
	RiskLevel        string      `json:"risk_level"` // MaxSeverity, or RiskUnscored / SeverityNone
}

// RiskUnscored is the risk level of an assessment whose CVEs are all still unscored.
const RiskUnscored = "UNSCORED"

// NVDResponse maps the NVD CVE API 2.0 response fields used by this client.
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			VulnStatus   string `json:"vulnStatus"`
			Published    string `json:"published"`    // NVD timestamps carry no zone, see parseNVDTime
			LastModified string `json:"lastModified"` // Same format as Published
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics    nvdMetrics `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
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

// APIKeyEnv names the environment variable holding an NVD API key. Without one NVD allows five
// requests per rolling 30 seconds; with one, fifty.
const APIKeyEnv = "ANTIGINX_NVD_API_KEY"

// Results requested per query. A release rarely has more than a few hundred CVEs, and 2000 is
// the most NVD returns at once; a keyword search is a sample anyway.
const (
	cpeResultsPerPage     = 2000
	keywordResultsPerPage = 100
)

// releaseVersion is what a version must look like to be put into a CPE match string: CPE
// escapes every other character, and a disclosed "version" outside this shape is not one.
var releaseVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z._-]*$`)

// NewCVEClient creates a client for the NVD CVE API, honouring BaseURLEnv and APIKeyEnv.
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
		apiKey:  strings.TrimSpace(os.Getenv(APIKeyEnv)),
	}
}

// AssessTechnologyVulnerabilities finds the CVEs of a technology and rates them. With a
// concrete version of a technology that has a verified CPE product, it asks NVD for the CVEs
// whose affected-version ranges include that release (MatchedByCPE). Otherwise it falls back
// to a keyword search (MatchedByKeyword), whose results mention the technology but are not
// known to affect any particular release. Rejected CVEs are never returned.
func (c *CVEClient) AssessTechnologyVulnerabilities(technology, version string) (*VulnerabilityAssessment, error) {
	assessment := &VulnerabilityAssessment{Technology: technology, Version: version}

	query := url.Values{}
	product, known := ProductFor(technology)
	if known && IsReleaseVersion(version) {
		assessment.MatchedBy = MatchedByCPE
		assessment.CPE = fmt.Sprintf("cpe:2.3:a:%s:%s:%s", product.Vendor, product.Product, version)
		query.Set("virtualMatchString", assessment.CPE)
		query.Set("resultsPerPage", fmt.Sprint(cpeResultsPerPage))
	} else {
		assessment.MatchedBy = MatchedByKeyword
		query.Set("keywordSearch", buildSearchQuery(normalizeTechnologyName(technology), version))
		query.Set("resultsPerPage", fmt.Sprint(keywordResultsPerPage))
	}

	response, err := c.search(query)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVEs: %w", err)
	}

	assessment.TotalResults = response.TotalResults
	assessment.CVEs = convertNVDToCVEResults(response)
	rate(assessment)
	return assessment, nil
}

// IsReleaseVersion reports whether a disclosed version is concrete enough to look up: not
// empty, not the "detected" placeholder, and shaped like a release number.
func IsReleaseVersion(version string) bool {
	return releaseVersion.MatchString(version)
}

// search runs one CVE API query, leaving rejected CVEs out.
func (c *CVEClient) search(query url.Values) (NVDResponse, error) {
	// noRejected takes no value, so it is appended rather than set
	requestURL := c.baseURL + "?" + query.Encode() + "&noRejected"

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return NVDResponse{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AntiGinx-CVE-Client/1.0")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NVDResponse{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("CVEClient \nWarning: Failed to close response channel: %s", err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return NVDResponse{}, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NVDResponse{}, fmt.Errorf("failed to read response: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return NVDResponse{}, fmt.Errorf("failed to parse response: %w", err)
	}
	return nvdResp, nil
}

// buildSearchQuery appends a version unless it is empty or "detected".
func buildSearchQuery(technology, version string) string {
	query := technology

	if version != "" && version != "detected" {
		query += " " + version
	}

	return query
}

// normalizeTechnologyName maps known names to keyword search terms; otherwise it lowercases
// the input.
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

// convertNVDToCVEResults selects the fields used by the assessment and rates each CVE by the
// scoring that stands for it (see selectMetric). A CVE NVD marks Rejected is no vulnerability
// and is dropped, in case the response still carries one.
func convertNVDToCVEResults(nvdResp NVDResponse) []CVEResult {
	cves := []CVEResult{}

	for _, vuln := range nvdResp.Vulnerabilities {
		if strings.EqualFold(vuln.CVE.VulnStatus, "Rejected") {
			continue
		}
		cve := CVEResult{
			ID:         vuln.CVE.ID,
			Status:     vuln.CVE.VulnStatus,
			Severity:   SeverityUnscored,
			Published:  parseNVDTime(vuln.CVE.Published),
			Modified:   parseNVDTime(vuln.CVE.LastModified),
			References: []string{},
		}

		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		if scoring, scored := vuln.CVE.Metrics.selectMetric(); scored {
			cve.Score = scoring.CVSSData.BaseScore
			cve.CVSSVersion = scoring.CVSSData.Version
			cve.Vector = scoring.CVSSData.VectorString
			cve.ScoredBy = scoring.Source
			// The rating follows from the score under the version's scale, so a label that
			// disagrees with its score, or a missing one, cannot skew it
			cve.Severity = SeverityFromScore(cve.CVSSVersion, cve.Score)
		}

		for _, reference := range vuln.CVE.References {
			cve.References = append(cve.References, reference.URL)
		}

		cves = append(cves, cve)
	}

	return cves
}

// rate counts the CVEs by rating and rates the assessment by the most severe of them.
func rate(assessment *VulnerabilityAssessment) {
	assessment.CVECount = len(assessment.CVEs)
	assessment.MaxSeverity = SeverityUnscored

	for _, cve := range assessment.CVEs {
		switch cve.Severity {
		case SeverityCritical:
			assessment.CriticalSeverity++
		case SeverityHigh:
			assessment.HighSeverity++
		case SeverityMedium:
			assessment.MediumSeverity++
		case SeverityLow:
			assessment.LowSeverity++
		case SeverityUnscored:
			assessment.Unscored++
		}
		if MoreSevere(cve.Severity, assessment.MaxSeverity) {
			assessment.MaxSeverity = cve.Severity
		}
	}

	// MaxScore is the score of the most severe CVE: a 10.0 under CVSS 2.0, rated High, must
	// not pose as the score behind a Critical rated under CVSS 3.1
	for _, cve := range assessment.CVEs {
		if cve.Severity == assessment.MaxSeverity && cve.Score > assessment.MaxScore {
			assessment.MaxScore = cve.Score
		}
	}

	switch {
	case assessment.CVECount == 0:
		assessment.RiskLevel = SeverityNone
	case assessment.MaxSeverity == SeverityUnscored:
		assessment.RiskLevel = RiskUnscored
	default:
		assessment.RiskLevel = assessment.MaxSeverity
	}
}

// GetThreatLevelFromAssessment maps an assessment's risk level onto the engine's threat level
// numbers: the CVSS ratings onto Low (2) to Critical (5), a CVE known but not yet scored onto
// Info (1), and no CVE, or only CVSS 0.0 ones, onto None (0).
func GetThreatLevelFromAssessment(assessment *VulnerabilityAssessment) int {
	switch assessment.RiskLevel {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case RiskUnscored:
		return 1
	default:
		return 0
	}
}
