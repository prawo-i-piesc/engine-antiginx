// Package modules holds the stage implementations of the Sitemap Security Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Fetcher retrieves a target's sitemap and reports what it exposes.
type Fetcher struct {
	DangerousPatterns SensitivePaths.Matcher
	Timeout           time.Duration
	MaxBodyBytes      int64
}

// SitemapPath is one URL declared in the sitemap whose path matched a dangerous pattern.
type SitemapPath struct {
	URL      string `json:"url"`
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
}

// SitemapAnalysis represents the comprehensive analysis results of sitemap.xml for dangerous
// path exposure.
type SitemapAnalysis struct {
	SitemapAccessible bool          `json:"sitemap_accessible"`
	TotalURLs         int           `json:"total_urls"`
	DangerousPaths    []SitemapPath `json:"dangerous_paths"`
	TotalDangerous    int           `json:"total_dangerous"`
}

// locPattern matches <loc>URL</loc> tags, allowing newlines inside <loc> content.
var locPattern = regexp.MustCompile(`(?s)<loc>(.*?)</loc>`)

// Analyze fetches and analyzes the sitemap.xml file for dangerous path exposures.
func (f Fetcher) Analyze(baseUrl string) SitemapAnalysis {
	analysis := SitemapAnalysis{DangerousPaths: []SitemapPath{}}

	// Fetch sitemap.xml
	page, err := SiteTests.Fetch(SSRF.NewClient(f.Timeout), baseUrl+"/sitemap.xml", f.MaxBodyBytes)

	// If sitemap doesn't exist or is inaccessible, return safe result
	if err != nil || page.Status != http.StatusOK {
		return analysis
	}

	analysis.SitemapAccessible = true
	return f.match(extractUrlsFromSitemap(string(page.Body)), analysis)
}

// match checks every declared URL against the dangerous patterns and fills in the analysis.
// Each URL is reported once, under its most specific pattern.
func (f Fetcher) match(urls []string, analysis SitemapAnalysis) SitemapAnalysis {
	analysis.TotalURLs = len(urls)

	seen := map[string]struct{}{}
	for _, declared := range urls {
		if _, repeated := seen[declared]; repeated {
			continue
		}
		seen[declared] = struct{}{}

		pattern, category, ok := f.DangerousPatterns.Best(urlPath(declared))
		if !ok {
			continue
		}
		analysis.DangerousPaths = append(analysis.DangerousPaths, SitemapPath{
			URL:      declared,
			Pattern:  pattern,
			Category: category,
		})
	}
	analysis.TotalDangerous = len(analysis.DangerousPaths)
	return analysis
}

// urlPath is the path of a declared URL, so the hostname cannot match a pattern the way
// test.example.com would match /test. A value that is not an absolute URL is matched as is.
func urlPath(declared string) string {
	parsed, err := url.Parse(declared)
	if err != nil || parsed.Host == "" {
		return declared
	}
	return parsed.EscapedPath()
}

// extractUrlsFromSitemap extracts the distinct URL entries from sitemap XML content, in the
// order they are declared.
func extractUrlsFromSitemap(content string) []string {
	urls := []string{}
	seen := map[string]bool{}

	for _, match := range locPattern.FindAllStringSubmatch(content, -1) {
		locValue := strings.TrimSpace(match[1])
		if locValue != "" && !seen[locValue] {
			seen[locValue] = true
			urls = append(urls, locValue)
		}
	}

	return urls
}

// EvaluateThreat grades what the sitemap lets an attacker do: a dangerous path it declares
// is handed to search engines to index, so anyone can find it with a search. That is Low,
// however many there are; the count is reported, not graded.
func EvaluateThreat(analysis SitemapAnalysis) SiteTests.ThreatLevel {
	if !analysis.SitemapAccessible || analysis.TotalDangerous == 0 {
		return SiteTests.None
	}
	return SiteTests.Low
}

// Describe creates a human-readable description of the sitemap analysis.
func Describe(analysis SitemapAnalysis) string {
	if !analysis.SitemapAccessible {
		return "Sitemap.xml is not accessible or does not exist - unable to analyze for dangerous path exposure. This is acceptable for security, but may impact SEO."
	}

	if analysis.TotalDangerous == 0 {
		return fmt.Sprintf("Sitemap.xml is secure - no dangerous paths detected among %d URLs. The sitemap properly excludes administrative interfaces, API endpoints, and sensitive areas from search engine indexing.",
			analysis.TotalURLs)
	}

	// Group dangerous paths by category, keeping the sitemap's order within each
	categoryGroups := make(map[string][]string)
	for _, path := range analysis.DangerousPaths {
		categoryGroups[path.Category] = append(categoryGroups[path.Category], path.URL)
	}
	categories := make([]string, 0, len(categoryGroups))
	for category := range categoryGroups {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	description := fmt.Sprintf("Sitemap.xml exposes %d dangerous paths that should not be indexed by search engines (out of %d total URLs):\n\n",
		analysis.TotalDangerous, analysis.TotalURLs)

	return description + SiteTests.DescribeGroups(categoryGroups, "exposed", 3)
}
