// Package modules holds the stage implementations of the Sitemap Security Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SSRF"
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Fetcher retrieves a target's sitemap and reports what it exposes.
type Fetcher struct {
	Matcher      SensitivePaths.Matcher
	Timeout      time.Duration
	MaxBodyBytes int64
}

// SitemapPath is one declared URL whose path matched a dangerous pattern.
type SitemapPath struct {
	URL      string `json:"url"`
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
}

// SitemapAnalysis represents the analysis results of sitemap.xml for dangerous path exposure.
type SitemapAnalysis struct {
	SitemapAccessible bool          `json:"sitemap_accessible"`
	TotalURLs         int           `json:"total_urls"`
	DangerousPaths    []SitemapPath `json:"dangerous_paths"`
	TotalDangerous    int           `json:"total_dangerous"`
}

// locPattern matches <loc>URL</loc> tags, allowing newlines inside the <loc> content.
var locPattern = regexp.MustCompile(`(?s)<loc>(.*?)</loc>`)

// Analyze fetches and analyzes the sitemap.xml file for dangerous path exposures.
func (f Fetcher) Analyze(baseUrl string) SitemapAnalysis {
	analysis := SitemapAnalysis{DangerousPaths: []SitemapPath{}}

	resp, err := SSRF.NewClient(f.Timeout).Get(baseUrl + "/sitemap.xml")
	if err != nil {
		return analysis
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", cerr.Error())
		}
	}()

	// If sitemap doesn't exist or is inaccessible, return safe result
	if resp.StatusCode != 200 {
		return analysis
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBodyBytes))
	if err != nil {
		return analysis
	}
	analysis.SitemapAccessible = true

	urls := extractUrlsFromSitemap(string(body))
	analysis.TotalURLs = len(urls)

	// Each URL is reported once, under the best pattern its path matches
	for _, declared := range urls {
		pattern, category, ok := f.Matcher.Best(declaredPath(declared))
		if !ok {
			continue
		}
		analysis.DangerousPaths = append(analysis.DangerousPaths, SitemapPath{URL: declared, Pattern: pattern, Category: category})
	}
	analysis.TotalDangerous = len(analysis.DangerousPaths)

	return analysis
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

// declaredPath is the part of a declared URL that is matched: its path, so a hostname such
// as dev.example.com or api.example.com is not mistaken for a dangerous location. A value
// that is not an absolute URL is matched as it is.
func declaredPath(declared string) string {
	parsed, err := url.Parse(declared)
	if err != nil || !parsed.IsAbs() {
		return declared
	}
	return parsed.EscapedPath()
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

	for _, category := range categories {
		paths := categoryGroups[category]
		description += fmt.Sprintf("• %s: %d exposed\n", category, len(paths))

		// Show first 3 examples from each category
		for _, path := range paths[:min(len(paths), 3)] {
			description += fmt.Sprintf("  - %s\n", path)
		}
		if len(paths) > 3 {
			description += fmt.Sprintf("  ... and %d more\n", len(paths)-3)
		}
	}

	return description
}
