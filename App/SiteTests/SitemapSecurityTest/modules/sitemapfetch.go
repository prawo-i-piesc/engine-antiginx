// Package modules holds the stage implementations of the Sitemap Security Analysis test.
// It is used by its own core.go and nothing else.
package modules

import (
	"Engine-AntiGinx/App/SiteTests"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Fetcher retrieves a target's sitemap and reports what it exposes.
type Fetcher struct {
	DangerousPatterns map[string]string
}

// SitemapAnalysis represents the comprehensive analysis results of sitemap.xml for dangerous
// path exposure.
type SitemapAnalysis struct {
	dangerous_paths    []string
	path_categories    map[string]string
	total_dangerous    int
	sitemap_accessible bool
	total_urls         int
}

// Analyze fetches and analyzes the sitemap.xml file for dangerous path exposures.
func (f Fetcher) Analyze(baseUrl string) SitemapAnalysis {
	sitemapUrl := baseUrl + "/sitemap.xml"

	analysis := SitemapAnalysis{
		dangerous_paths:    []string{},
		path_categories:    make(map[string]string),
		total_dangerous:    0,
		sitemap_accessible: false,
		total_urls:         0,
	}

	// Fetch sitemap.xml

	resp, err := http.Get(sitemapUrl)
	if err != nil {
		return analysis
	}

	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", err.Error())
		}
	}()

	// If sitemap doesn't exist or is inaccessible, return safe result
	if resp.StatusCode != 200 {
		return analysis
	}

	analysis.sitemap_accessible = true

	// Read sitemap content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return analysis
	}

	content := string(body)

	// Extract URLs from sitemap (basic XML parsing)
	urls := extractUrlsFromSitemap(content)
	analysis.total_urls = len(urls)

	// Check each URL for dangerous patterns
	for _, url := range urls {
		urlLower := strings.ToLower(url)

		for pattern, category := range f.DangerousPatterns {
			if strings.Contains(urlLower, pattern) {
				// Avoid duplicates - check if URL already exists
				isDuplicate := false
				for _, existingPath := range analysis.dangerous_paths {
					if existingPath == url {
						isDuplicate = true
						break
					}
				}

				if !isDuplicate {
					analysis.dangerous_paths = append(analysis.dangerous_paths, url)
					analysis.path_categories[url] = category
					analysis.total_dangerous++
				}
				break // Only categorize each URL once
			}
		}
	}

	return analysis
}

// extractUrlsFromSitemap extracts URL entries from sitemap XML content.
func extractUrlsFromSitemap(content string) []string {
	urls := []string{}

	// Regex to match <loc>URL</loc> tags, allowing newlines inside <loc> content
	locPattern := regexp.MustCompile(`(?s)<loc>(.*?)</loc>`)
	matches := locPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			locValue := strings.TrimSpace(match[1])
			if locValue != "" {
				urls = append(urls, locValue)
			}
		}
	}

	return urls
}

// EvaluateThreat determines the threat level based on dangerous path exposure.
func EvaluateThreat(analysis SitemapAnalysis) SiteTests.ThreatLevel {
	// If sitemap is not accessible or doesn't exist, return None
	if !analysis.sitemap_accessible {
		return SiteTests.None
	}

	count := analysis.total_dangerous

	switch {
	case count == 0:
		return SiteTests.None
	case count <= 2:
		return SiteTests.Low
	case count <= 5:
		return SiteTests.Medium
	case count <= 10:
		return SiteTests.High
	default:
		return SiteTests.Critical
	}
}

// Describe creates a human-readable description of the sitemap analysis.
func Describe(analysis SitemapAnalysis) string {
	if !analysis.sitemap_accessible {
		return "Sitemap.xml is not accessible or does not exist - unable to analyze for dangerous path exposure. This is acceptable for security, but may impact SEO."
	}

	if analysis.total_dangerous == 0 {
		return fmt.Sprintf("Sitemap.xml is secure - no dangerous paths detected among %d URLs. The sitemap properly excludes administrative interfaces, API endpoints, and sensitive areas from search engine indexing.",
			analysis.total_urls)
	}

	// Group dangerous paths by category
	categoryGroups := make(map[string][]string)
	for path, category := range analysis.path_categories {
		categoryGroups[category] = append(categoryGroups[category], path)
	}

	description := fmt.Sprintf("Sitemap.xml exposes %d dangerous paths that should not be indexed by search engines (out of %d total URLs):\n\n",
		analysis.total_dangerous, analysis.total_urls)

	// Add category breakdown
	for category, paths := range categoryGroups {
		description += fmt.Sprintf("• %s: %d exposed\n", category, len(paths))

		// Show first 3 examples from each category
		exampleCount := len(paths)
		if exampleCount > 3 {
			exampleCount = 3
		}
		for i := 0; i < exampleCount; i++ {
			description += fmt.Sprintf("  - %s\n", paths[i])
		}
		if len(paths) > 3 {
			description += fmt.Sprintf("  ... and %d more\n", len(paths)-3)
		}
	}

	return description
}
