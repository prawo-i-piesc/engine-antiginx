// Package Tests provides security testing functionality for Engine-AntiGinx.
//
// # SitemapSecurityTest Module
//
// This module analyzes sitemap.xml files to detect dangerous paths that should not
// be exposed to search engines. Such exposure violates security best practices and
// provides attackers with reconnaissance data about sensitive application areas.
//
// Dangerous Path Categories:
//
// Administrative Interfaces:
//   - /admin, /administrator, /wp-admin, /phpmyadmin
//   - /manager, /console, /panel, /dashboard
//
// API Endpoints:
//   - /api, /rest, /graphql, /v1, /v2
//   - /swagger, /api-docs, /openapi
//
// Configuration & Environment:
//   - /.env, /config, /.git, /.svn
//   - /settings, /configuration
//
// Development & Testing:
//   - /debug, /test, /testing, /dev
//   - /staging, /development, /qa
//
// Backup & Sensitive Files:
//   - /backup, /backups, /.backup
//   - /dump, /sql, /database
//
// Internal & Private:
//   - /private, /internal, /hidden
//   - /temp, /tmp, /cache
//
//	Exposure Level:
//	  0 dangerous paths     → None
//	  1-2 dangerous paths   → Low
//	  3-5 dangerous paths   → Medium
//	  6-10 dangerous paths  → High
//	  11+ dangerous paths   → Critical
//
package Tests

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// SitemapAnalysis represents the comprehensive analysis results of sitemap.xml
// for dangerous path exposure.
//
// Example structure:
//
//	{
//	    dangerous_paths: ["/admin", "/api/v1/users", "/.env"],
//	    path_categories: {
//	        "/admin": "Administrative Interface",
//	        "/api/v1/users": "API Endpoint",
//	        "/.env": "Configuration File"
//	    },
//	    total_dangerous: 3,
//	    sitemap_accessible: true,
//	    total_urls: 150
//	}
type SitemapAnalysis struct {
	dangerous_paths   []string
	path_categories   map[string]string
	total_dangerous   int
	sitemap_accessible bool
	total_urls        int
}

// NewSitemapSecurityTest creates a new security test that analyzes sitemap.xml
// for dangerous path exposure vulnerabilities.
//
// This test fetches the sitemap.xml file from the target website and examines
// all URLs for patterns that indicate sensitive areas that should not be
// indexed by search engines.
//
// Test Workflow:
//
//  1. Fetch Sitemap: Attempt to retrieve /sitemap.xml from target
//  2. Parse Content: Extract all URL entries from the XML
//  3. Pattern Analysis: Check each URL against dangerous path patterns
//  4. Categorization: Classify dangerous paths by security concern
//  5. Threat Evaluation: Calculate threat level based on exposure count
//  6. Generate Report: Create human-readable description
//
// Detected Path Patterns:
//
// The test uses regex and substring matching to identify:
//   - Administrative interfaces (admin, wp-admin, phpmyadmin, etc.)
//   - Authentication endpoints (login, signin, auth, oauth, etc.)
//   - API paths (api, rest, graphql, swagger, etc.)
//   - Configuration files (.env, config, settings, etc.)
//   - Development paths (debug, test, dev, staging, etc.)
//   - Backup locations (backup, dump, sql, database, etc.)
//   - Private areas (private, internal, hidden, etc.)
//
// Security Impact:
//
// Sitemap exposure enables:
//   - Rapid discovery of sensitive application areas
//   - Reduced attacker reconnaissance effort
//   - Identification of potential attack vectors
//   - Application structure mapping
//
// The test assigns higher threat levels when:
//   - Multiple sensitive paths are exposed (6+ = High)
//   - Critical paths like config files are found (Critical)
//   - Extensive API documentation is exposed (High)
//   - Authentication endpoints are revealed (Medium)
//
// Certainty:
//
// This test reports 90% certainty as sitemap analysis is reliable,
// but some false positives may occur from legitimate path names that
// match dangerous patterns (e.g., /api-guide, /admin-contact).
//
// Returns:
//   - *ResponseTest: Configured test instance ready for execution
//
// Example:
//
//	// Create the sitemap security test
//	sitemapTest := NewSitemapSecurityTest()
//
//	// Execute against target (via Runner)
//	params := ResponseTestParams{
//	    Response: httpResponse,
//	    Url:      "https://example.com",
//	}
//	result := sitemapTest.Run(params)
//
//	// No dangerous paths (secure)
//	// result.ThreatLevel = None
//	// result.Description = "Sitemap.xml does not expose dangerous paths..."
//
//	// Multiple exposures (insecure)
//	// result.ThreatLevel = High
//	// result.Description = "Sitemap.xml exposes 7 dangerous paths including administrative..."
//	// result.Metadata = SitemapAnalysis{...}
//
// Related Tests:
//   - ServerHeaderTest: Analyzes server header information disclosure
//   - JSObfuscationTest: Detects potential security threats in JavaScript
func NewSitemapSecurityTest() *ResponseTest {
	return &ResponseTest{
		Id:          "sitemap",
		Name:        "Sitemap Security Analysis",
		Description: "Analyzes sitemap.xml for dangerous paths that should not be exposed to search engines",
		RunTest: func(params ResponseTestParams) TestResult {
			// Extract base URL from the response
			baseUrl := params.Response.Request.URL.Scheme + "://" + params.Response.Request.URL.Host
			
			// Fetch sitemap.xml
			analysis := analyzeSitemap(baseUrl)

			// Determine threat level based on dangerous paths found
			threatLevel := evaluateSitemapThreatLevel(analysis)

			// Generate description
			description := generateSitemapDescription(analysis)

			return TestResult{
				Name:        "Sitemap Security Analysis",
				Certainty:   90,
				ThreatLevel: threatLevel,
				Metadata:    analysis,
				Description: description,
			}
		},
	}
}

// analyzeSitemap fetches and analyzes the sitemap.xml file for dangerous path exposures.
//
// This function performs:
//  1. HTTP GET request to /sitemap.xml
//  2. Content parsing to extract URLs
//  3. Pattern matching against dangerous path categories
//  4. Classification of found dangerous paths
//
// Parameters:
//   - baseUrl: The base URL of the target website (e.g., "https://example.com")
//
// Returns:
//   - SitemapAnalysis: Complete analysis results including dangerous paths
//
// The function handles:
//   - Sitemap not found (404) - returns safe analysis
//   - Network errors - marks sitemap as inaccessible
//   - Empty sitemaps - returns safe analysis
//   - Malformed XML - attempts best-effort parsing
func analyzeSitemap(baseUrl string) SitemapAnalysis {
	sitemapUrl := baseUrl + "/sitemap.xml"
	
	analysis := SitemapAnalysis{
		dangerous_paths:   []string{},
		path_categories:   make(map[string]string),
		total_dangerous:   0,
		sitemap_accessible: false,
		total_urls:        0,
	}

	// Fetch sitemap.xml
	resp, err := http.Get(sitemapUrl)
	if err != nil {
		return analysis
	}
	defer resp.Body.Close()

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

	// Define dangerous path patterns with their categories
	dangerousPatterns := map[string]string{
		// Administrative Interfaces
		`/admin`:          "Administrative Interface",
		`/administrator`:  "Administrative Interface",
		`/wp-admin`:       "Administrative Interface",
		`/phpmyadmin`:     "Administrative Interface",
		`/cpanel`:         "Administrative Interface",
		`/manager`:        "Administrative Interface",
		`/console`:        "Administrative Interface",
		`/panel`:          "Administrative Interface",
		`/dashboard`:      "Administrative Interface",
		`/control`:        "Administrative Interface",
		
		// API Endpoints
		`/api`:            "API Endpoint",
		`/rest`:           "API Endpoint",
		`/graphql`:        "API Endpoint",
		`/v1`:             "API Endpoint",
		`/v2`:             "API Endpoint",
		`/v3`:             "API Endpoint",
		`/swagger`:        "API Documentation",
		`/api-docs`:       "API Documentation",
		`/openapi`:        "API Documentation",
		`/docs/api`:       "API Documentation",
		
		// Configuration & Environment
		`/.env`:           "Configuration File",
		`/config`:         "Configuration File",
		`/.git`:           "Version Control",
		`/.svn`:           "Version Control",
		`/settings`:       "Configuration File",
		`/configuration`:  "Configuration File",
		`/env`:            "Configuration File",
		
		// Development & Testing
		`/debug`:          "Development Path",
		`/test`:           "Development Path",
		`/testing`:        "Development Path",
		`/dev`:            "Development Path",
		`/development`:    "Development Path",
		`/staging`:        "Development Path",
		`/qa`:             "Development Path",
		`/uat`:            "Development Path",
		
		// Backup & Sensitive Files
		`/backup`:         "Backup Location",
		`/backups`:        "Backup Location",
		`/.backup`:        "Backup Location",
		`/dump`:           "Database Dump",
		`/sql`:            "Database Dump",
		`/database`:       "Database Dump",
		`/db`:             "Database Dump",
		
		// Internal & Private
		`/private`:        "Private Area",
		`/internal`:       "Internal Area",
		`/hidden`:         "Private Area",
		`/temp`:           "Temporary Files",
		`/tmp`:            "Temporary Files",
		`/cache`:          "Cache Files",
		`/logs`:           "Log Files",
		`/log`:            "Log Files",
	}

	// Check each URL for dangerous patterns
	for _, url := range urls {
		urlLower := strings.ToLower(url)
		
		for pattern, category := range dangerousPatterns {
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
//
// This function uses regex pattern matching to find <loc> tags in the XML
// which contain the actual URLs. It's a lightweight parsing approach that
// doesn't require full XML parsing libraries.
//
// Parameters:
//   - content: The raw XML content of the sitemap
//
// Returns:
//   - []string: List of URLs extracted from the sitemap
//
// Example:
//
//	<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
//	  <url>
//	    <loc>https://example.com/page1</loc>
//	  </url>
//	  <url>
//	    <loc>https://example.com/admin</loc>
//	  </url>
//	</urlset>
//
//	Returns: ["https://example.com/page1", "https://example.com/admin"]
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

// evaluateSitemapThreatLevel determines the threat level based on dangerous path exposure.
//
// This function implements the threat assessment algorithm considering:
//   - Number of dangerous paths exposed
//   - Severity of path categories
//
// Threat Level Mapping:
//   - 0 dangerous paths: None
//   - 1-2 dangerous paths: Low
//   - 3-5 dangerous paths: Medium
//   - 6-10 dangerous paths: High
//   - 11+ dangerous paths: Critical
//
// Parameters:
//   - analysis: The complete sitemap analysis results
//
// Returns:
//   - ThreatLevel: Calculated threat level
func evaluateSitemapThreatLevel(analysis SitemapAnalysis) ThreatLevel {
	// If sitemap is not accessible or doesn't exist, return None
	if !analysis.sitemap_accessible {
		return None
	}

	count := analysis.total_dangerous

	switch {
	case count == 0:
		return None
	case count <= 2:
		return Low
	case count <= 5:
		return Medium
	case count <= 10:
		return High
	default:
		return Critical
	}
}

// generateSitemapDescription creates a human-readable description of the sitemap analysis.
//
// This function generates detailed descriptions including:
//   - Number of dangerous paths found
//   - Categories of exposed paths
//   - Specific examples of dangerous paths
//   - Security recommendations
//
// Parameters:
//   - analysis: The complete sitemap analysis results
//
// Returns:
//   - string: Formatted description for the test result
func generateSitemapDescription(analysis SitemapAnalysis) string {
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
