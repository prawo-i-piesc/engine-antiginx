// Package Tests provides security test implementations for HTTP response analysis.
// This file contains the HSTS (HTTP Strict Transport Security) test that checks for
// proper HSTS header configuration to prevent protocol downgrade attacks.
package Tests

import (
	"strconv"
	"strings"
)

// NewHSTSTest creates a new ResponseTest that analyzes HTTP Strict Transport Security (HSTS)
// header configuration. HSTS is a security mechanism that forces browsers to interact with
// websites exclusively over HTTPS, protecting against protocol downgrade attacks and cookie hijacking.
//
// The test evaluates:
//   - Presence of Strict-Transport-Security header
//   - max-age directive value (minimum recommended: 6 months, ideal: 1+ year)
//   - includeSubDomains directive (protects all subdomains)
//   - preload directive (enables HSTS preload list inclusion)
//
// Threat level assessment:
//   - None (0): Excellent - max-age ≥ 1 year + includeSubDomains + preload
//   - Info (1): Good - max-age ≥ 1 year + includeSubDomains
//   - Low (2): Acceptable - max-age ≥ 6 months
//   - Medium (3): Weak - max-age present but < 6 months
//   - Medium (3): Missing - No HSTS header found
//   - High (4): Invalid - HSTS header present but missing/invalid max-age
//
// Security implications:
//   - Missing HSTS: Vulnerable to SSL stripping attacks, protocol downgrades, and MITM attacks
//   - Short max-age: Limited protection window, requires frequent policy refreshes
//   - No includeSubDomains: Subdomains remain vulnerable to attacks
//   - No preload: Not eligible for browser HSTS preload lists
//
// Returns:
//   - *ResponseTest: Configured HSTS test ready for execution
//
// Example usage:
//
//	hstsTest := NewHSTSTest()
//	result := hstsTest.Run(ResponseTestParams{Response: httpResponse})
//	// Result includes threat level and detailed configuration analysis
func NewHSTSTest() *ResponseTest {
	return &ResponseTest{
		Id:          "hsts",
		Name:        "HSTS Header Analysis",
		Description: "Checks for HTTP Strict Transport Security header presence and configuration",
		RunTest: func(params ResponseTestParams) TestResult {
			// Check for HSTS header
			hstsHeader := params.Response.Header.Get("Strict-Transport-Security")

			if hstsHeader == "" {
				return TestResult{
					Name:        "HSTS Header Analysis",
					Certainty:   100,
					ThreatLevel: Medium,
					Metadata:    nil,
					Description: "Missing HSTS header - site vulnerable to protocol downgrade attacks and man-in-the-middle attacks",
				}
			}

			// Parse HSTS header for security analysis
			metadata := analyzeHSTSHeader(hstsHeader)

			// Determine threat level based on HSTS configuration
			threatLevel := evaluateHSTSThreatLevel(metadata)

			// Generate description based on findings
			description := generateHSTSDescription(metadata)

			return TestResult{
				Name:        "HSTS Header Analysis",
				Certainty:   95,
				ThreatLevel: threatLevel,
				Metadata:    metadata,
				Description: description,
			}
		},
	}
}

// analyzeHSTSHeader parses the Strict-Transport-Security header value and extracts
// configuration directives into a structured metadata map. This function performs
// case-insensitive parsing to handle various header formats.
//
// Parsed directives:
//   - max-age: The time (in seconds) that the browser should remember to access the site using HTTPS
//   - includeSubDomains: Whether the HSTS policy applies to all subdomains
//   - preload: Whether the site is eligible for HSTS preload list inclusion
//
// The function handles various header formats including:
//   - "max-age=31536000; includeSubDomains; preload"
//   - "max-age=31536000"
//   - "MAX-AGE=31536000; INCLUDESUBDOMAINS" (case-insensitive)
//
// Parameters:
//   - hstsHeader: Raw Strict-Transport-Security header value from HTTP response
//
// Returns:
//   - map[string]interface{}: Structured metadata containing:
//   - "include_subdomains" (bool): includeSubDomains directive present
//   - "preload" (bool): preload directive present
//   - "max_age" (int): max-age value in seconds (0 if missing/invalid)
//   - "directives" ([]string): List of present optional directives
//
// Example:
//
//	header := "max-age=31536000; includeSubDomains; preload"
//	metadata := analyzeHSTSHeader(header)
//	// Returns: {
//	//   "include_subdomains": true,
//	//   "preload": true,
//	//   "max_age": 31536000,
//	//   "directives": ["includeSubDomains", "preload"]
//	// }
func analyzeHSTSHeader(hstsHeader string) map[string]interface{} {
	metadata := map[string]interface{}{
		"include_subdomains": false,
		"preload":            false,
		"max_age":            0,
		"directives":         []string{},
	}

	// Convert to lowercase for case-insensitive parsing
	headerLower := strings.ToLower(hstsHeader)

	// Check for includeSubDomains directive
	if strings.Contains(headerLower, "includesubdomains") {
		metadata["include_subdomains"] = true
		metadata["directives"] = append(metadata["directives"].([]string), "includeSubDomains")
	}

	// Check for preload directive
	if strings.Contains(headerLower, "preload") {
		metadata["preload"] = true
		metadata["directives"] = append(metadata["directives"].([]string), "preload")
	}

	// Extract max-age value
	if maxAge := extractMaxAge(hstsHeader); maxAge > 0 {
		metadata["max_age"] = maxAge
	}

	return metadata
}

// extractMaxAge extracts and parses the max-age directive value from the HSTS header.
// The max-age directive specifies the duration (in seconds) that the browser should
// remember to access the site exclusively over HTTPS.
//
// The function performs case-insensitive parsing and handles various formats:
//   - "max-age=31536000"
//   - "MAX-AGE=31536000"
//   - "max-age=31536000; includeSubDomains"
//
// Parsing process:
//  1. Split header by semicolon to separate directives
//  2. Trim whitespace from each directive
//  3. Look for "max-age=" prefix (case-insensitive)
//  4. Extract numeric value after the equals sign
//  5. Convert to integer
//
// Parameters:
//   - hstsHeader: Raw Strict-Transport-Security header value
//
// Returns:
//   - int: max-age value in seconds, or 0 if not found or invalid
//
// Example:
//
//	age1 := extractMaxAge("max-age=31536000; includeSubDomains")  // Returns: 31536000
//	age2 := extractMaxAge("includeSubDomains; preload")           // Returns: 0
//	age3 := extractMaxAge("max-age=invalid")                      // Returns: 0
func extractMaxAge(hstsHeader string) int {
	parts := strings.Split(hstsHeader, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		partLower := strings.ToLower(part)
		if strings.HasPrefix(partLower, "max-age=") {
			maxAgeStr := strings.TrimPrefix(partLower, "max-age=")
			if maxAge, err := strconv.Atoi(maxAgeStr); err == nil {
				return maxAge
			}
		}
	}
	return 0
}

// evaluateHSTSThreatLevel determines the security threat level based on HSTS configuration
// quality. It applies industry best practices and security standards to classify the
// HSTS implementation strength.
//
// Threat level classification:
//
//   - None (0): Excellent configuration
//
//   - max-age ≥ 1 year (31,536,000 seconds)
//
//   - includeSubDomains present
//
//   - preload present
//
//   - Meets HSTS preload list requirements
//
//   - Maximum protection against protocol downgrade attacks
//
//   - Info (1): Good configuration
//
//   - max-age ≥ 1 year
//
//   - includeSubDomains present
//
//   - Strong protection, but not preload-eligible
//
//   - Low (2): Acceptable configuration
//
//   - max-age ≥ 6 months (15,552,000 seconds)
//
//   - Provides reasonable protection
//
//   - Should consider increasing max-age
//
//   - Medium (3): Weak configuration
//
//   - max-age present but < 6 months
//
//   - Limited protection window
//
//   - Requires frequent policy refreshes
//
//   - Vulnerable during gaps
//
//   - High (4): Invalid or critically weak
//
//   - max-age = 0 or missing
//
//   - HSTS effectively disabled
//
//   - No protection against protocol downgrades
//
// Security standards reference:
//   - OWASP recommends minimum max-age of 1 year
//   - HSTS preload list requires: max-age ≥ 1 year + includeSubDomains + preload
//   - RFC 6797 specifies HSTS behavior and directives
//
// Parameters:
//   - metadata: Parsed HSTS header metadata from analyzeHSTSHeader
//
// Returns:
//   - ThreatLevel: Security classification (None, Info, Low, Medium, or High)
//
// Example:
//
//	metadata := map[string]interface{}{
//	    "max_age": 31536000,
//	    "include_subdomains": true,
//	    "preload": true,
//	}
//	level := evaluateHSTSThreatLevel(metadata)  // Returns: None (Excellent)
func evaluateHSTSThreatLevel(metadata map[string]interface{}) ThreatLevel {
	maxAge := metadata["max_age"].(int)
	includeSubdomains := metadata["include_subdomains"].(bool)
	preload := metadata["preload"].(bool)

	oneYear := 60 * 60 * 24 * 365
	sixMonths := 60 * 60 * 24 * 30 * 6

	// Excellent configuration
	if maxAge >= oneYear && includeSubdomains && preload {
		return None
	}

	// Good configuration
	if maxAge >= oneYear && includeSubdomains {
		return Info
	}

	// Acceptable configuration
	if maxAge >= sixMonths {
		return Low
	}

	// Weak configuration
	if maxAge > 0 {
		return Medium
	}

	// Invalid or missing max-age
	return High
}

// generateHSTSDescription creates a human-readable description of the HSTS configuration
// analysis including the configuration details and security assessment. The description
// provides actionable information about the HSTS implementation quality.
//
// Description components:
//   - Human-readable max-age duration (e.g., "1 year", "6 months", "30 days")
//   - List of present directives (includeSubDomains, preload)
//   - Security assessment (Excellent, Good, Acceptable, or Weak)
//   - Recommendations for improvement when applicable
//
// Special cases handled:
//   - max-age = 0 or missing: "HSTS header present but missing or invalid max-age directive"
//   - Weak configuration: Includes suggestion to increase max-age
//
// Parameters:
//   - metadata: Parsed HSTS header metadata containing max_age, directives, and flags
//
// Returns:
//   - string: Formatted description for the TestResult
//
// Example outputs:
//
//	// Excellent configuration
//	"HSTS header configured with 1 year max-age and includes: includeSubDomains, preload - Excellent security configuration"
//
//	// Good configuration
//	"HSTS header configured with 2 years max-age and includes: includeSubDomains - Good security configuration"
//
//	// Weak configuration
//	"HSTS header configured with 30 days max-age - Weak security configuration, consider increasing max-age"
//
//	// Missing max-age
//	"HSTS header present but missing or invalid max-age directive"
func generateHSTSDescription(metadata map[string]interface{}) string {
	maxAge := metadata["max_age"].(int)
	includeSubdomains := metadata["include_subdomains"].(bool)
	preload := metadata["preload"].(bool)
	directives := metadata["directives"].([]string)

	if maxAge == 0 {
		return "HSTS header present but missing or invalid max-age directive"
	}

	ageDescription := formatMaxAge(maxAge)

	description := "HSTS header configured with " + ageDescription

	if len(directives) > 0 {
		description += " and includes: " + strings.Join(directives, ", ")
	}

	oneYear := 60 * 60 * 24 * 365
	sixMonths := 60 * 60 * 24 * 30 * 6

	if includeSubdomains && preload && maxAge >= oneYear {
		description += " - Excellent security configuration"
	} else if includeSubdomains && maxAge >= oneYear {
		description += " - Good security configuration"
	} else if maxAge >= sixMonths {
		description += " - Acceptable security configuration"
	} else {
		description += " - Weak security configuration, consider increasing max-age"
	}

	return description
}

// formatMaxAge converts a max-age value in seconds to a human-readable duration string.
// The function automatically selects the most appropriate time unit (years, months, days,
// hours, or seconds) based on the magnitude of the value.
//
// Conversion logic:
//   - ≥ 1 year (31,536,000 sec): Express in years
//   - ≥ 1 month (2,592,000 sec): Express in months
//   - ≥ 1 day (86,400 sec): Express in days
//   - ≥ 1 hour (3,600 sec): Express in hours
//   - < 1 hour: Express in seconds
//
// Singular/plural handling:
//   - Uses singular form for value of 1 (e.g., "1 year", "1 day")
//   - Uses plural form for all other values (e.g., "2 years", "30 days")
//
// Parameters:
//   - seconds: max-age value in seconds
//
// Returns:
//   - string: Human-readable duration with appropriate unit
//
// Examples:
//
//	formatMaxAge(31536000)     // Returns: "1 year max-age"
//	formatMaxAge(63072000)     // Returns: "2 years max-age"
//	formatMaxAge(2592000)      // Returns: "1 month max-age"
//	formatMaxAge(7776000)      // Returns: "3 months max-age"
//	formatMaxAge(86400)        // Returns: "1 day max-age"
//	formatMaxAge(259200)       // Returns: "3 days max-age"
//	formatMaxAge(3600)         // Returns: "1 hour max-age"
//	formatMaxAge(7200)         // Returns: "2 hours max-age"
//	formatMaxAge(300)          // Returns: "300 seconds max-age"
func formatMaxAge(seconds int) string {
	oneYear := 60 * 60 * 24 * 365
	oneMonth := 60 * 60 * 24 * 30
	oneDay := 60 * 60 * 24
	oneHour := 60 * 60

	if seconds >= oneYear {
		years := seconds / oneYear
		if years == 1 {
			return "1 year max-age"
		}
		return strconv.Itoa(years) + " years max-age"
	} else if seconds >= oneMonth {
		months := seconds / oneMonth
		if months == 1 {
			return "1 month max-age"
		}
		return strconv.Itoa(months) + " months max-age"
	} else if seconds >= oneDay {
		days := seconds / oneDay
		if days == 1 {
			return "1 day max-age"
		}
		return strconv.Itoa(days) + " days max-age"
	} else if seconds >= oneHour {
		hours := seconds / oneHour
		if hours == 1 {
			return "1 hour max-age"
		}
		return strconv.Itoa(hours) + " hours max-age"
	} else {
		return strconv.Itoa(seconds) + " seconds max-age"
	}
}
