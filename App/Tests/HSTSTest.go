package Tests

import (
	"strconv"
	"strings"
)

// NewHSTSTest creates a new test to check for HTTP Strict Transport Security header
func NewHSTSTest() *ResponseTest {
	return &ResponseTest{
		Id:          "hsts-header-check",
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
