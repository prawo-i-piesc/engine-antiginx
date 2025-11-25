// Package Runner provides the TargetFormatter component for intelligent URL formatting
// based on the tests being executed. This file contains logic for automatically selecting
// the appropriate protocol (HTTP/HTTPS) based on test requirements.
package Runner

import (
	"Engine-AntiGinx/App/Errors"
	"strings"
)

// targetFormatter is responsible for formatting target URLs by intelligently adding
// appropriate protocol prefixes (http:// or https://) based on the tests being executed.
//
// The formatter implements smart protocol selection:
//   - Uses HTTP protocol when testing HTTP-specific vulnerabilities (https, hsts tests)
//   - Uses HTTPS protocol for all other tests by default
//   - Validates that user hasn't already specified a protocol
//
// This ensures tests can properly assess protocol-level security issues without
// automatic browser redirects interfering with the analysis.
type targetFormatter struct{}

// InitializeTargetFormatter creates a new instance of targetFormatter ready to format
// target URLs. This factory function provides the entry point for creating a formatter
// that intelligently selects protocols based on test requirements.
//
// The formatter is stateless and can be reused for multiple formatting operations
// if needed, though typically only one instance is created per test run.
//
// Returns:
//   - *targetFormatter: A new formatter instance ready to call Format()
//
// Example:
//
//	formatter := InitializeTargetFormatter()
//	targetURL := formatter.Format("example.com", []string{"https", "hsts"})
//	// Returns: "http://example.com" (HTTP for protocol testing)
func InitializeTargetFormatter() *targetFormatter {
	return &targetFormatter{}
}

// Format constructs a properly formatted target URL by adding the appropriate protocol
// prefix based on the tests being executed. It implements intelligent protocol selection
// to ensure tests can properly assess security configurations.
//
// Protocol selection logic:
//
//   - HTTP (http://): Used when "https" or "hsts" tests are included
//     Rationale: These tests specifically check for HTTP→HTTPS redirects and HSTS headers,
//     so starting with HTTP is necessary to observe the security behavior
//
//   - HTTPS (https://): Used for all other test combinations (default)
//     Rationale: Most security tests should analyze the secure connection
//
// Validation:
//   - Panics if target already contains "http://" or "https://" prefix
//     Rationale: User should provide bare domain/hostname to allow automatic protocol selection
//
// Performance optimization:
//   - Uses strings.Builder with pre-allocated capacity for efficient string construction
//   - Grows buffer to avoid reallocations: len(target) + len("https://")
//
// Parameters:
//   - target: Bare domain or hostname without protocol (e.g., "example.com", "api.example.com")
//   - params: List of test IDs to be executed (e.g., ["https", "hsts", "csp"])
//
// Returns:
//   - *string: Pointer to formatted URL with appropriate protocol prefix
//
// Panics:
//   - Errors.Error with code 100: If target already contains protocol prefix
//
// Examples:
//
//	formatter := InitializeTargetFormatter()
//
//	// HTTPS test requires HTTP to check redirect behavior
//	url1 := formatter.Format("example.com", []string{"https", "csp"})
//	// Returns: "http://example.com"
//
//	// HSTS test requires HTTP to check HSTS header
//	url2 := formatter.Format("example.com", []string{"hsts"})
//	// Returns: "http://example.com"
//
//	// Other tests default to HTTPS
//	url3 := formatter.Format("example.com", []string{"csp", "xFrame"})
//	// Returns: "https://example.com"
//
//	// Invalid: protocol already specified
//	url4 := formatter.Format("https://example.com", []string{"https"})
//	// Panics with error code 100
func (t *targetFormatter) Format(target string, params []string) *string {
	if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "https") {
		panic(Errors.Error{
			Code: 100,
			Message: `Target Formatter error occurred. This could be due to:
				- invalid target passed to the parameter`,
			Source:      "Target Formatter",
			IsRetryable: false,
		})
	}
	builder := strings.Builder{}
	builder.Grow(len(target) + len("https://"))
	if t.containsParam(params, "https") || t.containsParam(params, "hsts") {
		builder.WriteString("http://")
	} else {
		builder.WriteString("https://")
	}
	builder.WriteString(target)
	target = builder.String()
	return &target
}

// containsParam is a helper function that performs a linear search to determine if a
// specific test ID (token) exists in the list of tests to be executed. This function
// is used internally by Format to implement protocol selection logic.
//
// The function uses simple iteration with O(n) time complexity, which is acceptable
// given that the params slice is typically small (usually 1-10 test IDs).
//
// Parameters:
//   - params: Slice of test IDs to search through
//   - token: The test ID to search for (e.g., "https", "hsts")
//
// Returns:
//   - bool: true if token is found in params, false otherwise
//
// Example:
//
//	formatter := &targetFormatter{}
//	tests := []string{"https", "hsts", "csp"}
//
//	found1 := formatter.containsParam(tests, "https")  // returns true
//	found2 := formatter.containsParam(tests, "xFrame") // returns false
func (t *targetFormatter) containsParam(params []string, token string) bool {
	for _, param := range params {
		if param == token {
			return true
		}
	}
	return false
}
