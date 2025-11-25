// Package helpers provides utility functions for common operations throughout the Engine-AntiGinx application.
// It includes string manipulation utilities such as case-insensitive substring matching,
// duplicate removal, and other helper functions for data processing.
package helpers

import "strings"

// ContainsAny performs a case-insensitive search to determine if any of the provided
// substrings exist within the target string. This is particularly useful for detecting
// keywords or patterns in HTTP responses, such as bot protection indicators or security challenges.
//
// The function converts both the target string and all substrings to lowercase before comparison,
// ensuring consistent matching regardless of character casing.
//
// Parameters:
//   - s: The target string to search within
//   - subs: A slice of substrings to search for
//
// Returns:
//   - bool: true if any substring is found in the target string, false otherwise
//
// Example:
//
//	keywords := []string{"cloudflare", "captcha", "challenge"}
//	body := "Please complete the Cloudflare Challenge to continue"
//	if ContainsAny(body, keywords) {
//	    fmt.Println("Bot protection detected")
//	}
func ContainsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicate strings from a slice while preserving the original order
// of first occurrence. It uses a map-based approach for efficient O(n) performance.
//
// This function is useful for deduplicating lists of test IDs, HTTP methods, or any other
// string collections where uniqueness is required.
//
// Parameters:
//   - slice: The input slice of strings that may contain duplicates
//
// Returns:
//   - []string: A new slice containing only unique strings in their order of first appearance
//
// Example:
//
//	methods := []string{"GET", "POST", "GET", "OPTIONS", "POST"}
//	unique := RemoveDuplicates(methods)
//	// Result: ["GET", "POST", "OPTIONS"]
func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
