package helpers

import "strings"

// ContainsAnySubstring performs a case-insensitive search to determine if any of the provided substrings exist within the target string.
func ContainsAnySubstring(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicate strings from a slice while preserving the original order of first occurrence.
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

// StringInSlice checks if a string slice contains a specific item.
func StringInSlice(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// AnyStringInSlice checks if a string slice contains any of the specified items.
func AnyStringInSlice(slice []string, items []string) bool {
	for _, item := range items {
		if StringInSlice(slice, item) {
			return true
		}
	}
	return false
}

