// Package helpers provides shared utilities for the application.
package helpers

// MinInt returns the smaller of two integers.
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
